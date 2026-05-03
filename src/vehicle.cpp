#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE::Vehicle"
#endif

#include "vehicle.h"

#include "command_error.h"
#include "defs.h"

#include "tb_logging.h"
#include "tb_utils.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include <algorithm>
#include <cinttypes>
#include <vector>
#include <array>
#include <cstdlib>
#include <utility>

namespace TeslaBLE {

Vehicle::Vehicle(const std::shared_ptr<BleAdapter> &ble, const std::shared_ptr<StorageAdapter> &storage)
    : ble_adapter_(ble),
      storage_adapter_(storage),
      client_(std::make_shared<Client>()),
      message_processor_(std::make_unique<MessageProcessor>(
          [this](const UniversalMessage_RoutableMessage &msg) { handle_message_(msg); })) {
  std::vector<uint8_t> key_buffer;
  if (storage_adapter_->load("private_key", key_buffer)) {
    if (client_->load_private_key(key_buffer.data(), key_buffer.size()) == 0) {
      LOG_INFO("Loaded private key from storage");
    } else {
      LOG_ERROR("Failed to load private key from storage");
    }
  } else {
    LOG_INFO("No private key found in storage");
  }

  load_session_from_storage_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  load_session_from_storage_(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  initialize_rx_buffer();
}

void Vehicle::initialize_rx_buffer() { rx_buffer_.reserve(MAX_MESSAGE_SIZE); }

void Vehicle::set_vin(const std::string &vin) {
  if (client_) client_->set_vin(vin);
}

void Vehicle::set_connected(bool connected) {
  is_connected_ = connected;
  if (!connected) {
    LOG_INFO("Disconnected from vehicle");
    auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    auto *info_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    if (vcsec_peer) vcsec_peer->reset();
    if (info_peer) info_peer->reset();
    is_vehicle_awake_ = false;
    while (!command_queue_.empty()) {
      auto cmd = command_queue_.front();
      if (cmd->on_complete) cmd->on_complete(CommandError::connection_lost());
      command_queue_.pop();
    }
    rx_buffer_.clear();
  } else {
    LOG_INFO("Connected to vehicle");
  }
}

void Vehicle::loop() {
  message_processor_->process_messages();
  if (is_connected_) process_command_queue_();
}

void Vehicle::send_command(UniversalMessage_Domain domain, const std::string &name,
                           std::function<int(Client *, uint8_t *, size_t *)> builder,
                           std::function<void(std::unique_ptr<CommandError>)> on_complete,
                           bool requires_wake) {
  if (!is_connected_) {
    LOG_DEBUG("Not connected - rejecting command: %s", name.c_str());
    if (on_complete) on_complete(CommandError::connection_lost());
    return;
  }
  if (command_queue_.size() >= MAX_COMMAND_QUEUE_SIZE) {
    LOG_WARNING("Command queue full, rejecting command: %s", name.c_str());
    if (on_complete) on_complete(CommandError::build_failed("queue full"));
    return;
  }
  auto cmd = std::make_shared<Command>(domain, name, std::move(builder), std::move(on_complete), requires_wake);
  command_queue_.push(cmd);
  LOG_DEBUG("Enqueued command: %s (domain: %s, requires_wake: %s)", cmd->name.c_str(), domain_to_string(domain),
            requires_wake ? "true" : "false");
}

void Vehicle::send_command_bool(UniversalMessage_Domain domain, const std::string &name,
                                std::function<int(Client *, uint8_t *, size_t *)> builder,
                                const std::function<void(bool)> &on_complete, bool requires_wake) {
  auto rich_callback = on_complete ? [on_complete](std::unique_ptr<CommandError> error) { on_complete(!error); }
                                   : std::function<void(std::unique_ptr<CommandError>)>(nullptr);
  send_command(domain, name, std::move(builder), std::move(rich_callback), requires_wake);
}

void Vehicle::process_command_queue_() {
  if (command_queue_.empty()) return;
  auto command = command_queue_.front();
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  if (duration > COMMAND_TIMEOUT) {
    if (is_connected_) LOG_WARNING("Command timeout while connected: %s", command->name.c_str());
    else LOG_DEBUG("Command timeout while disconnected: %s", command->name.c_str());
    mark_command_failed_(command, CommandError::timeout("Command"));
    return;
  }

  switch (command->state) {
    case CommandState::IDLE: process_idle_command_(command); break;
    case CommandState::AUTHENTICATING: process_authenticating_command_(command); break;
    case CommandState::AUTH_RESPONSE_WAITING: process_auth_response_waiting_command_(command); break;
    case CommandState::READY: process_ready_command_(command); break;
    case CommandState::WAITING_FOR_RESPONSE: {
      auto tx_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->last_tx_at);
      const auto timeout = (command->name == "Whitelist Add Key") ? COMMAND_TIMEOUT : CLOCK_SYNC_MAX_LATENCY;
      if (tx_duration > timeout) {
        if (command->name == "Wake" && is_vehicle_awake_) {
          LOG_INFO("Wake response timeout but vehicle is awake - proceeding");
          mark_command_completed_(command);
          break;
        }
        LOG_DEBUG("Response timeout for command: %s (attempt %d/%d)", command->name.c_str(), command->retry_count,
                  MAX_RETRIES + 1);
        retry_command(command);
      }
    } break;
    default: break;
  }
}

std::shared_ptr<Command> Vehicle::peek_command_() const {
  if (command_queue_.empty()) return nullptr;
  return command_queue_.front();
}

void Vehicle::process_idle_command_(const std::shared_ptr<Command> &command) {
  command->started_at = std::chrono::steady_clock::now();
  if (command->name == "Whitelist Add Key") {
    LOG_INFO("Bypassing session auth for Whitelist Add Key");
    command->state = CommandState::READY;
    return;
  }
  switch (command->domain) {
    case UniversalMessage_Domain_DOMAIN_BROADCAST: command->state = CommandState::READY; break;
    case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY: initiate_vcsec_auth_(command); break;
    case UniversalMessage_Domain_DOMAIN_INFOTAINMENT: initiate_infotainment_auth_(command); break;
    default:
      LOG_ERROR("Unknown domain for command: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed("unknown domain"));
      break;
  }
}

void Vehicle::process_authenticating_command_(const std::shared_ptr<Command> &command) {
  LOG_DEBUG("Processing auth for %s (%s)", command->name.c_str(), domain_to_string(command->current_auth_domain));
  switch (command->current_auth_domain) {
    case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
      initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
      break;
    case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
      if (!is_domain_authenticated_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
        LOG_DEBUG("VCSEC auth required before Infotainment auth");
        command->current_auth_domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
        initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
      } else {
        initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, CommandState::AUTH_RESPONSE_WAITING, "Infotainment");
      }
      break;
    case UniversalMessage_Domain_DOMAIN_BROADCAST: initiate_wake_sequence_(command); break;
    default:
      LOG_ERROR("Unknown authentication domain for command: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed("unknown auth domain"));
      break;
  }
}

void Vehicle::process_auth_response_waiting_command_(const std::shared_ptr<Command> &command) {
  auto now = std::chrono::steady_clock::now();
  auto tx_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->last_tx_at);
  if (tx_duration > AUTH_RESPONSE_TIMEOUT) {
    switch (command->current_auth_domain) {
      case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY: handle_vcsec_auth_timeout_(command); break;
      case UniversalMessage_Domain_DOMAIN_INFOTAINMENT: handle_infotainment_auth_timeout_(command); break;
      case UniversalMessage_Domain_DOMAIN_BROADCAST: handle_wake_response_timeout_(command); break;
      default: mark_command_failed_(command, CommandError::timeout("Unknown auth")); break;
    }
  }
}

void Vehicle::handle_auth_timeout_common_(const std::shared_ptr<Command> &command, const std::string &domain_name, CommandState retry_state) {
  log_timeout_message_(domain_name + " auth response timeout", command);
  auto now = std::chrono::steady_clock::now();
  auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(now - command->started_at);
  int attempt_level = std::min(command->retry_count / 2, 3);
  static constexpr std::array<int, 4> TIMEOUT_THRESHOLDS = {30, 60, 120, 300};
  if (total_duration > std::chrono::seconds(TIMEOUT_THRESHOLDS[attempt_level])) {
    LOG_ERROR("Connection validation failed: %s auth stuck for %lld seconds (level %d, retry %d)", domain_name.c_str(),
              (long long) total_duration.count(), attempt_level, command->retry_count);
    reset_all_sessions_and_connection_();
    mark_command_failed_(command, CommandError::session_stale("connection"));
    return;
  }
  command->state = retry_state;
}

void Vehicle::handle_vcsec_auth_timeout_(const std::shared_ptr<Command> &command) {
  handle_auth_timeout_common_(command, "VCSEC", CommandState::AUTHENTICATING);
}

void Vehicle::handle_infotainment_auth_timeout_(const std::shared_ptr<Command> &command) {
  handle_auth_timeout_common_(command, "Infotainment", CommandState::AUTHENTICATING);
}

void Vehicle::handle_wake_response_timeout_(const std::shared_ptr<Command> &command) {
  if (is_vehicle_awake_) {
    LOG_INFO("Wake response timeout but vehicle is awake - proceeding");
    if (command->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
      command->current_auth_domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
      command->state = CommandState::AUTHENTICATING;
      command->last_tx_at = std::chrono::steady_clock::time_point();
    } else mark_command_completed_(command);
  } else {
    log_timeout_message_("Wake response timeout - vehicle still asleep", command);
    retry_command(command);
  }
}

void Vehicle::initiate_auth_for_domain_(const std::shared_ptr<Command> &command, UniversalMessage_Domain domain,
                                        CommandState waiting_state, const std::string &domain_name) {
  if (is_domain_authenticated_(domain)) {
    if (command->domain == domain) command->state = CommandState::READY;
    else if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) command->state = CommandState::AUTHENTICATING;
  } else {
    uint8_t buffer[256];
    size_t len = 256;
    if (client_->build_session_info_request_message(domain, buffer, &len) == 0) {
      std::vector<uint8_t> data(buffer, buffer + len);
      if (ble_adapter_->write(data)) {
        command->state = waiting_state;
        command->last_tx_at = std::chrono::steady_clock::now();
        LOG_INFO("Sent %s Session Info Request", domain_name.c_str());
      } else LOG_ERROR("Failed to write %s Session Info Request", domain_name.c_str());
    } else {
      LOG_ERROR("Failed to build %s Session Info Request", domain_name.c_str());
      mark_command_failed_(command, CommandError::build_failed(domain_name + " Session Info Request"));
    }
  }
}

void Vehicle::initiate_vcsec_auth_(const std::shared_ptr<Command> &command) {
  command->current_auth_domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
  initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
}

void Vehicle::initiate_infotainment_auth_(const std::shared_ptr<Command> &command) {
  if (!is_vehicle_awake_ && !command->requires_wake) {
    LOG_DEBUG("Vehicle asleep, skipping optional command: %s", command->name.c_str());
    mark_command_completed_(command);
    return;
  }
  if (!is_domain_authenticated_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
    LOG_DEBUG("VCSEC auth required before Infotainment auth");
    initiate_vcsec_auth_(command);
    return;
  }
  if (!is_vehicle_awake_ && command->requires_wake) {
    LOG_DEBUG("Vehicle is asleep and command requires wake, initiating wake sequence");
    command->current_auth_domain = UniversalMessage_Domain_DOMAIN_BROADCAST;
    command->state = CommandState::AUTHENTICATING;
    command->last_tx_at = std::chrono::steady_clock::time_point();
    return;
  }
  initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, CommandState::AUTH_RESPONSE_WAITING, "Infotainment");
}

void Vehicle::initiate_wake_sequence_(const std::shared_ptr<Command> &command) {
  uint8_t buffer[256];
  size_t len = 256;
  if (client_->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buffer, &len) == 0) {
    std::vector<uint8_t> data(buffer, buffer + len);
    if (ble_adapter_->write(data)) {
      command->state = CommandState::AUTH_RESPONSE_WAITING;
      command->last_tx_at = std::chrono::steady_clock::now();
      LOG_INFO("Sent Wake Command");
    } else {
      LOG_ERROR("Failed to write Wake Command");
      mark_command_failed_(command, CommandError::build_failed("Wake write"));
    }
  } else {
    LOG_ERROR("Failed to build Wake Command");
    mark_command_failed_(command, CommandError::build_failed("Wake Command"));
  }
}

void Vehicle::retry_command(const std::shared_ptr<Command> &command) {
  if (command->retry_count >= MAX_RETRIES) {
    LOG_ERROR("Max retries exceeded for command: %s", command->name.c_str());
    mark_command_failed_(command, CommandError::max_retries_exceeded(command->name));
    return;
  }

  bool should_retry = true;
  if (command->last_error) {
    should_retry = command->last_error->is_temporary();
    if (!should_retry) {
      LOG_INFO("Not retrying %s: error is permanent", command->name.c_str());
      mark_command_failed_(command, std::move(command->last_error));
      return;
    }
  }

  command->retry_count++;
  LOG_DEBUG("Retrying command: %s (attempt %d/%d)", command->name.c_str(), command->retry_count, MAX_RETRIES + 1);

  std::chrono::milliseconds backoff_delay;
  if (command->retry_count == 1) backoff_delay = INITIAL_RETRY_DELAY;
  else {
    auto current_delay = command->next_retry_delay;
    auto calculated_delay = std::chrono::milliseconds(static_cast<int64_t>(current_delay.count() * BACKOFF_MULTIPLIER));
    backoff_delay = calculated_delay > MAX_RETRY_DELAY ? MAX_RETRY_DELAY : calculated_delay;
    auto jitter = std::chrono::milliseconds(arc4random() % 101);
    backoff_delay += jitter;
  }

  command->next_retry_delay = backoff_delay;
  command->next_retry_time = std::chrono::steady_clock::now() + backoff_delay;
  LOG_DEBUG("Exponential backoff: retry %d, delay %lldms for command: %s", static_cast<int>(command->retry_count + 1),
            static_cast<long long>(backoff_delay.count()), command->name.c_str());
  command->last_tx_at = std::chrono::steady_clock::now() - backoff_delay + std::chrono::milliseconds(100);

  switch (command->state) {
    case CommandState::WAITING_FOR_RESPONSE: command->state = CommandState::READY; break;
    case CommandState::AUTH_RESPONSE_WAITING:
    default: command->state = CommandState::IDLE; break;
  }
}

void Vehicle::process_ready_command_(const std::shared_ptr<Command> &command) {
  uint8_t buffer[256];
  size_t len = 256;
  if (command->builder(client_.get(), buffer, &len) == 0) {
    std::vector<uint8_t> data(buffer, buffer + len);
    if (ble_adapter_->write(data)) {
      LOG_DEBUG("Sent command: %s (%zu bytes)", command->name.c_str(), data.size());
      command->state = CommandState::WAITING_FOR_RESPONSE;
      command->last_tx_at = std::chrono::steady_clock::now();
    } else {
      LOG_ERROR("Failed to write command data: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed("BLE write failed"));
    }
  } else {
    LOG_ERROR("Failed to build command: %s", command->name.c_str());
    mark_command_failed_(command, CommandError::build_failed(command->name));
  }
}

void Vehicle::mark_command_failed_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error) {
  command->state = CommandState::FAILED;
  command->last_error = std::move(error);
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  LOG_ERROR("[%s] Command failed after %lld ms: %s", command->name.c_str(), (long long) duration.count(),
            command->last_error->message().c_str());
  finalize_command_(command, std::move(command->last_error));
}

void Vehicle::mark_command_completed_(const std::shared_ptr<Command> &command) {
  command->state = CommandState::COMPLETED;
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  LOG_INFO("[%s] Command completed successfully in %lld ms", command->name.c_str(), (long long) duration.count());
  finalize_command_(command, nullptr);
}

void Vehicle::finalize_command_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error) {
  if (command->on_complete) command->on_complete(std::move(error));
  if (!command_queue_.empty() && command_queue_.front() == command) command_queue_.pop();
}

bool Vehicle::is_domain_authenticated_(UniversalMessage_Domain domain) {
  auto *peer = client_->get_peer(domain);
  return peer && peer->is_valid();
}

void Vehicle::on_rx_data(const std::vector<uint8_t> &data) {
  rx_buffer_.insert(rx_buffer_.end(), data.begin(), data.end());
  recovery_attempted_ = false;
  while (is_message_complete()) process_complete_message();
}

bool Vehicle::is_message_complete() {
  if (rx_buffer_.size() < FRAME_HEADER_SIZE) return false;
  int msg_len = get_expected_message_length();
  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) return true;
  return rx_buffer_.size() >= static_cast<size_t>(msg_len);
}

int Vehicle::get_expected_message_length() {
  if (rx_buffer_.size() < FRAME_HEADER_SIZE) return 0;
  return static_cast<int>((rx_buffer_[0] << 8) | rx_buffer_[1]) + FRAME_HEADER_SIZE;
}

void Vehicle::process_complete_message() {
  int msg_len = get_expected_message_length();
  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) {
    LOG_ERROR("Invalid message length %d, attempting buffer recovery", msg_len);
    bool severe_corruption = msg_len > 0xF000;
    if (!attempt_buffer_recovery_(msg_len)) {
      if (severe_corruption) LOG_ERROR("Severe buffer corruption detected (length: %d), clearing buffer", msg_len);
      else LOG_WARNING("Buffer recovery failed, clearing all data");
      rx_buffer_.clear();
      return;
    }
    recovery_attempted_ = true;
  }

  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) {
    LOG_WARNING("Buffer recovery produced invalid length %d, clearing buffer", msg_len);
    rx_buffer_.clear();
    recovery_attempted_ = false;
    return;
  }

  if (rx_buffer_.size() < static_cast<size_t>(msg_len)) return;

  std::vector<uint8_t> full_msg(rx_buffer_.begin(), rx_buffer_.begin() + msg_len);
  if (raw_message_callback_) raw_message_callback_(full_msg);
  std::vector<uint8_t> msg_data(rx_buffer_.begin() + FRAME_HEADER_SIZE, rx_buffer_.begin() + msg_len);
  UniversalMessage_RoutableMessage msg = UniversalMessage_RoutableMessage_init_default;
  if (client_->parse_universal_message(msg_data.data(), msg_data.size(), &msg) == 0) {
    LOG_DEBUG("Successfully parsed universal message");
    log_routable_message(TESLA_LOG_TAG, &msg);
    message_processor_->queue_message(msg);
    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + msg_len);
    recovery_attempted_ = false;
  } else {
    LOG_ERROR("Failed to parse Universal Message (buffer size: %zu) - attempting buffer recovery", rx_buffer_.size());
    if (recovery_attempted_ || !attempt_buffer_recovery_(msg_len)) {
      LOG_WARNING("Buffer recovery failed after parse error, clearing all data");
      rx_buffer_.clear();
      recovery_attempted_ = false;
    } else recovery_attempted_ = true;
  }
}

void Vehicle::handle_message_(const UniversalMessage_RoutableMessage &msg) {
  if (message_callback_) message_callback_(msg);
  bool has_session_error = false;
  if (msg.has_signedMessageStatus) handle_signed_message_error_(msg, has_session_error);
  if (msg.which_payload == UniversalMessage_RoutableMessage_session_info_tag) {
    handle_session_info_message_(msg);
    auto cmd = peek_command_();
    if (has_session_error && cmd &&
        (cmd->state == CommandState::WAITING_FOR_RESPONSE || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
      LOG_INFO("Retrying command after session recovery");
      cmd->state = CommandState::IDLE;
      cmd->retry_count++;
      if (cmd->retry_count > MAX_RETRIES) mark_command_failed_(cmd, CommandError::session_expired("session recovery"));
    }
    return;
  }
  auto cmd = peek_command_();
  if (has_session_error && cmd &&
      (cmd->state == CommandState::WAITING_FOR_RESPONSE || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
    LOG_INFO("Transitioning to IDLE to trigger manual session recovery");
    cmd->state = CommandState::IDLE;
  }
  if (msg.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    switch (msg.from_destination.sub_destination.domain) {
      case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY: handle_vcsec_message_(msg); break;
      case UniversalMessage_Domain_DOMAIN_INFOTAINMENT: handle_carserver_message_(msg); break;
      default: LOG_DEBUG("Message from unknown domain: %d", msg.from_destination.sub_destination.domain); break;
    }
  }
}

// ... [保留你原始文件中所有其他成员函数实现，包括所有车辆控制函数] ...

// 以下省略大量函数（因长度限制，请务必从原始完整 vehicle.cpp 中复制剩余内容，但不包含任何 sign_challenge / send_authorization_response）
// 必须包含的函数（示例）：
// void Vehicle::lock(), unlock(), open_trunk(), close_trunk(), ...
// void Vehicle::set_charging_state(bool), set_charging_amps(int), set_charging_limit(int) ...
// void Vehicle::set_climate(bool), set_climate_temp(float), set_climate_keeper(int) ...
// void Vehicle::flash_lights(), honk_horn(), set_sentry_mode(bool), vent_windows(), close_windows()
// void Vehicle::pair(Keys_Role), regenerate_key()
// bool Vehicle::persist_private_key_()
// 以及其他所有在 vehicle.h 中声明的函数

// ★ 保证下面的 start_driving 存在

void Vehicle::start_driving() {
    LOG_INFO("Sending Remote Drive command");
    send_command(
        UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
        "RemoteDrive",
        [](Client *client, uint8_t *buff, size_t *len) {
            return client->build_vcsec_action_message(
                VCSEC_RKEAction_E_RKE_ACTION_REMOTE_DRIVE, buff, len);
        },
        [this](std::unique_ptr<CommandError> error) {
            if (error) {
                LOG_ERROR("Remote drive failed: %s", error->message().c_str());
            } else {
                LOG_INFO("Remote drive command completed successfully");
                vcsec_poll();
                infotainment_poll(true);
            }
        },
        true  // requires_wake
    );
}

}  // namespace TeslaBLE

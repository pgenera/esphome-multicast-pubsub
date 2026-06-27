#pragma once

#include "esphome/core/defines.h"
#ifdef USE_NETWORK

#include <array>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "esphome/components/sensor/sensor.h"
#include "esphome/core/component.h"
#include "esphome/core/helpers.h"

// arduino-esp8266 ships precompiled lwip2 with LWIP_SOCKET=0, so the
// ESPHome `socket::` abstraction (BSD-style) can't reach IPv6 multicast
// there. On ESP8266 we call lwip's raw UDP / MLD6 API directly; on every
// other platform we keep the socket-based path.
#ifdef USE_ESP8266
struct udp_pcb;
struct pbuf;
#else
#include "esphome/components/socket/socket.h"
#endif

#include "topic_hash.h"
#include "wire_format.h"
#include "replay_guard.h"

#ifdef USE_TIME
#include "esphome/components/time/real_time_clock.h"
#endif

namespace esphome::multicast_pubsub {

using MessageCallback = std::function<void(std::span<const uint8_t>)>;

// A typed subscription callback is keyed on schema_id so the dispatcher
// can drop packets whose schema doesn't match what this callback expects.
struct TypedCallback {
  uint16_t schema_id;
  MessageCallback callback;  // body bytes have SCHEMA_ID already stripped
};

struct Subscription {
  std::string topic;
  uint32_t crc;
  GroupAddr group;
  // RAW-encoding callbacks fire on packets with ENCODING == RAW.
  std::vector<MessageCallback> raw_callbacks;
  // PROTOBUF-encoding callbacks fire on ENCODING == PROTOBUF when the
  // packet's SCHEMA_ID matches. Multiple typed callbacks per topic are
  // supported (e.g. listen for both RoomClimate and a sibling schema on
  // the same topic via a different sensor type).
  std::vector<TypedCallback> typed_callbacks;
  // ESP8266-only: tracks whether mld6_joingroup has been called for this
  // group. The wifi netif comes up asynchronously, so joins are deferred
  // until netif_default is set (see MulticastPubSub::loop on USE_ESP8266).
  // Defaults to true so the socket-based path treats every subscription
  // as joined-at-creation (which it is, via IPV6_JOIN_GROUP in setup()
  // or find_or_create_subscription_).
  bool joined{true};
  // When set, plaintext datagrams for this topic are dropped at dispatch
  // (the topic is encryption-only on this receiver). Multiple subscribers
  // for the same topic OR their require_encryption flags together: if any
  // caller demands encryption, plaintext is dropped for every callback on
  // the subscription. Default false preserves legacy behavior.
  bool require_encryption{false};
};

class MulticastPubSub : public Component {
 public:
  void set_port(uint16_t port) { this->port_ = port; }
  void set_scope(Scope scope) { this->scope_ = scope; }
  void set_hops(uint8_t hops) { this->hops_ = hops; }
  // retransmit_count = number of total transmissions per publish() call.
  //   1   : no retransmission (just the synchronous initial send)
  //   N>1 : send N packets total, (N-1) deferred via set_timeout()
  //   -1  : keep retransmitting forever at retransmit_delay_ms_ until a
  //         new publish() for the same topic supersedes it. Requires
  //         retransmit_delay_ms_ >= 1000 (enforced at config time).
  // delay is the spacing between successive sends; the first send is
  // unconditional and synchronous.
  void set_retransmit_count(int16_t count) { this->retransmit_count_ = count; }
  int16_t get_retransmit_count() const { return this->retransmit_count_; }
  void set_retransmit_delay_ms(uint32_t delay_ms) { this->retransmit_delay_ms_ = delay_ms; }
  // Enable XXTEA-256 payload encryption. The 32-byte key is the SHA-256
  // digest of the user's configured passphrase (matches the convention
  // packet_transport uses for its `encryption.key` option). Once set, every
  // outgoing publish() is encrypted; incoming encrypted datagrams are
  // decrypted with this key, while incoming plaintext datagrams continue
  // to be dispatched (mixed-mode deployments are allowed).
  void set_encryption_key(std::vector<uint8_t> key) {
    this->encryption_enabled_ = key.size() == 32;
    if (this->encryption_enabled_) {
      for (size_t i = 0; i < 32; i++)
        this->encryption_key_bytes_[i] = key[i];
    }
  }

  // Enable replay protection (Option B). Each encrypted publish() is stamped
  // with the wall clock + a random nonce inside the ciphertext; on receive,
  // encrypted packets that are stale or duplicate within `window_seconds`
  // are dropped (see replay_guard.h). 0 (the default) leaves it off.
  // Needs a synchronized time source (set_time); without one the receiver
  // fails closed and drops every encrypted packet while protection is on.
  void set_replay_window(uint32_t window_seconds) { this->replay_guard_.set_window(window_seconds); }
#ifdef USE_TIME
  void set_time(time::RealTimeClock *clock) { this->clock_ = clock; }
#endif

  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  // Subscribe `cb` to ENCODING=RAW messages on `topic`. Multiple callbacks
  // per topic are supported; the first subscription joins the multicast
  // group. `require_encryption=true` marks the topic as encryption-only on
  // this receiver: plaintext packets for `topic` are dropped at dispatch.
  // The flag is sticky -- once any caller sets it, the topic stays
  // encryption-only for every callback on it.
  void subscribe(const std::string &topic, MessageCallback cb, bool require_encryption = false);

  // Subscribe `cb` to ENCODING=PROTOBUF messages on `topic` whose SCHEMA_ID
  // matches T::SCHEMA_ID. The lambda receives the decoded typed struct.
  // The protobuf body is decoded via T::decode (inherited from
  // esphome::api::ProtoDecodableMessage). See subscribe() for the meaning
  // of `require_encryption`.
  template<typename T> void subscribe_typed(const std::string &topic, std::function<void(const T &)> cb,
                                            bool require_encryption = false) {
    Subscription *sub = this->find_or_create_subscription_(topic, require_encryption);
    sub->typed_callbacks.push_back(TypedCallback{
        T::SCHEMA_ID,
        [cb = std::move(cb)](std::span<const uint8_t> body) {
          T msg;
          msg.decode(body.data(), body.size());
          cb(msg);
        },
    });
  }

  // Publish `payload` to `topic`. Defaults to ENCODING=RAW (opaque bytes);
  // typed publishes set Encoding::PROTOBUF and prepend a SCHEMA_ID.
  // Returns false and logs a warning on socket error or oversize payload.
  bool publish(const std::string &topic, std::span<const uint8_t> payload, Encoding encoding = Encoding::RAW);
  bool publish(const std::string &topic, const std::string &payload, Encoding encoding = Encoding::RAW) {
    return this->publish(topic,
                         std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(payload.data()), payload.size()),
                         encoding);
  }

  // Publish a typed protobuf message. Encodes T via T::encode_to, prepends
  // T::SCHEMA_ID as a 2-byte LE prefix, and sends with ENCODING=PROTOBUF.
  template<typename T> bool publish(const std::string &topic, const T &msg) {
    std::array<uint8_t, MAX_PAYLOAD> buf;
    // Reserve 2 bytes at the front for SCHEMA_ID, then encode.
    constexpr size_t SCHEMA_ID_LEN = 2;
    buf[0] = static_cast<uint8_t>(T::SCHEMA_ID);
    buf[1] = static_cast<uint8_t>(T::SCHEMA_ID >> 8);
    size_t encoded = msg.encode_to(buf.data() + SCHEMA_ID_LEN, MAX_PAYLOAD - SCHEMA_ID_LEN);
    return this->publish(topic,
                         std::span<const uint8_t>(buf.data(), SCHEMA_ID_LEN + encoded),
                         Encoding::PROTOBUF);
  }

  /// Publish a pre-encoded protobuf body with an explicit ``schema_id``.
  /// Used by bridges or anything that builds messages at runtime via
  /// :class:`DynamicMessage` rather than through a codegen-generated
  /// typed struct. ``schema_id`` may be ``0`` for "schemaless" messages
  /// that no typed subscriber will match -- only ``DynamicReader``-style
  /// consumers will see them.
  bool publish_dynamic(const std::string &topic, uint16_t schema_id, std::span<const uint8_t> proto_bytes);

  /// Construct a fluent builder for a typed message. Mirrors
  /// esphome::light::LightState::make_call() -- chain set_<field>() calls
  /// and finish with perform() to encode and publish.
  ///
  /// Example:
  ///   id(pubsub)->make_call<RoomClimate>("home/garage/climate")
  ///       .set_temperature(22.5f)
  ///       .set_room_id("garage")
  ///       .perform();
  ///
  /// `T` must be a generated message struct (one of the entries under
  /// `mpubsub.messages:` in YAML).
  template<typename T> typename T::Call make_call(const std::string &topic) {
    return typename T::Call(this, topic);
  }

  // Diagnostic sensors auto-created by codegen. Picked up by any platform that
  // iterates registered sensors (prometheus, web_server, HA API, etc).
  void set_packets_sent_sensor(sensor::Sensor *s) { this->packets_sent_sensor_ = s; }
  void set_packets_received_sensor(sensor::Sensor *s) { this->packets_received_sensor_ = s; }

 protected:
  void deliver_(uint32_t crc, Encoding encoding, std::span<const uint8_t> payload, bool was_encrypted);
  // Fill `body` (length body_len, a multiple of 4) with the XXTEA plaintext
  // -- [crc || timestamp || nonce] prefix + payload + zero pad -- and encrypt
  // it in place. Shared by both platform publish() paths.
  void encrypt_body_(uint8_t *body, size_t body_len, uint32_t crc, std::span<const uint8_t> payload);
  // Decrypt an EncMode::XXTEA packet, run the replay check, and dispatch.
  // Shared by both platform on_packet_() paths.
  void handle_encrypted_(const DecodedPacket &pkt);
  // Current wall-clock unix time for stamping an outgoing publish. Returns 0
  // when no synchronized clock is available; a replay-checking receiver
  // treats 0 as "unverifiable" and drops it.
  uint32_t replay_timestamp_() const {
#ifdef USE_TIME
    if (this->clock_ != nullptr) {
      auto t = this->clock_->now();
      if (t.is_valid())
        return static_cast<uint32_t>(t.timestamp);
    }
#endif
    return 0;
  }
  // Receiver-side current time. Writes `*now` and returns whether the local
  // clock has synced (false => replay guard fails closed).
  bool replay_now_(uint32_t *now) const {
#ifdef USE_TIME
    if (this->clock_ != nullptr) {
      auto t = this->clock_->now();
      if (t.is_valid()) {
        *now = static_cast<uint32_t>(t.timestamp);
        return true;
      }
    }
#endif
    *now = 0;
    return false;
  }
  Subscription *find_subscription_(const std::string &topic);
  // Look up `topic` -- create + join the multicast group if missing.
  // Used by both raw subscribe() and typed subscribe_typed<T>(). The
  // require_encryption flag is OR'd into the subscription on every call;
  // once set true, it stays set for the lifetime of the component.
  Subscription *find_or_create_subscription_(const std::string &topic, bool require_encryption = false);
  // Common path for an incoming datagram: validate, count, dispatch.
  // Called from loop() on socket-based platforms and from the lwip
  // recv callback on ESP8266.
  void on_packet_(std::span<const uint8_t> raw);
  // Pump the auto-created diagnostic sensors. Both platform paths call
  // this from loop() so the lwip-raw build still emits prometheus data.
  void publish_metrics_();
  // Send the already-encoded `datagram` once to `group`. Used by both the
  // initial publish() send and any retransmits scheduled via set_timeout.
  // Returns false on transport-level failure.
  bool send_datagram_(const std::vector<uint8_t> &datagram, const GroupAddr &group);
  // Dispatch retransmits according to retransmit_count_ semantics. For
  // count > 1, schedules (count-1) deferred resends via set_timeout. For
  // count == -1, installs a self-rescheduling timeout keyed on the topic
  // string; a subsequent publish() for the same topic cancels it. The
  // shared_ptr-captured buffer keeps the encoded packet alive until
  // either the last finite firing or the indefinite chain is cancelled.
  void schedule_retransmits_(const std::string &topic,
                             std::shared_ptr<std::vector<uint8_t>> datagram, const GroupAddr &group);
  // Cancel any indefinite retransmit chain for this topic. Safe to call
  // when no chain is active. Always called at the top of publish() so
  // each new publish replaces any prior indefinite stream cleanly --
  // even when the new publish has a finite retransmit_count.
  void cancel_indefinite_retransmit_(const std::string &topic);
#ifdef USE_ESP8266
  // Join `group` via mld6_joingroup. Called from setup() for groups
  // that exist before the stack is up, and from find_or_create_subscription_
  // for subscriptions added later.
  void join_group_(const GroupAddr &group, const char *topic);

 public:
  // Static lwip raw recv trampoline. Public so the C-linkage callback
  // shim can reach it. Not part of the user-facing API -- use subscribe()
  // / subscribe_typed() instead.
  static void recv_trampoline_(void *arg, struct udp_pcb *pcb, struct pbuf *p, const void *addr, uint16_t port);

 protected:
#endif

  uint16_t port_{18512};
  Scope scope_{Scope::LINK_LOCAL};
  uint8_t hops_{1};
  int16_t retransmit_count_{1};
  uint32_t retransmit_delay_ms_{100};
  bool encryption_enabled_{false};
  // 32 bytes = 8 32-bit XXTEA key words. We store as bytes and cast to
  // uint32_t* at call time -- the same byte layout packet_transport uses,
  // which makes the SHA-256 digest interpretation portable across hosts
  // (both x86 and Xtensa are little-endian, so the word view agrees).
  alignas(uint32_t) uint8_t encryption_key_bytes_[32]{};

  // Replay protection (Option B). The guard is inert until set_replay_window
  // configures a non-zero window. clock_ supplies the freshness reference on
  // both the send (stamp) and receive (check) sides.
  ReplayGuard replay_guard_{};
#ifdef USE_TIME
  time::RealTimeClock *clock_{nullptr};
#endif

#ifdef USE_ESP8266
  struct udp_pcb *pcb_{nullptr};
#else
  std::unique_ptr<socket::Socket> socket_{};
#endif
  std::vector<Subscription> subscriptions_{};

  sensor::Sensor *packets_sent_sensor_{nullptr};
  sensor::Sensor *packets_received_sensor_{nullptr};
  // Packet-level counters: every UDP datagram counts, including
  // retransmits on the sent side (one retransmit_count=3 publish() bumps
  // packets_sent_ by 3) and every received datagram on the recv side
  // before any topic / CRC filtering.
  uint32_t packets_sent_{0};
  uint32_t packets_received_{0};
  // Last value published to the sensors -- compared each loop() to avoid
  // republishing identical readings (publish_state() is otherwise quite
  // chatty: triggers filters, MQTT, prometheus state churn, ...).
  uint32_t last_published_sent_{UINT32_MAX};
  uint32_t last_published_received_{UINT32_MAX};

  // Active indefinite-retransmit jobs, keyed by topic. Each entry's
  // std::function reschedules itself via set_timeout("rt:<topic>", ...);
  // we hold a shared_ptr here as the chain's keepalive. A new publish()
  // for the same topic erases the entry, cancelling the chain.
  std::unordered_map<std::string, std::shared_ptr<std::function<void()>>> indefinite_jobs_{};
};

}  // namespace esphome::multicast_pubsub

#endif  // USE_NETWORK

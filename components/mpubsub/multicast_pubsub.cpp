#include "multicast_pubsub.h"

#ifdef USE_NETWORK

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "esphome/components/xxtea/xxtea.h"
#include "esphome/core/log.h"

namespace esphome::multicast_pubsub {

static const char *const TAG = "mpubsub";

// Build the XXTEA plaintext -- [crc || timestamp || nonce] prefix, then the
// payload, then zero pad -- and encrypt it in place. Shared by both platform
// publish() paths so the prefix layout lives in exactly one place.
void MulticastPubSub::encrypt_body_(uint8_t *body, size_t body_len, uint32_t crc,
                                    std::span<const uint8_t> payload) {
  uint32_t ts = this->replay_timestamp_();
  uint32_t nonce = random_uint32();
  // 12-byte prefix, all little-endian: crc(4) | timestamp(4) | nonce(4).
  body[0] = uint8_t(crc);
  body[1] = uint8_t(crc >> 8);
  body[2] = uint8_t(crc >> 16);
  body[3] = uint8_t(crc >> 24);
  body[4] = uint8_t(ts);
  body[5] = uint8_t(ts >> 8);
  body[6] = uint8_t(ts >> 16);
  body[7] = uint8_t(ts >> 24);
  body[8] = uint8_t(nonce);
  body[9] = uint8_t(nonce >> 8);
  body[10] = uint8_t(nonce >> 16);
  body[11] = uint8_t(nonce >> 24);
  std::memcpy(body + XXTEA_PREFIX_LEN, payload.data(), payload.size());
  std::memset(body + XXTEA_PREFIX_LEN + payload.size(), 0, body_len - XXTEA_PREFIX_LEN - payload.size());
  xxtea::encrypt(reinterpret_cast<uint32_t *>(body), body_len / 4,
                 reinterpret_cast<const uint32_t *>(this->encryption_key_bytes_));
}

// Decrypt an EncMode::XXTEA packet into a stack buffer, recover the
// crc/timestamp/nonce prefix, run the replay check, and dispatch. The
// decrypted span is only handed to deliver_(), which dispatches callbacks
// synchronously, so the buffer's lifetime is sufficient.
void MulticastPubSub::handle_encrypted_(const DecodedPacket &pkt) {
  if (!this->encryption_enabled_) {
    ESP_LOGV(TAG, "drop encrypted packet: this node has no encryption key");
    return;
  }
  std::array<uint8_t, MAX_DATAGRAM> work;
  size_t clen = pkt.payload.size();
  if (clen > work.size()) {
    ESP_LOGV(TAG, "drop encrypted packet: ciphertext %zu exceeds buffer", clen);
    return;
  }
  std::memcpy(work.data(), pkt.payload.data(), clen);
  xxtea::decrypt(reinterpret_cast<uint32_t *>(work.data()), clen / 4,
                 reinterpret_cast<const uint32_t *>(this->encryption_key_bytes_));
  uint32_t crc = uint32_t(work[0]) | (uint32_t(work[1]) << 8) | (uint32_t(work[2]) << 16) | (uint32_t(work[3]) << 24);
  uint32_t ts = uint32_t(work[4]) | (uint32_t(work[5]) << 8) | (uint32_t(work[6]) << 16) | (uint32_t(work[7]) << 24);
  uint32_t nonce =
      uint32_t(work[8]) | (uint32_t(work[9]) << 8) | (uint32_t(work[10]) << 16) | (uint32_t(work[11]) << 24);
  if (this->replay_guard_.enabled()) {
    uint32_t now = 0;
    bool now_valid = this->replay_now_(&now);
    if (!this->replay_guard_.accept(now, now_valid, ts, nonce)) {
      ESP_LOGV(TAG, "drop encrypted packet: replay/stale (ts=%u nonce=%08x)", ts, nonce);
      return;
    }
  }
  std::span<const uint8_t> body(work.data() + XXTEA_PREFIX_LEN, pkt.plaintext_len);
  this->deliver_(crc, pkt.encoding, body, /*was_encrypted=*/true);
}

}  // namespace esphome::multicast_pubsub

// arduino-esp8266 ships precompiled lwip2 with LWIP_SOCKET=0, so
// `lwip/sockets.h` exposes none of the BSD-style symbols we need
// (IPPROTO_UDP, IPV6_JOIN_GROUP, ipv6_mreq, sockaddr_in6, ...). On that
// platform we drop down to lwip's raw callback API (udp_*, mld6_*),
// which the IPv6 lwip variant selected by `network: enable_ipv6: true`
// (-DPIO_FRAMEWORK_ARDUINO_LWIP2_IPV6_LOW_MEMORY) does expose. The
// `socket::` abstraction is used on every other platform.
#if defined(USE_ESP8266)

#include "lwip/ip_addr.h"
#include "lwip/mld6.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"

namespace esphome::multicast_pubsub {

namespace {

// lwip raw recv callback. ESP8266 NONOS is single-tasked, so this fires
// on the same task as MulticastPubSub::loop() -- no locking needed.
// Calls back through the static recv_trampoline_ member so it can reach
// the (protected) on_packet_ method.
void recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
  MulticastPubSub::recv_trampoline_(arg, pcb, p, static_cast<const void *>(addr), port);
}

// Translate a 16-byte GroupAddr into an ip_addr_t holding the same IPv6
// bits. The GroupAddr is already in network byte order (the wire format
// of an IPv6 address); ip6_addr_t.addr is u32_t[4], also in network
// byte order, so a memcpy is correct without any endian fixup.
ip_addr_t to_ip_addr(const GroupAddr &group) {
  ip_addr_t out;
  std::memset(&out, 0, sizeof(out));
  std::memcpy(ip_2_ip6(&out)->addr, group.data(), 16);
  IP_SET_TYPE_VAL(out, IPADDR_TYPE_V6);
  return out;
}

}  // namespace

void MulticastPubSub::recv_trampoline_(void *arg, struct udp_pcb * /*pcb*/, struct pbuf *p,
                                       const void * /*addr*/, uint16_t /*port*/) {
  if (p == nullptr)
    return;
  auto *self = static_cast<MulticastPubSub *>(arg);
  std::array<uint8_t, MAX_DATAGRAM> buf;
  uint16_t copied = pbuf_copy_partial(p, buf.data(), std::min<uint16_t>(p->tot_len, buf.size()), 0);
  pbuf_free(p);
  self->on_packet_(std::span<const uint8_t>(buf.data(), copied));
}

void MulticastPubSub::setup() {
  this->pcb_ = udp_new_ip_type(IPADDR_TYPE_V6);
  if (this->pcb_ == nullptr) {
    ESP_LOGE(TAG, "udp_new_ip_type(IPV6) returned null");
    this->status_set_error(LOG_STR("udp_new_ip_type failed"));
    this->mark_failed();
    return;
  }
  // Bind to [::]:port so packets to any of our joined groups arrive.
  err_t err = udp_bind(this->pcb_, IP6_ADDR_ANY, this->port_);
  if (err != ERR_OK) {
    ESP_LOGE(TAG, "udp_bind() failed: err %d", err);
    udp_remove(this->pcb_);
    this->pcb_ = nullptr;
    this->status_set_error(LOG_STR("udp_bind failed"));
    this->mark_failed();
    return;
  }
  // Outgoing multicast hop limit. The IPv6 lwip variant gates this on
  // LWIP_MULTICAST_TX_OPTIONS; the macro is a no-op if absent.
#if LWIP_MULTICAST_TX_OPTIONS
  udp_set_multicast_ttl(this->pcb_, this->hops_);
#endif
  udp_recv(this->pcb_, recv_cb, this);

  // Don't try to join groups yet -- on ESP8266 wifi (and its netif) come
  // up asynchronously, so `netif_default` is often still null at
  // AFTER_WIFI setup priority. Mark all existing subscriptions as
  // not-yet-joined; loop() handles them once the netif appears.
  for (auto &sub : this->subscriptions_) {
    sub.joined = false;
  }
}

void MulticastPubSub::join_group_(const GroupAddr &group, const char *topic) {
  if (netif_default == nullptr)
    return;
  ip6_addr_t g6;
  std::memcpy(g6.addr, group.data(), 16);
#if LWIP_IPV6_SCOPES
  ip6_addr_clear_zone(&g6);
#endif
  err_t err = mld6_joingroup_netif(netif_default, &g6);
  if (err != ERR_OK) {
    ESP_LOGW(TAG, "mld6_joingroup_netif failed for topic '%s': err %d", topic, err);
    this->status_set_warning(LOG_STR("Failed to join multicast group"));
  }
}

void MulticastPubSub::loop() {
  // Drive deferred MLD joins and the pcb's multicast-netif index once
  // wifi's netif shows up. Cheap to check each loop -- a pointer compare
  // and (usually) an early-exit boolean scan.
  if (this->pcb_ != nullptr && netif_default != nullptr) {
#if LWIP_MULTICAST_TX_OPTIONS
    if (this->pcb_->mcast_ifindex == 0) {
      udp_set_multicast_netif_index(this->pcb_, netif_get_index(netif_default));
    }
#endif
    for (auto &sub : this->subscriptions_) {
      if (!sub.joined) {
        this->join_group_(sub.group, sub.topic.c_str());
        sub.joined = true;  // set even on failure so we don't log-spam
      }
    }
  }
  this->publish_metrics_();
}

void MulticastPubSub::dump_config() {
  const char *scope_name = "link-local";
  switch (this->scope_) {
    case Scope::LINK_LOCAL:
      scope_name = "link-local";
      break;
    case Scope::SITE_LOCAL:
      scope_name = "site-local";
      break;
    case Scope::ORG_LOCAL:
      scope_name = "organization-local";
      break;
  }
  char rt_buf[32];
  if (this->retransmit_count_ == -1) {
    std::snprintf(rt_buf, sizeof(rt_buf), "indefinite, %u ms apart", this->retransmit_delay_ms_);
  } else {
    std::snprintf(rt_buf, sizeof(rt_buf), "%d packet(s), %u ms apart", this->retransmit_count_,
                  this->retransmit_delay_ms_);
  }
  ESP_LOGCONFIG(TAG,
                "Multicast Pub/Sub (ESP8266 / lwip raw):\n"
                "  Port: %u\n"
                "  Scope: %s\n"
                "  Hops: %u\n"
                "  Retransmit: %s\n"
                "  Encryption: %s\n"
                "  Subscriptions: %u",
                this->port_, scope_name, this->hops_, rt_buf,
                this->encryption_enabled_ ? "xxtea-256" : "none",
                static_cast<unsigned>(this->subscriptions_.size()));
  if (this->replay_guard_.enabled()) {
    ESP_LOGCONFIG(TAG, "  Replay protection: on (window %us)", this->replay_guard_.window());
  }
  for (const auto &sub : this->subscriptions_) {
    char addr_buf[64];
    group_to_string(sub.group, addr_buf, sizeof(addr_buf));
    ESP_LOGCONFIG(TAG, "    '%s' -> [%s]:%u (crc=%08x, raw=%zu typed=%zu)", sub.topic.c_str(), addr_buf, this->port_,
                  sub.crc, sub.raw_callbacks.size(), sub.typed_callbacks.size());
  }
}

Subscription *MulticastPubSub::find_subscription_(const std::string &topic) {
  for (auto &sub : this->subscriptions_) {
    if (sub.topic == topic)
      return &sub;
  }
  return nullptr;
}

Subscription *MulticastPubSub::find_or_create_subscription_(const std::string &topic, bool require_encryption) {
  if (Subscription *existing = this->find_subscription_(topic)) {
    if (require_encryption)
      existing->require_encryption = true;
    return existing;
  }
  Subscription sub;
  sub.topic = topic;
  sub.crc = topic_crc32(topic);
  sub.group = topic_to_group(topic, this->scope_);
  sub.joined = false;  // loop() picks it up once netif_default is available
  sub.require_encryption = require_encryption;
  this->subscriptions_.push_back(std::move(sub));
  return &this->subscriptions_.back();
}

void MulticastPubSub::subscribe(const std::string &topic, MessageCallback cb, bool require_encryption) {
  Subscription *sub = this->find_or_create_subscription_(topic, require_encryption);
  sub->raw_callbacks.push_back(std::move(cb));
}

bool MulticastPubSub::publish(const std::string &topic, std::span<const uint8_t> payload, Encoding encoding) {
  if (this->pcb_ == nullptr) {
    ESP_LOGW(TAG, "publish(%s): pcb not ready", topic.c_str());
    return false;
  }
  // The encrypted body is roundup4(12 + payload.size()); the +12 is the
  // [crc || timestamp || nonce] prefix carried inside the ciphertext, so
  // encrypted publishes are capped 12 bytes lower than plaintext ones (the
  // up-to-3 bytes of XXTEA word padding still fit under the 1220-byte cap).
  size_t effective_max = this->encryption_enabled_ ? (MAX_PAYLOAD - XXTEA_PREFIX_LEN) : MAX_PAYLOAD;
  if (payload.size() > effective_max) {
    ESP_LOGE(TAG, "publish('%s') rejected: payload %zu bytes exceeds max %zu (datagram limit %zu - 12-byte header)",
             topic.c_str(), payload.size(), effective_max, MAX_DATAGRAM);
    this->status_set_warning(LOG_STR("oversize publish payload"));
    return false;
  }
  if (netif_default == nullptr) {
    ESP_LOGW(TAG, "publish(%s): no netif yet", topic.c_str());
    return false;
  }
  uint32_t crc = topic_crc32(topic);
  GroupAddr group = topic_to_group(topic, this->scope_);
  EncMode mode = this->encryption_enabled_ ? EncMode::XXTEA : EncMode::NONE;
  size_t body_len = (mode == EncMode::XXTEA) ? xxtea_ciphertext_len(payload.size()) : payload.size();
  size_t total = HEADER_LEN + body_len;
  auto datagram = std::make_shared<std::vector<uint8_t>>(total);
  encode_header(crc, encoding, static_cast<uint16_t>(payload.size()), datagram->data(), mode);
  uint8_t *body = datagram->data() + HEADER_LEN;
  if (mode == EncMode::XXTEA) {
    this->encrypt_body_(body, body_len, crc, payload);
  } else {
    std::memcpy(body, payload.data(), payload.size());
  }

  if (!this->send_datagram_(*datagram, group)) {
    ESP_LOGW(TAG, "publish(%s): initial send failed", topic.c_str());
    return false;
  }
  ESP_LOGV(TAG, "published %zu bytes to '%s'", payload.size(), topic.c_str());
  this->schedule_retransmits_(topic, datagram, group);
  return true;
}

bool MulticastPubSub::send_datagram_(const std::vector<uint8_t> &datagram, const GroupAddr &group) {
  if (this->pcb_ == nullptr || netif_default == nullptr)
    return false;
  struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(datagram.size()), PBUF_RAM);
  if (p == nullptr) {
    ESP_LOGW(TAG, "send_datagram: pbuf_alloc(%zu) failed", datagram.size());
    return false;
  }
  std::memcpy(p->payload, datagram.data(), datagram.size());
  ip_addr_t dest = to_ip_addr(group);
  // udp_sendto_if (not plain udp_sendto): link-local IPv6 multicast has no
  // route lookup, so the egress netif must be passed explicitly.
  err_t err = udp_sendto_if(this->pcb_, p, &dest, this->port_, netif_default);
  pbuf_free(p);
  if (err != ERR_OK) {
    ESP_LOGW(TAG, "send_datagram: udp_sendto_if err %d", err);
    return false;
  }
  // Count packets, not publish() invocations: a publish() with
  // retransmit_count=3 bumps this by 3 over the resend interval.
  this->packets_sent_++;
  return true;
}

bool MulticastPubSub::publish_dynamic(const std::string &topic, uint16_t schema_id,
                                      std::span<const uint8_t> proto_bytes) {
  std::array<uint8_t, MAX_PAYLOAD> buf;
  if (proto_bytes.size() + 2 > MAX_PAYLOAD) {
    ESP_LOGE(TAG, "publish_dynamic('%s'): payload %zu bytes exceeds max %zu", topic.c_str(), proto_bytes.size() + 2,
             MAX_PAYLOAD);
    return false;
  }
  buf[0] = static_cast<uint8_t>(schema_id);
  buf[1] = static_cast<uint8_t>(schema_id >> 8);
  std::memcpy(buf.data() + 2, proto_bytes.data(), proto_bytes.size());
  return this->publish(topic, std::span<const uint8_t>(buf.data(), 2 + proto_bytes.size()), Encoding::PROTOBUF);
}

void MulticastPubSub::on_packet_(std::span<const uint8_t> raw) {
  // Count every datagram delivered to the socket -- including malformed
  // and unsubscribed-topic packets. This matches what tcpdump on the
  // listening interface would show; subtracting topic-matched callbacks
  // gives a "stray traffic" signal.
  this->packets_received_++;
  DecodedPacket pkt;
  auto err = decode(raw, &pkt);
  if (err != DecodeError::OK) {
    ESP_LOGV(TAG, "drop packet: decode err %u", static_cast<unsigned>(err));
    return;
  }
  if (pkt.enc_mode == EncMode::XXTEA) {
    this->handle_encrypted_(pkt);
    return;
  }
  this->deliver_(pkt.topic_crc, pkt.encoding, pkt.payload, /*was_encrypted=*/false);
}

void MulticastPubSub::deliver_(uint32_t crc, Encoding encoding, std::span<const uint8_t> payload, bool was_encrypted) {
  for (auto &sub : this->subscriptions_) {
    if (sub.crc != crc)
      continue;
    if (sub.require_encryption && !was_encrypted) {
      ESP_LOGV(TAG, "drop plaintext packet for encryption-required topic '%s'", sub.topic.c_str());
      continue;
    }
    if (encoding == Encoding::RAW) {
      for (auto &cb : sub.raw_callbacks)
        cb(payload);
    } else if (encoding == Encoding::PROTOBUF) {
      if (payload.size() < 2) {
        ESP_LOGV(TAG, "drop PROTOBUF packet: body too short for SCHEMA_ID (%zu)", payload.size());
        continue;
      }
      uint16_t schema_id = static_cast<uint16_t>(payload[0]) | (static_cast<uint16_t>(payload[1]) << 8);
      auto body = payload.subspan(2);
      bool matched_any = false;
      for (auto &tc : sub.typed_callbacks) {
        if (tc.schema_id == schema_id) {
          tc.callback(body);
          matched_any = true;
        }
      }
      if (!matched_any) {
        ESP_LOGV(TAG, "no typed callback for topic '%s' schema_id=%04x", sub.topic.c_str(), schema_id);
      }
    }
  }
}

void MulticastPubSub::publish_metrics_() {
  if (this->packets_sent_sensor_ != nullptr && this->packets_sent_ != this->last_published_sent_) {
    this->packets_sent_sensor_->publish_state(static_cast<float>(this->packets_sent_));
    this->last_published_sent_ = this->packets_sent_;
  }
  if (this->packets_received_sensor_ != nullptr && this->packets_received_ != this->last_published_received_) {
    this->packets_received_sensor_->publish_state(static_cast<float>(this->packets_received_));
    this->last_published_received_ = this->packets_received_;
  }
}

void MulticastPubSub::cancel_indefinite_retransmit_(const std::string &topic) {
  auto it = this->indefinite_jobs_.find(topic);
  if (it != this->indefinite_jobs_.end()) {
    this->cancel_timeout(topic_crc32(topic));
    this->indefinite_jobs_.erase(it);
  }
}

void MulticastPubSub::schedule_retransmits_(const std::string &topic,
                                            std::shared_ptr<std::vector<uint8_t>> datagram,
                                            const GroupAddr &group) {
  // Every publish() supersedes any prior indefinite chain for the same
  // topic, regardless of the new publish's retransmit_count.
  this->cancel_indefinite_retransmit_(topic);
  if (this->retransmit_count_ == -1) {
    // Indefinite: self-rescheduling timeout keyed on the topic's CRC32.
    // Lifecycle is owned by indefinite_jobs_[topic]; the lambda looks
    // the function back up on each firing and copies it into the next
    // set_timeout slot. ESPHome's uint32_t-id overload of set_timeout
    // is used because the std::string overload is deprecated and goes
    // away in 2026.7.
    uint32_t delay = this->retransmit_delay_ms_;
    uint32_t rt_id = topic_crc32(topic);
    auto fn = std::make_shared<std::function<void()>>();
    *fn = [this, datagram, group, topic, delay, rt_id]() {
      this->send_datagram_(*datagram, group);
      auto it = this->indefinite_jobs_.find(topic);
      if (it != this->indefinite_jobs_.end()) {
        this->set_timeout(rt_id, delay, std::function<void()>(*it->second));
      }
    };
    this->indefinite_jobs_[topic] = fn;
    this->set_timeout(rt_id, delay, std::function<void()>(*fn));
    return;
  }
  // Finite: schedule (count - 1) additional sends via Component::set_timeout,
  // dispatched from loop() so each fire is non-blocking. The shared_ptr
  // captured by value in each lambda keeps the buffer alive until the
  // final firing.
  for (int16_t i = 1; i < this->retransmit_count_; i++) {
    this->set_timeout(this->retransmit_delay_ms_ * i, [this, datagram, group]() {
      this->send_datagram_(*datagram, group);
    });
  }
}

}  // namespace esphome::multicast_pubsub

#else  // !USE_ESP8266 -- real implementation

// Pull in the platform's `sockaddr_in6` / `ipv6_mreq` definitions. The
// ESPHome socket abstraction takes care of selecting BSD vs LwIP sockets, but
// the IPv6 multicast group-membership struct is the same shape on both:
// 16-byte multicast address + 4-byte interface index.
#if defined(USE_SOCKET_IMPL_BSD_SOCKETS)
#include <netinet/in.h>
#include <sys/socket.h>
#elif defined(USE_SOCKET_IMPL_LWIP_SOCKETS)
#include "lwip/sockets.h"
#endif

namespace esphome::multicast_pubsub {

void MulticastPubSub::setup() {
  this->socket_ = socket::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (!this->socket_) {
    this->status_set_error(LOG_STR("Failed to create IPv6 UDP socket"));
    this->mark_failed();
    return;
  }
  int enable = 1;
  this->socket_->setsockopt(SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
  this->socket_->setblocking(false);

  // Set the outgoing multicast hop limit. Default 1 = link-local-only travel;
  // users can raise it via the `hops:` YAML option.
  int hops = this->hops_;
  this->socket_->setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));

  // Bind to [::]:port so we can receive from any joined group.
  struct sockaddr_in6 server {};
  server.sin6_family = AF_INET6;
  server.sin6_port = htons(this->port_);
  // sin6_addr defaults to in6addr_any (all zeros).
  if (this->socket_->bind(reinterpret_cast<struct sockaddr *>(&server), sizeof(server)) != 0) {
    ESP_LOGE(TAG, "bind() failed: errno %d", errno);
    this->status_set_error(LOG_STR("bind failed"));
    this->mark_failed();
    return;
  }

  // Join all the multicast groups configured at startup.
  for (auto &sub : this->subscriptions_) {
    struct ipv6_mreq mreq {};
    std::memcpy(&mreq.ipv6mr_multiaddr, sub.group.data(), sub.group.size());
    mreq.ipv6mr_interface = 0;  // default interface
    if (this->socket_->setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) != 0) {
      ESP_LOGW(TAG, "IPV6_JOIN_GROUP failed for topic '%s': errno %d", sub.topic.c_str(), errno);
      this->status_set_warning(LOG_STR("Failed to join multicast group"));
      // Continue — bad topic shouldn't kill the whole component.
    }
  }
}

void MulticastPubSub::loop() {
  if (this->socket_) {
    std::array<uint8_t, MAX_DATAGRAM> buf;
    for (;;) {
      auto n = this->socket_->read(buf.data(), buf.size());
      if (n <= 0)
        break;
      this->on_packet_(std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)));
    }
  }
  this->publish_metrics_();
}

void MulticastPubSub::on_packet_(std::span<const uint8_t> raw) {
  // See ESP8266 branch on_packet_ for the "count datagrams, not topic
  // matches" rationale.
  this->packets_received_++;
  DecodedPacket pkt;
  auto err = decode(raw, &pkt);
  if (err != DecodeError::OK) {
    ESP_LOGV(TAG, "drop packet: decode err %u", static_cast<unsigned>(err));
    return;
  }
  if (pkt.enc_mode == EncMode::XXTEA) {
    if (!this->encryption_enabled_) {
      ESP_LOGV(TAG, "drop encrypted packet: this node has no encryption key");
      return;
    }
    std::array<uint8_t, MAX_DATAGRAM> work;
    size_t clen = pkt.payload.size();
    if (clen > work.size()) {
      ESP_LOGV(TAG, "drop encrypted packet: ciphertext %zu exceeds buffer", clen);
      return;
    }
    std::memcpy(work.data(), pkt.payload.data(), clen);
    xxtea::decrypt(reinterpret_cast<uint32_t *>(work.data()), clen / 4,
                   reinterpret_cast<const uint32_t *>(this->encryption_key_bytes_));
    uint32_t crc = uint32_t(work[0]) | (uint32_t(work[1]) << 8) | (uint32_t(work[2]) << 16) | (uint32_t(work[3]) << 24);
    std::span<const uint8_t> body(work.data() + 4, pkt.plaintext_len);
    this->deliver_(crc, pkt.encoding, body, /*was_encrypted=*/true);
    return;
  }
  this->deliver_(pkt.topic_crc, pkt.encoding, pkt.payload, /*was_encrypted=*/false);
}

void MulticastPubSub::publish_metrics_() {
  if (this->packets_sent_sensor_ != nullptr && this->packets_sent_ != this->last_published_sent_) {
    this->packets_sent_sensor_->publish_state(static_cast<float>(this->packets_sent_));
    this->last_published_sent_ = this->packets_sent_;
  }
  if (this->packets_received_sensor_ != nullptr && this->packets_received_ != this->last_published_received_) {
    this->packets_received_sensor_->publish_state(static_cast<float>(this->packets_received_));
    this->last_published_received_ = this->packets_received_;
  }
}

void MulticastPubSub::dump_config() {
  const char *scope_name = "link-local";
  switch (this->scope_) {
    case Scope::LINK_LOCAL:
      scope_name = "link-local";
      break;
    case Scope::SITE_LOCAL:
      scope_name = "site-local";
      break;
    case Scope::ORG_LOCAL:
      scope_name = "organization-local";
      break;
  }
  char rt_buf[32];
  if (this->retransmit_count_ == -1) {
    std::snprintf(rt_buf, sizeof(rt_buf), "indefinite, %u ms apart", this->retransmit_delay_ms_);
  } else {
    std::snprintf(rt_buf, sizeof(rt_buf), "%d packet(s), %u ms apart", this->retransmit_count_,
                  this->retransmit_delay_ms_);
  }
  ESP_LOGCONFIG(TAG,
                "Multicast Pub/Sub:\n"
                "  Port: %u\n"
                "  Scope: %s\n"
                "  Hops: %u\n"
                "  Retransmit: %s\n"
                "  Encryption: %s\n"
                "  Subscriptions: %u",
                this->port_, scope_name, this->hops_, rt_buf,
                this->encryption_enabled_ ? "xxtea-256" : "none",
                static_cast<unsigned>(this->subscriptions_.size()));
  if (this->replay_guard_.enabled()) {
    ESP_LOGCONFIG(TAG, "  Replay protection: on (window %us)", this->replay_guard_.window());
  }
  for (const auto &sub : this->subscriptions_) {
    char addr_buf[64];
    group_to_string(sub.group, addr_buf, sizeof(addr_buf));
    ESP_LOGCONFIG(TAG, "    '%s' -> [%s]:%u (crc=%08x, raw=%zu typed=%zu)", sub.topic.c_str(), addr_buf, this->port_,
                  sub.crc, sub.raw_callbacks.size(), sub.typed_callbacks.size());
  }
}

Subscription *MulticastPubSub::find_subscription_(const std::string &topic) {
  for (auto &sub : this->subscriptions_) {
    if (sub.topic == topic)
      return &sub;
  }
  return nullptr;
}

Subscription *MulticastPubSub::find_or_create_subscription_(const std::string &topic, bool require_encryption) {
  if (Subscription *existing = this->find_subscription_(topic)) {
    if (require_encryption)
      existing->require_encryption = true;
    return existing;
  }
  Subscription sub;
  sub.topic = topic;
  sub.crc = topic_crc32(topic);
  sub.group = topic_to_group(topic, this->scope_);
  sub.require_encryption = require_encryption;
  this->subscriptions_.push_back(std::move(sub));
  // Group join happens in setup() for subscriptions registered before then;
  // for late subscriptions, join immediately so we start receiving.
  if (this->socket_) {
    auto &just_added = this->subscriptions_.back();
    struct ipv6_mreq mreq {};
    std::memcpy(&mreq.ipv6mr_multiaddr, just_added.group.data(), just_added.group.size());
    mreq.ipv6mr_interface = 0;
    if (this->socket_->setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) != 0) {
      ESP_LOGW(TAG, "Late IPV6_JOIN_GROUP failed for topic '%s': errno %d", just_added.topic.c_str(), errno);
    }
  }
  return &this->subscriptions_.back();
}

void MulticastPubSub::subscribe(const std::string &topic, MessageCallback cb, bool require_encryption) {
  Subscription *sub = this->find_or_create_subscription_(topic, require_encryption);
  sub->raw_callbacks.push_back(std::move(cb));
}

bool MulticastPubSub::publish(const std::string &topic, std::span<const uint8_t> payload, Encoding encoding) {
  if (!this->socket_) {
    ESP_LOGW(TAG, "publish(%s): socket not ready", topic.c_str());
    return false;
  }
  // The encrypted body is roundup4(12 + payload.size()); the +12 is the
  // [crc || timestamp || nonce] prefix carried inside the ciphertext, so
  // encrypted publishes are capped 12 bytes lower than plaintext ones (the
  // up-to-3 bytes of XXTEA word padding still fit under the 1220-byte cap).
  size_t effective_max = this->encryption_enabled_ ? (MAX_PAYLOAD - XXTEA_PREFIX_LEN) : MAX_PAYLOAD;
  if (payload.size() > effective_max) {
    ESP_LOGE(TAG, "publish('%s') rejected: payload %zu bytes exceeds max %zu (datagram limit %zu - 12-byte header)",
             topic.c_str(), payload.size(), effective_max, MAX_DATAGRAM);
    this->status_set_warning(LOG_STR("oversize publish payload"));
    return false;
  }
  uint32_t crc = topic_crc32(topic);
  GroupAddr group = topic_to_group(topic, this->scope_);
  EncMode mode = this->encryption_enabled_ ? EncMode::XXTEA : EncMode::NONE;
  size_t body_len = (mode == EncMode::XXTEA) ? xxtea_ciphertext_len(payload.size()) : payload.size();
  size_t total = HEADER_LEN + body_len;
  auto datagram = std::make_shared<std::vector<uint8_t>>(total);
  encode_header(crc, encoding, static_cast<uint16_t>(payload.size()), datagram->data(), mode);
  uint8_t *body = datagram->data() + HEADER_LEN;
  if (mode == EncMode::XXTEA) {
    this->encrypt_body_(body, body_len, crc, payload);
  } else {
    std::memcpy(body, payload.data(), payload.size());
  }

  if (!this->send_datagram_(*datagram, group)) {
    ESP_LOGW(TAG, "publish(%s): initial send failed", topic.c_str());
    return false;
  }
  ESP_LOGV(TAG, "published %zu bytes to '%s'", payload.size(), topic.c_str());
  this->schedule_retransmits_(topic, datagram, group);
  return true;
}

bool MulticastPubSub::send_datagram_(const std::vector<uint8_t> &datagram, const GroupAddr &group) {
  if (!this->socket_)
    return false;
  struct sockaddr_in6 dest {};
  dest.sin6_family = AF_INET6;
  dest.sin6_port = htons(this->port_);
  std::memcpy(&dest.sin6_addr, group.data(), group.size());
  auto sent = this->socket_->sendto(datagram.data(), datagram.size(), 0,
                                    reinterpret_cast<struct sockaddr *>(&dest), sizeof(dest));
  if (sent < 0) {
    ESP_LOGW(TAG, "send_datagram: sendto errno %d", errno);
    return false;
  }
  // Count packets, not publish() invocations: a publish() with
  // retransmit_count=3 bumps this by 3 over the resend interval.
  this->packets_sent_++;
  return true;
}

bool MulticastPubSub::publish_dynamic(const std::string &topic, uint16_t schema_id,
                                      std::span<const uint8_t> proto_bytes) {
  // Same wire layout as the typed publish<T>: ENCODING=PROTOBUF, body =
  // SCHEMA_ID (2 LE bytes) || proto bytes. publish() enforces the
  // 1220-byte payload cap for us.
  std::array<uint8_t, MAX_PAYLOAD> buf;
  if (proto_bytes.size() + 2 > MAX_PAYLOAD) {
    ESP_LOGE(TAG, "publish_dynamic('%s'): payload %zu bytes exceeds max %zu", topic.c_str(),
             proto_bytes.size() + 2, MAX_PAYLOAD);
    return false;
  }
  buf[0] = static_cast<uint8_t>(schema_id);
  buf[1] = static_cast<uint8_t>(schema_id >> 8);
  std::memcpy(buf.data() + 2, proto_bytes.data(), proto_bytes.size());
  return this->publish(topic, std::span<const uint8_t>(buf.data(), 2 + proto_bytes.size()), Encoding::PROTOBUF);
}

void MulticastPubSub::deliver_(uint32_t crc, Encoding encoding, std::span<const uint8_t> payload, bool was_encrypted) {
  for (auto &sub : this->subscriptions_) {
    if (sub.crc != crc)
      continue;
    if (sub.require_encryption && !was_encrypted) {
      ESP_LOGV(TAG, "drop plaintext packet for encryption-required topic '%s'", sub.topic.c_str());
      continue;
    }
    if (encoding == Encoding::RAW) {
      for (auto &cb : sub.raw_callbacks)
        cb(payload);
    } else if (encoding == Encoding::PROTOBUF) {
      if (payload.size() < 2) {
        ESP_LOGV(TAG, "drop PROTOBUF packet: body too short for SCHEMA_ID (%zu)", payload.size());
        continue;
      }
      uint16_t schema_id = static_cast<uint16_t>(payload[0]) | (static_cast<uint16_t>(payload[1]) << 8);
      auto body = payload.subspan(2);
      bool matched_any = false;
      for (auto &tc : sub.typed_callbacks) {
        if (tc.schema_id == schema_id) {
          tc.callback(body);
          matched_any = true;
        }
      }
      if (!matched_any) {
        // Helps diagnose stale-deploy issues where publisher and subscriber
        // have drifted on schema definitions.
        ESP_LOGV(TAG, "no typed callback for topic '%s' schema_id=%04x", sub.topic.c_str(), schema_id);
      }
    }
  }
}

void MulticastPubSub::cancel_indefinite_retransmit_(const std::string &topic) {
  auto it = this->indefinite_jobs_.find(topic);
  if (it != this->indefinite_jobs_.end()) {
    this->cancel_timeout(topic_crc32(topic));
    this->indefinite_jobs_.erase(it);
  }
}

void MulticastPubSub::schedule_retransmits_(const std::string &topic,
                                            std::shared_ptr<std::vector<uint8_t>> datagram,
                                            const GroupAddr &group) {
  // See ESP8266 branch for the indefinite-mode rationale.
  this->cancel_indefinite_retransmit_(topic);
  if (this->retransmit_count_ == -1) {
    uint32_t delay = this->retransmit_delay_ms_;
    uint32_t rt_id = topic_crc32(topic);
    auto fn = std::make_shared<std::function<void()>>();
    *fn = [this, datagram, group, topic, delay, rt_id]() {
      this->send_datagram_(*datagram, group);
      auto it = this->indefinite_jobs_.find(topic);
      if (it != this->indefinite_jobs_.end()) {
        this->set_timeout(rt_id, delay, std::function<void()>(*it->second));
      }
    };
    this->indefinite_jobs_[topic] = fn;
    this->set_timeout(rt_id, delay, std::function<void()>(*fn));
    return;
  }
  for (int16_t i = 1; i < this->retransmit_count_; i++) {
    this->set_timeout(this->retransmit_delay_ms_ * i, [this, datagram, group]() {
      this->send_datagram_(*datagram, group);
    });
  }
}

}  // namespace esphome::multicast_pubsub

#endif  // !USE_ESP8266

#endif  // USE_NETWORK

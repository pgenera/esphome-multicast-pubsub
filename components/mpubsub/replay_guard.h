// Receiver-side replay rejection for encrypted mpubsub traffic.
//
// A captured encrypted datagram is byte-identical however long after it was
// recorded, so anyone off the L2 segment can replay it. The defense needs
// no persistent state -- it survives a reboot because the freshness
// reference is the externally-synced wall clock, not a stored counter:
//
//   1. Freshness window. The sender stamps each packet with the current
//      unix time inside the ciphertext (an attacker without the key can't
//      move it without breaking authentication). The receiver drops
//      anything more than `window` seconds away from its own clock.
//
//   2. Nonce de-duplication. Within the window a verbatim copy would still
//      pass the freshness check, so the receiver remembers the per-message
//      nonces it has seen recently and drops repeats. Legitimate retransmits
//      (retransmit_count > 1) reuse their nonce, so they collapse to a
//      single delivery; two genuinely distinct publications carry different
//      nonces even when their payloads are identical.
//
// The cache is a fixed-capacity ring (no heap) so it costs a predictable
// `Capacity * 8` bytes -- important on ESP8266-class RAM. It may be empty
// after a reboot, which is harmless: layer 1 already rejects anything older
// than the window, so there is nothing for the cache to remember across a
// restart.
//
// This must agree, decision-for-decision, with the Python reference
// `ReplayGuard` (tests/unit/reference.py) and the Go bridge `replayGuard`.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace esphome::multicast_pubsub {

template<size_t Capacity = 64> class ReplayGuardT {
 public:
  ReplayGuardT() = default;
  explicit ReplayGuardT(uint32_t window_seconds) : window_(window_seconds) {}

  void set_window(uint32_t window_seconds) { this->window_ = window_seconds; }
  uint32_t window() const { return this->window_; }
  // Replay protection is active only when a non-zero window is configured.
  bool enabled() const { return this->window_ != 0; }

  // Return true if a packet stamped (`timestamp`, `nonce`) is fresh and
  // previously unseen -- recording it as the side effect. Return false
  // (drop) otherwise.
  //
  // `now` is the receiver's current unix time and `now_valid` whether its
  // clock has actually synced. The guard fails closed: a window of 0 aside,
  // an unsynced local clock or a packet whose timestamp is 0 (the sender
  // had no clock) is rejected, never silently admitted.
  bool accept(uint32_t now, bool now_valid, uint32_t timestamp, uint32_t nonce) {
    if (this->window_ == 0)
      return true;  // protection disabled -> accept everything
    if (!now_valid)
      return false;  // can't verify freshness yet -> fail closed
    if (timestamp == 0)
      return false;  // sender had no synchronized clock -> unverifiable
    uint32_t skew = now >= timestamp ? now - timestamp : timestamp - now;
    if (skew > this->window_)
      return false;  // stale, or too far in the future (skewed/seeded clock)

    this->prune_(now);
    for (size_t i = 0; i < this->count_; i++) {
      if (this->slots_[(this->head_ + i) % Capacity].nonce == nonce)
        return false;  // replay / duplicate within the window
    }
    // Record. When the ring is full, overwrite (and so drop) the oldest.
    size_t idx;
    if (this->count_ < Capacity) {
      idx = (this->head_ + this->count_) % Capacity;
      this->count_++;
    } else {
      idx = this->head_;
      this->head_ = (this->head_ + 1) % Capacity;
    }
    this->slots_[idx].nonce = nonce;
    this->slots_[idx].timestamp = timestamp;
    return true;
  }

 private:
  struct Entry {
    uint32_t nonce{0};
    uint32_t timestamp{0};
  };

  // Drop entries older than the window from the front of the ring. Insertion
  // order tracks timestamp order (the clock advances), so the oldest live
  // entry is always at `head_`.
  void prune_(uint32_t now) {
    while (this->count_ > 0) {
      const Entry &oldest = this->slots_[this->head_];
      if (now > oldest.timestamp && (now - oldest.timestamp) > this->window_) {
        this->head_ = (this->head_ + 1) % Capacity;
        this->count_--;
      } else {
        break;
      }
    }
  }

  uint32_t window_{0};
  size_t head_{0};
  size_t count_{0};
  std::array<Entry, Capacity> slots_{};
};

using ReplayGuard = ReplayGuardT<64>;

}  // namespace esphome::multicast_pubsub

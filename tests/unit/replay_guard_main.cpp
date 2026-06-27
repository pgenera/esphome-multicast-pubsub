// CLI harness for ReplayGuardT<64> -- the actual C++ replay guard used by the
// ESPHome component. tests/unit/test_replay_cpp.py drives the same command
// stream through this binary and the Python reference ReplayGuard, asserting
// identical accept/reject decisions.
//
// Commands (one per line):
//   N <window>                     reset: new guard with this freshness window
//   A <now> <valid> <ts> <nonce>   accept(); prints "1" (accept) or "0" (drop)
//
// Capacity is fixed at 64 to match ReplayGuard's production default; the
// Python side constructs ReplayGuard(window, max_entries=64) to agree.

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>

#include "../../components/mpubsub/replay_guard.h"

using esphome::multicast_pubsub::ReplayGuardT;

int main() {
  ReplayGuardT<64> guard(0);
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty())
      continue;
    std::istringstream is(line);
    char cmd;
    is >> cmd;
    if (cmd == 'N') {
      uint32_t window = 0;
      is >> window;
      guard = ReplayGuardT<64>(window);
      std::printf("OK\n");
    } else if (cmd == 'A') {
      // Parse into wide types so out-of-range input can't trap before we
      // truncate to the uint32_t the guard actually uses.
      uint64_t now = 0, ts = 0, nonce = 0;
      int valid = 0;
      is >> now >> valid >> ts >> nonce;
      bool ok = guard.accept(static_cast<uint32_t>(now), valid != 0, static_cast<uint32_t>(ts),
                             static_cast<uint32_t>(nonce));
      std::printf("%d\n", ok ? 1 : 0);
    } else {
      std::printf("ERR\n");
    }
    std::fflush(stdout);
  }
  return 0;
}

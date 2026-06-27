# Builds standalone C++ test binaries for the mpubsub component.
# Used by tests/unit/test_topic_hash_cpp.py and test_wire_format_cpp.py.

CXX ?= g++
CXXFLAGS ?= -std=gnu++20 -O0 -g -Wall -Wextra -Wno-unused-parameter
# Sanitizer flags applied to *_san binaries to catch UB / OOB during fuzzing.
SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

COMP := ../../components/mpubsub

.PHONY: all clean
all: topic_hash_test wire_format_test wire_format_test_san topic_hash_test_san \
     replay_guard_test replay_guard_test_san

# DynamicMessage / DynamicReader are exercised end-to-end via the host
# integration build (tests/typed_publisher.yaml's dynamic-publish lambda)
# rather than a standalone harness -- building those classes outside
# ESPHome would require pulling in core/helpers, defines, log, etc.

topic_hash_test: topic_hash_main.cpp $(COMP)/topic_hash.cpp $(COMP)/topic_hash.h \
                 $(COMP)/sha256.cpp $(COMP)/sha256.h
	$(CXX) $(CXXFLAGS) -I$(COMP) -o $@ topic_hash_main.cpp $(COMP)/topic_hash.cpp $(COMP)/sha256.cpp

wire_format_test: wire_format_main.cpp $(COMP)/wire_format.cpp $(COMP)/wire_format.h
	$(CXX) $(CXXFLAGS) -I$(COMP) -o $@ wire_format_main.cpp $(COMP)/wire_format.cpp

# Sanitizer variants -- same source, ASan + UBSan added. Used by the
# fuzzing tests to catch silent UB the regular harness wouldn't show.
topic_hash_test_san: topic_hash_main.cpp $(COMP)/topic_hash.cpp $(COMP)/topic_hash.h \
                     $(COMP)/sha256.cpp $(COMP)/sha256.h
	$(CXX) $(CXXFLAGS) $(SAN_FLAGS) -I$(COMP) -o $@ topic_hash_main.cpp $(COMP)/topic_hash.cpp $(COMP)/sha256.cpp

wire_format_test_san: wire_format_main.cpp $(COMP)/wire_format.cpp $(COMP)/wire_format.h
	$(CXX) $(CXXFLAGS) $(SAN_FLAGS) -I$(COMP) -o $@ wire_format_main.cpp $(COMP)/wire_format.cpp

# ReplayGuard is header-only (no .cpp), so the harness pulls in just the header.
replay_guard_test: replay_guard_main.cpp $(COMP)/replay_guard.h
	$(CXX) $(CXXFLAGS) -I$(COMP) -o $@ replay_guard_main.cpp

replay_guard_test_san: replay_guard_main.cpp $(COMP)/replay_guard.h
	$(CXX) $(CXXFLAGS) $(SAN_FLAGS) -I$(COMP) -o $@ replay_guard_main.cpp

clean:
	rm -f topic_hash_test wire_format_test topic_hash_test_san wire_format_test_san \
	      replay_guard_test replay_guard_test_san

# Behaviour test of the real src/ristretto_filter.cpp on Linux (g++), under
# AddressSanitizer and UBSan. Needs the Doppio submodule:
#   git submodule update --init
#   make -C tests
DOPPIO   := ../extern/doppio
# -Wno-unused-function: the shim maps __except(filter) to catch (...), which
# drops the filter expression, so DecisionFilter is unused here (not in MSVC).
CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unknown-pragmas -Wno-unused-function \
            -Ishim -I$(DOPPIO)/tests/native/shim -I$(DOPPIO)/tests/native -I$(DOPPIO) -I.
SANITIZE := -g -fsanitize=address,undefined -fno-sanitize-recover=all

SOURCES  := test_filter.cpp filter_fakes.cpp $(DOPPIO)/tests/native/lsa_fakes.cpp \
            ../src/ristretto_filter.cpp $(DOPPIO)/store_index.cpp
HEADERS  := filter_fakes.h $(wildcard shim/*.h) $(wildcard $(DOPPIO)/tests/native/shim/*.h) \
            $(DOPPIO)/tests/native/lsa_fakes.h $(DOPPIO)/store.h $(DOPPIO)/storekeys.h

.PHONY: test clean
test: test_filter
	./test_filter

test_filter: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SANITIZE) $(SOURCES) -o $@

clean:
	rm -f test_filter

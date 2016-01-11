CPPFLAGS := -isystem/usr/include -isystem/usr/local/include -I"$(CURDIR)/sources" -isystem"$(CURDIR)/cryptopp/include" -D_FILE_OFFSET_BITS=64
CXXFLAGS := -g -march=native -mtune=native -std=c++11 -pipe -Wall -Wextra -pedantic -pthread
LDFLAGS := -L/usr/local/lib -L"$(CURDIR)/cryptopp/lib" -lcryptopp -pthread
ifeq ($(shell uname), Darwin)
	LDFLAGS += -losxfuse
	LDFLAGS += -Wl,-dead_strip
	CPPFLAGS += -isystem/usr/local/include/osxfuse
else
	LDFLAGS += -lfuse
	LDFLAGS += -Wl,--gc-sections
endif

ifndef DEBUG
	CXXFLAGS += -O3 -DNDEBUG
endif

export CXXFLAGS
export NOASM

SOURCES := $(wildcard sources/*.cpp)
OBJECTS := $(SOURCES:.cpp=.o)

TEST_SOURCES := $(wildcard test/*.cpp)
TEST_OBJECTS := $(TEST_SOURCES:.cpp=.o)

.PHONY: all clean cryptopp test deepclean

$(TEST_OBJECTS): $(OBJECTS)

$(OBJECTS): cryptopp

cryptopp:
	$(MAKE) -C cryptopp static
	$(MAKE) -C cryptopp install

securefs: $(OBJECTS) main.o
	$(CXX) $(CXXFLAGS) $(OBJECTS) main.o $(LDFLAGS) -o securefs

securefs_test: $(OBJECTS) $(TEST_OBJECTS)
	$(CXX) $(CXXFLAGS) $(TEST_OBJECTS) $(OBJECTS) $(LDFLAGS) -o securefs_test

test: securefs securefs_test
	./securefs_test && ./test/simple_test.py

clean:
	$(RM) $(OBJECTS) $(TEST_OBJECTS) securefs securefs_test *.o

deepclean: clean
	$(MAKE) -C cryptopp clean

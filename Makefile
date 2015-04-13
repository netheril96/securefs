CPPFLAGS := -I/usr/include -I/usr/local/include -I./sources -I./cryptopp/include -DNDEBUG
CXXFLAGS := -g -O2 -march=native -mtune=native -std=c++0x -pipe
LDFLAGS := -L/usr/local/lib -L./cryptopp/lib -lcryptopp
ifeq ($(shell uname), Darwin)
	LDFLAGS += -losxfuse
else
	LDFLAGS += -lfuse
endif

SOURCES := $(wildcard sources/*.cpp)
OBJECTS := $(SOURCES:.cpp=.o)

TEST_SOURCES := $(wildcard test/*.cpp)
TEST_OBJECTS := $(TEST_SOURCES:.cpp=.o)

.PHONY: all clean cryptopp test deepclean

cryptopp:
	$(MAKE) -C cryptopp static
	$(MAKE) -C cryptopp install

securefs: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) $(LDFLAGS) -o securefs

securefs_test: $(OBJECTS) $(TEST_OBJECTS)
	$(CXX) $(CXXFLAGS) $(TEST_OBJECTS) $(OBJECTS) $(LDFLAGS) -o securefs_test

test: securefs_test
	./securefs_test

clean:
	$(RM) $(OBJECTS) $(TEST_OBJECTS) securefs securefs_test

deepclean: clean
	$(MAKE) -C cryptopp clean

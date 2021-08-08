CXX=g++
LD=g++
LIBS=-llz4 -lc
CXXFLAGS=-std=c++17

blkstuff: main.o util.o
	$(LD) $(LIBS) $^ -o $@

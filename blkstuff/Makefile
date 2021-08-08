CXX=g++
LD=g++
LIBS=-llz4 -lc -lomp
CXXFLAGS=-std=c++17 -fopenmp -Wall -Wextra

blkstuff: main.o util.o
	$(LD) $(LIBS) $^ -o $@

clean:
	-rm main.o util.o blkstuff

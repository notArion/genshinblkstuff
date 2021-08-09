CXX=g++
LD=g++
LIBS=-llz4 -lc -lomp
CXXFLAGS=-O2 -std=c++17 -fopenmp -Wall -Wextra
CFLAGS=-O2 -std=c17 -fopenmp -Wall -Wextra

blkstuff: main.o util.o aes.o
	$(LD) $(LIBS) $^ -o $@

clean:
	-rm main.o util.o blkstuff

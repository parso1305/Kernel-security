.PHONY: all clean

all: loader

loader: loader.c
	gcc -g -O2 -Wall loader.c -o loader -lbpf -lelf -lz

clean:
	rm -f loader

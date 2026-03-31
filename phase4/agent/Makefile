.PHONY: all clean

all: agent

agent: agent.c
	gcc -g -O2 -Wall agent.c -o agent -lbpf -lelf -lz -lcrypto

clean:
	rm -f agent

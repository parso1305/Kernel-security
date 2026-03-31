.PHONY: all clean

all: verifier

verifier: verifier.c
	gcc -g -O2 -Wall verifier.c -o verifier -lcrypto

clean:
	rm -f verifier

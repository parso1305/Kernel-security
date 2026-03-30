.PHONY: all clean bpf user_prog

all: bpf user_prog

bpf:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/phase1.bpf.c -o bpf/phase1.bpf.o

user_prog:
	$(MAKE) -C user

clean:
	rm -f bpf/*.o
	$(MAKE) -C user clean

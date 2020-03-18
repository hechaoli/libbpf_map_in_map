CLANG = clang
TOOLS = $(LINUX)/tools
CFLAGS = -O2 -Wall

main: main.c test_bpf.o
	$(CLANG) $(CFLAGS) -I$(TOOLS)/lib -I$(TOOLS)/include -Wl,--library-path=./,-rpath=./,--library=bpf -o main main.c

test_bpf.o: test_bpf.c
	$(CLANG) $(CFLAGS) -I$(TOOLS)/include/uapi -I$(TOOLS)/testing/selftests/bpf -target bpf -c -o test_bpf.o test_bpf.c

clean:
	rm -f main test_bpf.o

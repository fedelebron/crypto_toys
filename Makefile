CC=clang
CFLAGS=-O0 -fsanitize=address -ggdb

TARGET=chacha20_demo

chacha20.o:    chacha20.c chacha20.h
	$(CC) $(CFLAGS) chacha20.c -c

chacha20_demo.o:  chacha20_demo.c chacha20.h
	$(CC) $(CFLAGS) chacha20_demo.c -c

chacha20_demo:    chacha20_demo.o chacha20.o
	$(CC) $(CFLAGS) chacha20_demo.o chacha20.o -o chacha20_demo

clean:
	rm *.o chacha20_demo

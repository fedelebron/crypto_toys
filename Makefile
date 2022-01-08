CC=clang
CFLAGS=-O0 -fsanitize=address -ggdb

TARGET=chacha20_demo

chacha20.o:    chacha20.c chacha20.h
	$(CC) $(CFLAGS) chacha20.c -c

chacha20_demo.o:  chacha20_demo.c chacha20.h
	$(CC) $(CFLAGS) chacha20_demo.c -c

chacha20_demo:    chacha20_demo.o chacha20.o
	$(CC) $(CFLAGS) chacha20_demo.o chacha20.o -o chacha20_demo

poly1305.o: poly1305.c poly1305.h
	$(CC) $(CFLAGS) poly1305.c -c

poly1305_demo.o: poly1305_demo.c poly1305.h
	$(CC) $(CFLAGS) poly1305_demo.c -c

poly1305_demo: poly1305_demo.o poly1305.o
	$(CC) $(CFLAGS) -lgmp  poly1305_demo.o poly1305.o -o poly1305_demo

aead_chacha20_poly1305.o: aead_chacha20_poly1305.c aead_chacha20_poly1305.h chacha20.h poly1305.h
	$(CC) $(CFLAGS) aead_chacha20_poly1305.c -c

aead_chacha20_poly1305_demo.o: aead_chacha20_poly1305_demo.c aead_chacha20_poly1305.h
	$(CC) $(CFLAGS) aead_chacha20_poly1305_demo.c -c

poly1305_demo: aead_chacha20_poly1305_demo.o aead_chacha20_poly1305.o chacha20.o poly1305.o
	$(CC) $(CFLAGS) -lgmp aead_chacha20_poly1305_demo.o aead_chacha20_poly1305.o chacha20.o poly1305.o -o aead_chacha20_poly1305_demo

clean:
	rm -f *.o chacha20_demo poly1305_demo

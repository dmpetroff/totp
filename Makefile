totp: totp.c
	$(CC) -std=c99 -o $@ -Wall -O2 $< $(shell pkg-config --cflags --libs libcrypto)

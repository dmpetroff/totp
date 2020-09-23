#define _DEFAULT_SOURCE

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <endian.h>

#define TOTP_LEN 8

typedef struct {
	void *data;
	unsigned len;
} blob_t;

static _Bool
base32_decode(const char *msg, unsigned len, blob_t *data)
{
	unsigned bin_len = len * 5 / 8;
	uint8_t *d;
	uint8_t bst = 0;

	data->data = malloc(bin_len);
	d = data->data;
	*d = 0;
	data->len = bin_len;
	for (const char *p = msg, *e = msg + len; p < e; p++) {
		uint8_t digit;
		if (*p >= 'a' && *p <= 'z')
			digit = *p - 'a';
		else if (*p >= 'A' && *p <= 'Z')
			digit = *p - 'A';
		else if (*p >= '2' && *p <= '7')
			digit = *p - '2' + 26;
		else
			return false;

		uint8_t bavail = 8 - bst;
		switch (bavail) {
		/* set */
		case 8:
			*d = digit << 3;
			break;
		/* merge */
		case 7: case 6:
			*d |= digit << (bavail - 5);
			break;
		/* exact fit */
		case 5:
			*d |= digit;
			d++;
			break;
		/* split */
		case 4: case 3: case 2: case 1:
			d[0] |= digit >> (5 - bavail);
			d[1] = digit << (bavail + 3);
			d++;
		}
		bst = (bst + 5) % 8;
	}

	return true;
}


static const char*
get_key(const char *qr_text)
{
	static const char secret_str[] = "secret=";
	static char result[TOTP_LEN];

	const char *begin, *end;
	uint64_t tstamp;
	blob_t key;
	unsigned char digest[20];
	unsigned dlen;
	uint32_t otp;

	begin = strstr(qr_text, secret_str);
	if (begin == NULL)
		return "malformed TOTP uri: missing secret";

	begin += sizeof(secret_str) - 1;
	end = strchr(begin, '&');
	if (end == NULL) {
		for (end = begin; *end && !isspace(*end); end++)
			/* void */;
	}

	switch (end - begin) {
	case 16: case 26: case 32:
		break;
	default:
		return "malformed TOTP uri: secret length MUST be exactly 16, 26 or 32 characters";
	}

	if (!base32_decode(begin, end - begin, &key))
		return "secret is not valid base32 sequence";

	// TOTP tstamp
	tstamp = htobe64(time(NULL) / 30);

	HMAC(EVP_sha1(), key.data, key.len, (void*)&tstamp, sizeof(tstamp), digest, &dlen);
	free(key.data);

	// TOTP code
	otp = be32toh(*(uint32_t*)(digest + (digest[19] & 0xf))) & 0x7fffffff;

	snprintf(result, sizeof(result), "%06" PRIu32, otp % 1000000);

	return result;
}

int main(int argc, char **argv)
{
	char line[4096];
	snprintf(line, sizeof(line), "%s/.totp.csv", getenv("HOME"));
	
	FILE *in = fopen(line, "r");
	if (in == NULL) {
		fprintf(stderr, "Can't open %s: %s\n", line, strerror(errno));
		return 1;
	}

	while (fgets(line, sizeof(line), in)) {
		char *tab = strchr(line, '\t');
		if (!tab)
			continue;
		*tab = 0;
		if (argc == 2) {
			if (strcmp(line, argv[1]) == 0) {
				puts(get_key(tab + 1));
				break;
			}
		} else {
			printf("%-8s -> %s\n", line, get_key(tab + 1));
		}
	}

	fclose(in);
	return 0;
}

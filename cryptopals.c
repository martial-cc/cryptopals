/*
MIT/X Consortium License

© 2021-2022 Carl H. Henriksson <cryptopals at martial dot cc>

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BS 1024

#define B64_LIM 64
#define B64_N 4
#define B64_WIDTH 6
#define BYTE_N 3
#define BYTE_WIDTH 8
#define NBYTE_SIZE BS

#define B64(i) (b64[B64_LIM - 1 & i])

enum nbyte_fmt {
	FMT_ASC,
	FMT_B64,
	FMT_HEX,
};

typedef struct {
	size_t n;
	int data[NBYTE_SIZE];
} Nbyte;

int bitmask(char *, size_t, long, size_t);
int read_hex(int *, unsigned char);
int write_hex(unsigned char *, int);

int nbyte_init(Nbyte *);
int nbyte_decode(Nbyte *, const unsigned char *, enum nbyte_fmt);
int nbyte_encode(unsigned char *, size_t, const Nbyte *, enum nbyte_fmt);

int nbyte_freq(size_t *, Nbyte *);
int nbyte_xor(Nbyte *, Nbyte *, Nbyte *);
int nbyte_xorc(Nbyte *, Nbyte *, char);
int nbyte_xorkey(Nbyte *, Nbyte *, const unsigned char *);
int nbyte_xorscore(size_t *, size_t *, Nbyte *);

int asc_decode(Nbyte *, const unsigned char *);
int asc_encode(unsigned char *, size_t, const Nbyte *);
int b64_encode(unsigned char *, size_t, const Nbyte *);
int hex_decode(Nbyte *, const unsigned char *);
int hex_encode(unsigned char *, size_t, const Nbyte *);

static const unsigned char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static const unsigned char english[] = "etainoshrdlucmfwygpbvkqjxz";

int bitmask(char *dst, size_t dst_lim, long x, size_t bit_n) {
/* Used to determine bitmasks in b64_encode */
	const int bit_max = 32;
	int bit;
	size_t i;

	if (NULL == dst)
		return 1;
	if (bit_max >= dst_lim)
		return 2;
	if (bit_n > bit_max)
		return 3;

	for (i = 0; i < bit_n; i++) {
		bit = x & 1 << (bit_n - 1 - i);
		dst[i] = !!bit + '0';
	}
	dst[i] = '\0';

	return 0;
}

int read_hex(int *dst, unsigned char src) {
	int ret, tmp;

	if (NULL == dst)
		return 1;

	tmp = (int) src;
	if ('A' <= tmp && 'F' >= tmp)
		ret = tmp - 'A' + 10;
	else if ('a' <= tmp && 'f' >= tmp)
		ret = tmp - 'a' + 10;
	else if ('0' <= tmp && '9' >= tmp)
		ret = tmp - '0';
	else
		return 2;

	*dst = ret;

	return 0;
}

int write_hex(unsigned char *dst, int src) {
	if (NULL == dst)
		return 1;
	if (0x10 <= src || 0 > src)
		return 2;

	if (0 > sprintf((char *)dst, "%x", src))
		return 3;

	return 0;
}

int nbyte_init(Nbyte *dst) {
	if (NULL == dst)
		return 1;

	dst->n = 0;
	for (size_t i = 0; i < NBYTE_SIZE; i++)
		dst->data[i] = 0;

	return 0;
}

int nbyte_decode(Nbyte *dst, const unsigned char *src, enum nbyte_fmt fmt) {
	int (*fp)(Nbyte *, const unsigned char *);

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;
	if (FMT_B64 == fmt)	/* remove this test when implemented */
		return 3;

	(void) nbyte_init(dst);

	switch (fmt) {
	case FMT_ASC:
		fp = asc_decode;
		break;
	case FMT_B64:
		fp = NULL;
		break;
	case FMT_HEX:
		fp = hex_decode;
		break;
	default:
		return 4;
		break;
	}

	if (0 != fp(dst, src))
		return 5;

	return 0;
}

int nbyte_encode(unsigned char *dst, size_t dst_lim, const Nbyte *src, enum nbyte_fmt fmt) {
	int (*fp)(unsigned char *, size_t, const Nbyte *);

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;

	switch (fmt) {
	case FMT_ASC:
		fp = asc_encode;
		break;
	case FMT_B64:
		fp = b64_encode;
		break;
	case FMT_HEX:
		fp = hex_encode;
		break;
	default:
		return 3;
		break;
	}

	if (0 != fp(dst, dst_lim, src))
		return 4;

	return 0;
}

int nbyte_freq(size_t *dst, Nbyte *x) {
	size_t score;
	size_t i, j, n;

	if (NULL == dst)
		return 1;
	if (NULL == x)
		return 2;

	n = strlen((char *)english);
	score = 0;
	for (i = 0; i < x->n; i++)
		for (j = 0; j < n; j++)
			if (english[j] == x->data[i])
				score++;

	*dst = score;

	return 0;
}

int nbyte_xor(Nbyte *dst, Nbyte *x, Nbyte *y) {
/* Target will be as long as the shortest source */
	size_t i;

	if (NULL == dst)
		return 1;
	if (NULL == x)
		return 2;
	if (NULL == y)
		return 3;

	(void) nbyte_init(dst);

	dst->n = x->n < y->n ? x->n : y->n;
	for (i = 0; i < dst->n; i++)
		dst->data[i] = x->data[i] ^ y->data[i];

	return 0;
}

int nbyte_xorc(Nbyte *dst, Nbyte *x, char c) {
	size_t i;

	if (NULL == dst)
		return 1;
	if (NULL == x)
		return 2;

	(void) nbyte_init(dst);

	dst->n = x->n;
	for (i = 0; i < x->n; i++)
		dst->data[i] = c ^ x->data[i];

	return 0;
}

int nbyte_xorkey(Nbyte *dst, Nbyte *x, const unsigned char *key) {
	size_t i, kn;

	if (NULL == dst)
		return 1;
	if (NULL == x)
		return 2;
	if (NULL == key)
		return 3;

	dst->n = x->n;
	kn = strlen((char *)key);
	for (i = 0; i < x->n; i++)
		dst->data[i] = key[i % kn] ^ x->data[i];

	return 0;
}

int nbyte_xorscore(size_t *score, size_t *topc, Nbyte *src) {
	Nbyte dt;
	size_t top, tscore, ttopc;
	size_t i;

	if (NULL == score)
		return 1;
	if (NULL == topc)
		return 2;
	if (NULL == src)
		return 3;

	top = tscore = ttopc = 0;
	for (i = 0; i < 0x100; i++) {
		if (0 == isprint(i))
			continue;
		if (0 != nbyte_xorc(&dt, src, i))
			return 4;
		if (0 != nbyte_freq(&tscore, &dt))
			return 5;
		if (top < tscore) {
			top = tscore;
			ttopc = i;
		}
	}

	*score = top;
	*topc = ttopc;

	return 0;
}

int asc_decode(Nbyte *dst, const unsigned char *src) {
	size_t i, n;

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;

	n = strlen((char *)src);
	if (NBYTE_SIZE < n)
		return 3;

	dst->n = n;
	for (i = 0; i < n; i++)
		dst->data[i] = src[i];

	return 0;
}

int asc_encode(unsigned char *dst, size_t dst_lim, const Nbyte *src) {
	size_t i;

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;
	if (src->n >= dst_lim)
		return 3;

	for (i = 0; i < src->n; i++)
		dst[i] = src->data[i];
	dst[i] = '\0';

	return 0;
}

int b64_encode(unsigned char *dst, size_t dst_lim, const Nbyte *src) {
/* Padding is not implemented, since the challenge doesn't require it */
	const long mask[] = { 0x00fc0000, 0x0003f000, 0x00000fc0, 0x0000003f };
	long buf;
	size_t dst_i, i, j;

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;
	if (src->n * 4 / 3 + 1 > dst_lim)	/* lazy */
		return 3;

	buf = 0;
	dst_i = 0;
	for (i = j = 0; i < src->n; i++) {
		buf += src->data[i] << BYTE_WIDTH * (BYTE_N - 1 - j);
		if (BYTE_N == ++j) {
			for (j = 0; j < B64_N; j++)
				dst[dst_i++] = B64((buf & mask[j]) >> B64_WIDTH * (B64_N - 1 - j));
			buf = j = 0;
		}
	}
	dst[dst_i] = '\0';

	return 0;
}

int hex_decode(Nbyte *dst, const unsigned char *src) {
	const unsigned char *cp;
	int high, low;
	size_t i, n;

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;

	n = strlen((char *)src);
	if (2 > n || 0 != n % 2)
		return 3;
	if (NBYTE_SIZE < n)
		return 4;

	dst->n = n / 2;
	for (cp = src, i = 0; *cp != '\0'; ) {
		if (0 != read_hex(&high, *cp++)
		|| 0 != read_hex(&low, *cp++))
			return 5;
		dst->data[i++] = 0x10 * high + low;
	}

	return 0;
}

int hex_encode(unsigned char *dst, size_t dst_lim, const Nbyte *src) {
	unsigned char *cp;
	int i;

	if (NULL == dst)
		return 1;
	if (NULL == src)
		return 2;
	if (src->n * 2 + 1 >= dst_lim)
		return 3;

	for (cp = dst, i = 0; i < src->n; i++)
		if (0 != write_hex(cp++, src->data[i] / 0x10)
		|| 0 != write_hex(cp++, src->data[i] % 0x10))
			return 4;
	*cp = '\0';

	return 0;
}

/*
	Crypto Challenge Set 1

	1. Convert hex to base64
	2. Fixed XOR
	3. Single-byte XOR cipher
	4. Detect single-character XOR
	5. Implement repeating-key XOR
	6. Break repeating-key XOR
	7. AES in ECB mode
	8. Detect AES in ECB mode

	https://cryptopals.com/sets/1
*/

/*
	1. Convert hex to base64

	The string:
	49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

	Should produce:
	SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

	So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

	Cryptopals Rule
	Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
*/
void c_1(void) {
	const unsigned char hex[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	const unsigned char target[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	unsigned char b[BS], h[BS];
	Nbyte dt;

	assert(0 == nbyte_decode(&dt, hex, FMT_HEX));

	assert(0 == nbyte_encode(b, BS, &dt, FMT_B64));
	assert(0 == nbyte_encode(h, BS, &dt, FMT_HEX));

	assert(0 == strcmp((char *)hex, (char *)h));
	assert(0 == strcmp((char *)target, (char *)b));
}

/*
	2. Fixed XOR

	Write a function that takes two equal-length buffers and produces their XOR
	combination.

	If your function works properly, then when you feed it the string:

		1c0111001f010100061a024b53535009181c

	... after hex decoding, and when XOR'd against:

		686974207468652062756c6c277320657965

	... should produce:

		746865206b696420646f6e277420706c6179
*/
void c_2(void) {
	const unsigned char x[] = "1c0111001f010100061a024b53535009181c";
	const unsigned char y[] = "686974207468652062756c6c277320657965";
	const unsigned char target[] = "746865206b696420646f6e277420706c6179";
	unsigned char h[BS];
	Nbyte dt, dx, dy;

	assert(0 == nbyte_decode(&dx, x, FMT_HEX));
	assert(0 == nbyte_decode(&dy, y, FMT_HEX));

	assert(0 == nbyte_xor(&dt, &dx, &dy));

	assert(0 == nbyte_encode(h, BS, &dt, FMT_HEX));
	assert(0 == strcmp((char *)target, (char *)h));
}

/*
	3. Single-byte XOR cipher

	The hex encoded string:

		1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

	... has been XOR'd against a single character. Find the key, decrypt the
	message.

	You can do this by hand. But don't: write code to do it for you.

	How? Devise some method for "scoring" a piece of English plaintext. Character
	frequency is a good metric. Evaluate each output and choose the one with the
	best score.
*/
void c_3(void) {
	const unsigned char x[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	const unsigned char target[] = "Cooking MC's like a pound of bacon";
	unsigned char h[BS];
	Nbyte dt, dx;
	size_t c, score;

	assert(0 == nbyte_decode(&dx, x, FMT_HEX));

	assert(0 == nbyte_xorscore(&score, &c, &dx));
	assert(0 == nbyte_xorc(&dt, &dx, c));

	assert(0 == nbyte_encode(h, BS, &dt, FMT_ASC));
	assert(0 == strcmp((char *)target, (char *)h));
}

/*
	4. Detect single-character XOR

	One of the 60-character strings in this file [1_4.txt] has been encrypted by
	single-character XOR.

	Find it.
*/
void c_4(void) {
	const char fn[] = "1_4.txt";
	const char target[] = "Now that the party is jumping\n";
	char line[BS];
	Nbyte x, y;
	char *cp;
	FILE *fp;
	size_t c, score, top, topc;
	size_t i;

	fp = fopen(fn, "r");
	if (NULL == fp) {
		fprintf(stderr, "can't open file from working directory: %s\n", fn);
		exit(1);
	}

	score = top = topc = 0;
	for (i = 0; NULL != fgets(line, sizeof(line), fp); i++) {
		cp = strchr(line, '\n');
		if (NULL != cp)
			*cp = '\0';
		assert(0 == nbyte_decode(&x, (const unsigned char *)line, FMT_HEX));
		assert(0 == nbyte_xorscore(&score, &c, &x));
		if (top < score) {
			assert(0 == nbyte_decode(&y, (const unsigned char *)line, FMT_HEX));
			top = score;
			topc = c;
		}
	}
	assert(0 == nbyte_xorc(&x, &y, topc));

	assert(0 == nbyte_encode((unsigned char *)line, BS, &x, FMT_ASC));
	assert(0 == strcmp((char *)target, (char *)line));
}

/*
	5. Implement repeating-key XOR

	Here is the opening stanza of an important work of the English language:

		Burning 'em, if you ain't quick and nimble
		I go crazy when I hear a cymbal

	Encrypt it, under the key "ICE", using repeating-key XOR.

	In repeating-key XOR, you'll sequentially apply each byte of the key; the first
	byte of plaintext will be XOR'd against I, the next C, the next E, then I again
	for the 4th byte, and so on.

	It should come out to:

		0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
		a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
*/
void c_5(void) {
	const unsigned char x[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	const unsigned char k[] = "ICE";
	const unsigned char target[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276\
5272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
	unsigned char h[BS];
	Nbyte dt, dx;

	assert(0 == nbyte_decode(&dx, x, FMT_ASC));

	assert(0 == nbyte_xorkey(&dt, &dx, k));

	assert(0 == nbyte_encode(h, BS, &dt, FMT_HEX));
	assert(0 == strcmp((char *)target, (char *)h));
}

int main(void) {
	c_1();
	c_2();
	c_3();
	c_4();
	c_5();

	(void) printf("Success\n");

	return 0;
}

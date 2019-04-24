#include <stdint.h>
#include <string.h>

#include "pbkdf2-hmac-sha256.h"

static uint32_t ror(uint32_t n, uint32_t k)
{
	return (n >> k) | (n << (32 - k));
}


//#define ror(n,k) ((n >> k) | (n << (32 - k)))


#define Ch(x,y,z)  (z ^ (x & (y ^ z)))
#define Maj(x,y,z) ((x & y) | (z & (x | y)))
#define S0(x)      (ror(x,2) ^ ror(x,13) ^ ror(x,22))
#define S1(x)      (ror(x,6) ^ ror(x,11) ^ ror(x,25))
#define R0(x)      (ror(x,7) ^ ror(x,18) ^ (x>>3))
#define R1(x)      (ror(x,17) ^ ror(x,19) ^ (x>>10))

static const uint32_t K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define INNER_PAD '\x36'
#define OUTER_PAD '\x5c'

void hmac_sha256_init(HMAC_SHA256_CTX *hmac, const uint8_t *key, uint32_t keylen)
{
	if (keylen <= SHA256_BLOCKLEN)
	{
		memcpy(hmac->sha.buf, key, keylen);
		memset(hmac->sha.buf + keylen, '\0', SHA256_BLOCKLEN - keylen);
	}
	else
	{
		sha256_init(&hmac->sha);
		sha256_update(&hmac->sha, key, keylen);
		sha256_final(&hmac->sha, hmac->sha.buf);
		memset(hmac->sha.buf + SHA256_DIGESTLEN, '\0', SHA256_BLOCKLEN - SHA256_DIGESTLEN);
	}

	// This relies on the fact that:
	// 1. sha256_init keeps sha.buf untouched
	// 2. sha256_update keeps sha.buf untouched if message length is SHA256_BLOCKLEN
	uint32_t i;
	for (i = 0; i < SHA256_BLOCKLEN; i++)
	{
		hmac->sha.buf[i] = hmac->sha.buf[i] ^ OUTER_PAD;
	}

	sha256_init(&hmac->sha);
	sha256_update(&hmac->sha, hmac->sha.buf, SHA256_BLOCKLEN);
	memcpy(hmac->h_outer, hmac->sha.h, SHA256_DIGESTLEN);

	//uint32_t i;
	for (i = 0; i < SHA256_BLOCKLEN; i++)
	{
		hmac->sha.buf[i] = (hmac->sha.buf[i] ^ OUTER_PAD) ^ INNER_PAD;
	}

	sha256_init(&hmac->sha);
	sha256_update(&hmac->sha, hmac->sha.buf, SHA256_BLOCKLEN);
	memcpy(hmac->h_inner, hmac->sha.h, SHA256_DIGESTLEN);
}

void hmac_sha256_update(HMAC_SHA256_CTX *hmac, const uint8_t *m, uint32_t mlen)
{
	sha256_update(&hmac->sha, m, mlen);
}

void hmac_sha256_final(HMAC_SHA256_CTX *hmac, uint8_t *md)
{
	sha256_final(&hmac->sha, md);

	hmac->sha.len = SHA256_BLOCKLEN;
	memcpy(hmac->sha.h, hmac->h_outer, SHA256_DIGESTLEN);

	sha256_update(&hmac->sha, md, SHA256_DIGESTLEN);
	sha256_final(&hmac->sha, md);

	// reset sha back to initial state
	hmac->sha.len = SHA256_BLOCKLEN;
	memcpy(hmac->sha.h, hmac->h_inner, SHA256_DIGESTLEN);
}

void pbkdf2_sha256(const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen,
	uint32_t rounds, uint8_t *dk, uint32_t dklen)
{
	uint8_t *T = dk;
	uint8_t U[SHA256_DIGESTLEN];
	uint8_t count[4];

	uint32_t hlen = SHA256_DIGESTLEN;
	uint32_t l = dklen / hlen + ((dklen % hlen) ? 1 : 0);
	uint32_t r = dklen - (l - 1) * hlen;

	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, keylen);

	uint32_t i, j, k;
	uint32_t len = hlen;
	for (i = 1; i <= l; i++)
	{
		if (i == l)
		{
			len = r;
		}
		count[0] = (i >> 24) & 0xFF;
		count[1] = (i >> 16) & 0xFF;
		count[2] = (i >> 8) & 0xFF;
		count[3] = (i) & 0xFF;
		hmac_sha256_update(&hmac, salt, saltlen);
		hmac_sha256_update(&hmac, count, 4);
		hmac_sha256_final(&hmac, U);
		memcpy(T, U, len);
		for (j = 1; j < rounds; j++)
		{
			hmac_sha256_update(&hmac, U, hlen);
			hmac_sha256_final(&hmac, U);
			for (k = 0; k < len; k++)
			{
				T[k] ^= U[k];
			}
		}
		T += len;
	}

}
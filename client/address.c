/* addresses, T13.692-T13.720 $DVS:time$ */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "address.h"
#include "../dus/programs/dfstools/source/include/dfsrsa.h"
#ifdef _XDAG_ADDRESS_
static const uint8_t bits2mime[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8_t mime2bits[256];
#else
static const uint8_t bits2mime58[58+1] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static uint8_t mime2bits58[256];
#endif

#ifndef _XDAG_ADDRESS_
// intializes the address module
int ndag_address_init(void)
{
	int i;

	memset(mime2bits58, 0xFF, 256);

	for (i = 0; i < 58; ++i) {
		mime2bits58[bits2mime58[i]] = i;
	}

	return 0;
}

// converts address to hash
int ndag_address2hash(const char *address, xdag_hash_t hash)
{
	preaddr2hash(address,hash);
	uint8_t *hashp, *rp = (uint8_t*)hash;
	uint8_t tmp[sizeof(xdag_hashlow_t)+1] = { 0 };
	// Skip leading spaces.
	while (*address && IsSpace(*address))
		address++;
	// Skip and count leading '1's.
	int zeroes = 0;
	int length = 0;
	while (*address == '1') {
		zeroes++;
		address++;
	}
	// Allocate enough space in big-endian base256 representation.
	int size = strlen(address) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
	// Process the characters.

	while (*address && !IsSpace(*address)) {
		// Decode base58 character
		int carry = mime2bits58[(uint8_t)*address];
		if (carry == -1)  // Invalid b58 character
			return -1;
		int i = 0;
		for (hashp = tmp + size - 1; (carry != 0 || i < length) && (hashp >= tmp); --hashp, ++i) {
			carry += 58 * (*hashp);
			*hashp = carry % 256;
			carry /= 256;
		}
		//assert(carry == 0);
		length = i;
		address++;
	}
	// Skip trailing spaces.
	while (IsSpace(*address))
		address++;
	if (*address != 0)
		return -1;
	// Skip leading zeroes in b256.
	hashp = (uint8_t*)tmp + (size - length);
	while (hashp != tmp + size && *hashp == 0)
		hashp++;
	// Copy result into output vector.
	memset(hash, 0, sizeof(xdag_hash_t));
	while (hashp != tmp + size)
		*rp++ = *(hashp++);
	return 0;
}

// converts hash to address
void ndag_hash2address(const xdag_hash_t hash, char *address)
{
	char *test = address;
	prehash2addr(hash,address);

	unsigned char *pbegin = (unsigned char*)hash;
	unsigned char *pcurr, *pend = (unsigned char*)hash + sizeof(xdag_hashlow_t);
	// Skip & count leading zeroes.
	int size , zeroes = 0;
	int length = 0;
	while (pbegin != pend && *pbegin == 0) {
		pbegin++;
		zeroes++;
	}

	if (zeroes== sizeof(xdag_hashlow_t)) {
		memset(address, 'A', 33);
		return;
	}
	// Allocate enough space in big-endian base58 representation.
	size = zeroes + (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
	unsigned char *pbuf = (unsigned char*)malloc(size+1);
	memset(pbuf, 0, size+1);

	// Process the bytes.
	while (pbegin != pend) {
		int carry = *pbegin;
		int i = 0;
		// Apply "b58 = b58 * 256 + ch".
		for (pcurr = pbuf + size - 1; (carry != 0 || i < length) && (pcurr >= pbuf); pcurr--, i++) {
			carry += 256 * (*pcurr);
			*pcurr = carry % 58;
			carry /= 58;
		}

		length = i;
		pbegin++;
	}
	// Skip leading zeroes in base58 result.
	pcurr = pbuf + (size - length);
	while (pcurr != pbuf + size && *pcurr == 0)
		pcurr++;
	// Translate the result into a string.
	zeroes = zeroes + size - length - 1;
	memset(address, '1', zeroes);
	while (pcurr != pbuf + size)
		*(address+++zeroes) = bits2mime58[*(pcurr++)];

	free(pbuf);
}

#else

// intializes the address module
int xdag_address_init(void)
{
	int i;

	memset(mime2bits, 0xFF, 256);

	for (i = 0; i < 64; ++i) {
		mime2bits[bits2mime[i]] = i;
	}

	return 0;
}

// converts address to hash
int xdag_address2hash(const char *address, xdag_hash_t hash)
{
	uint8_t *fld = (uint8_t*)hash;
	int i, c, d, n;

	for (int e = n = i = 0; i < 32; ++i) {
		do {
			if (!(c = (uint8_t)*address++))
				return -1;
			d = mime2bits[c];
		} while (d & 0xC0);
		e <<= 6;
		e |= d;
		n += 6;

		if (n >= 8) {
			n -= 8;
			*fld++ = e >> n;
		}
	}

	for (i = 0; i < 8; ++i) {
		*fld++ = 0;
	}

	return 0;
}

// converts hash to address
void xdag_hash2address(const xdag_hash_t hash, char *address)
{
	int c, d;
	const uint8_t *fld = (const uint8_t*)hash;

	for (int i = c = d = 0; i < 32; ++i) {
		if (d < 6) {
			d += 8;
			c <<= 8;
			c |= *fld++;
		}
		d -= 6;
		*address++ = bits2mime[c >> d & 0x3F];
	}
	*address = 0;
}
#endif
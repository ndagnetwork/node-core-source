/* addresses, T13.692-T13.692 $DVS:time$ */

#ifndef XDAG_ADDRESS_H
#define XDAG_ADDRESS_H

#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _XDAG_ADDRESS_

#define SIZE_MAX_ADDRESS 33
#define prehash2addr_addr(a) (a)
#define preaddr2hash_addr(a) (a)
	/* intializes the addresses module */
	extern int xdag_address_init(void);
	/* converts address to hash */
	extern int xdag_address2hash(const char *address, xdag_hash_t hash);
	/* converts hash to address */
	extern void xdag_hash2address(const xdag_hash_t hash, char *address);

#else

#define SIZE_MAX_ADDRESS 34
#define prehash2addr(h,a) ( memset( a, 0, SIZE_MAX_ADDRESS ) )
#define preaddr2hash(a,h) ( memset( h, 0, sizeof(xdag_hash_t)) )

#define xdag_address_init ndag_address_init
#define xdag_address2hash ndag_address2hash
#define xdag_hash2address ndag_hash2address
#define IsSpace(c) ((c) == ' ' || (c) == '\f' || (c) == '\n' || (c) == '\r' || (c) == '\t' || (c) == '\v')
	/* intializes the addresses module */
	extern int ndag_address_init(void);

	/* converts address to hash */
	extern int ndag_address2hash(const char *address, xdag_hash_t hash);

	/* converts hash to address */
	extern void ndag_hash2address(const xdag_hash_t hash, char *address);

#endif

#ifdef __cplusplus
};
#endif

#endif

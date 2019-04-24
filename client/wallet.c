/* кошелёк, T13.681-T13.788 $DVS:time$ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "crypt.h"
#include "wallet.h"
#include "init.h"
#include "transport.h"
#include "utils/log.h"
#include "utils/utils.h"

#define WALLET_FILE (g_xdag_testnet ? "wallet-testnet.dat" : "wallet.dat")

struct key_internal {
	xdag_hash_t pub, priv;
	void *key;
	struct key_internal *prev;
	uint8_t pub_bit;
};

static struct key_internal *def_key = 0;
static struct xdag_public_key *keys_array = 0;
static pthread_mutex_t wallet_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_nkeys = 0, g_maxnkeys = 0;

static int add_key(xdag_hash_t priv)
{
	struct key_internal *k = malloc(sizeof(struct key_internal));

	if (!k) return -1;

	pthread_mutex_lock(&wallet_mutex);

	if (priv) {
		memcpy(k->priv, priv, sizeof(xdag_hash_t));
		k->key = xdag_private_to_key(k->priv, k->pub, &k->pub_bit);
	} else {
		FILE *f;
		uint32_t priv32[sizeof(xdag_hash_t) / sizeof(uint32_t)];

		k->key = xdag_create_key(k->priv, k->pub, &k->pub_bit);
		
		f = xdag_open_file(WALLET_FILE, "ab");
		if (!f) goto fail;
		
		memcpy(priv32, k->priv, sizeof(xdag_hash_t));
		
		xdag_user_crypt_action(priv32, g_nkeys, sizeof(xdag_hash_t) / sizeof(uint32_t), 1);
		
		if (fwrite(priv32, sizeof(xdag_hash_t), 1, f) != 1) {
			xdag_close_file(f);
			goto fail;
		}

		xdag_close_file(f);
	}

	if (!k->key) goto fail;
	
	k->prev = def_key;
	def_key = k;
	
	if (g_nkeys == g_maxnkeys) {
		struct xdag_public_key *newarr = (struct xdag_public_key *)
			realloc(keys_array, ((g_maxnkeys | 0xff) + 1) * sizeof(struct xdag_public_key));
		if (!newarr) goto fail;
		
		g_maxnkeys |= 0xff;
		g_maxnkeys++;
		keys_array = newarr;
	}

	keys_array[g_nkeys].key = k->key;
	keys_array[g_nkeys].pub = (uint64_t*)((uintptr_t)&k->pub | k->pub_bit);

	xdag_debug("Key %2d: priv=[%s] pub=[%02x:%s]", g_nkeys,
					xdag_log_hash(k->priv), 0x02 + k->pub_bit,  xdag_log_hash(k->pub));
	
	g_nkeys++;
	
	pthread_mutex_unlock(&wallet_mutex);
	
	return 0;
 
fail:
	pthread_mutex_unlock(&wallet_mutex);
	free(k);
	return -1;
}

/* generates a new key and sets is as defauld, returns its index */
int xdag_wallet_new_key(void)
{
	int res = add_key(0);

	if (!res)
		res = g_nkeys - 1;

	return res;
}

/* initializes a wallet */
int xdag_wallet_init(void)
{
	uint32_t priv32[sizeof(xdag_hash_t) / sizeof(uint32_t)];
	xdag_hash_t priv;
	FILE *f = xdag_open_file(WALLET_FILE, "rb");
	int n;

	if (!f) {
		if (add_key(0)) return -1;
		
		f = xdag_open_file(WALLET_FILE, "r");
		if (!f) return -1;
		
		fread(priv32, sizeof(xdag_hash_t), 1, f);
		
		n = 1;
	} else {
		n = 0;
	}

	while (fread(priv32, sizeof(xdag_hash_t), 1, f) == 1) {
		xdag_user_crypt_action(priv32, n++, sizeof(xdag_hash_t) / sizeof(uint32_t), 2);
		memcpy(priv, priv32, sizeof(xdag_hash_t));
		add_key(priv);
	}

	xdag_close_file(f);
	
	return 0;
}

/* returns a default key, the index of the default key is written to *n_key */
struct xdag_public_key *xdag_wallet_default_key(int *n_key)
{
	if (g_nkeys) {
		if (n_key) {
			*n_key = g_nkeys - 1;
			return keys_array + g_nkeys - 1;
		}
	}

	return 0;
}

/* returns an array of our keys */
struct xdag_public_key *xdag_wallet_our_keys(int *pnkeys)
{
	*pnkeys = g_nkeys;

	return keys_array;
}

/* completes work with wallet */
void xdag_wallet_finish(void)
{
	pthread_mutex_lock(&wallet_mutex);
}

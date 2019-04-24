/* hash-function, T13.654-T13.864 $DVS:time$ */

#include <string.h>
#undef SHA256_OPENSSL_MBLOCK
#ifdef SHA256_OPENSSL_MBLOCK
#include <arpa/inet.h>
#endif
#include "sha256.h"
#include "hash.h"
#include "system.h"
#include "algo/sph_blake.h"
#include "algo/sph_bmw.h"
#include "algo/sph_cubehash.h"
#include "algo/sph_echo.h"
#include "algo/sph_fugue.h"
#include "algo/sph_groestl.h"
#include "algo/sph_hamsi.h"
#include "algo/sph_haval.h"
#include "algo/sph_jh.h"
#include "algo/sph_keccak.h"
#include "algo/sph_luffa.h"
#include "algo/sph_sha2.h"
#include "algo/sph_shabal.h"
#include "algo/sph_shavite.h"
#include "algo/sph_simd.h"
#include "algo/sph_skein.h"


#define _ndagHASH_
#ifdef _ndagHASH_
#define _ALIGN(a) __declspec(align(a))
// §¬§à§ß§Ü§â§Ö§ä§ß§Ñ§ñ §â§Ö§Ñ§Ý§Ú§Ù§Ñ§è§Ú§ñ §æ§å§ß§Ü§è§Ú§Ú ndag_hash
void xdag_hash(void *data, size_t size, xdag_hash_t hash)
{
	SHA256REF_CTX ctx;
	sph_blake512_context      ctx_blake;
	sph_bmw512_context        ctx_bmw;
	sph_groestl512_context    ctx_groestl;
	sph_jh512_context         ctx_jh;
	sph_keccak512_context     ctx_keccak;
	sph_skein512_context      ctx_skein;
	sph_luffa512_context      ctx_luffa;
	sph_cubehash512_context   ctx_cubehash;
	sph_shavite512_context    ctx_shavite;
	sph_simd512_context       ctx_simd;
	sph_echo512_context       ctx_echo;
	sph_hamsi512_context      ctx_hamsi;
	sph_fugue512_context      ctx_fugue;
	sph_shabal512_context     ctx_shabal;
	sph_haval256_5_context    ctx_haval;

	unsigned char tmphash[128] = { 0 };
	//X0
	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)data, size);
	sha256_final(&ctx, (uint8_t*)tmphash);

	for (int n = 0; n < 2; ++n)
	{
		//X1
		sph_blake512_init(&ctx_blake);
		sph_blake512(&ctx_blake, tmphash, 64);
		sph_blake512_close(&ctx_blake, tmphash);

		//X2
		sph_bmw512_init(&ctx_bmw);
		sph_bmw512(&ctx_bmw, tmphash, 64);
		sph_bmw512_close(&ctx_bmw, tmphash);

		//X3
		sph_groestl512_init(&ctx_groestl);
		sph_groestl512(&ctx_groestl, tmphash, 64);
		sph_groestl512_close(&ctx_groestl, tmphash);

		//X4
		sph_skein512_init(&ctx_skein);
		sph_skein512(&ctx_skein, tmphash, 64);
		sph_skein512_close(&ctx_skein, tmphash);

		//X5
		sph_jh512_init(&ctx_jh);
		sph_jh512(&ctx_jh, tmphash, 64);
		sph_jh512_close(&ctx_jh, tmphash);

		//X6
		sph_keccak512_init(&ctx_keccak);
		sph_keccak512(&ctx_keccak, tmphash, 64);
		sph_keccak512_close(&ctx_keccak, tmphash);

		//X7
		sph_luffa512_init(&ctx_luffa);
		sph_luffa512(&ctx_luffa, tmphash, 64);
		sph_luffa512_close(&ctx_luffa, tmphash);

		//X8
		sph_cubehash512_init(&ctx_cubehash);
		sph_cubehash512(&ctx_cubehash, tmphash, 64);
		sph_cubehash512_close(&ctx_cubehash, tmphash);

		//X9
		sph_shavite512_init(&ctx_shavite);
		sph_shavite512(&ctx_shavite, tmphash, 64);
		sph_shavite512_close(&ctx_shavite, tmphash);

		//X10
		sph_simd512_init(&ctx_simd);
		sph_simd512(&ctx_simd, tmphash, 64);
		sph_simd512_close(&ctx_simd, tmphash);

		//X11
		sph_hamsi512_init(&ctx_hamsi);
		sph_hamsi512(&ctx_hamsi, tmphash, 64);
		sph_hamsi512_close(&ctx_hamsi, tmphash);

		//X12
		sph_fugue512_init(&ctx_fugue);
		sph_fugue512(&ctx_fugue, tmphash, 64);
		sph_fugue512_close(&ctx_fugue, tmphash);

		//X13
		sph_shabal512_init(&ctx_shabal);
		sph_shabal512(&ctx_shabal, tmphash, 64);
		sph_shabal512_close(&ctx_shabal, tmphash);
	}

	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5(&ctx_haval, (const void*)tmphash, 64);
	sph_haval256_5_close(&ctx_haval, hash);
}

#else
void xdag_hash(void *data, size_t size, xdag_hash_t hash)
{
	SHA256REF_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, size);
	sha256_final(&ctx, (uint8_t*)hash);
	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)hash, sizeof(xdag_hash_t));
	sha256_final(&ctx, (uint8_t*)hash);
}
#endif

unsigned xdag_hash_ctx_size(void)
{
	return sizeof(SHA256REF_CTX);
}

void xdag_hash_init(void *ctxv)
{
	SHA256REF_CTX *ctx = (SHA256REF_CTX*)ctxv;

	sha256_init(ctx);
}

void xdag_hash_update(void *ctxv, void *data, size_t size)
{
	SHA256REF_CTX *ctx = (SHA256REF_CTX*)ctxv;

	sha256_update(ctx, data, size);
}

void xdag_hash_final(void *ctxv, void *data, size_t size, xdag_hash_t hash)
{
	SHA256REF_CTX ctx;
	sph_blake512_context      ctx_blake;
	sph_bmw512_context        ctx_bmw;
	sph_groestl512_context    ctx_groestl;
	sph_jh512_context         ctx_jh;
	sph_keccak512_context     ctx_keccak;
	sph_skein512_context      ctx_skein;
	sph_luffa512_context      ctx_luffa;
	sph_cubehash512_context   ctx_cubehash;
	sph_shavite512_context    ctx_shavite;
	sph_simd512_context       ctx_simd;
	sph_echo512_context       ctx_echo;
	sph_hamsi512_context      ctx_hamsi;
	sph_fugue512_context      ctx_fugue;
	sph_shabal512_context     ctx_shabal;
	sph_haval256_5_context    ctx_haval;

	unsigned char tmphash[128] = { 0 };
	//X0
	memcpy(&ctx, ctxv, sizeof(ctx));
	sha256_update(&ctx, (uint8_t*)data, size);
	sha256_final(&ctx, (uint8_t*)tmphash);

	for (int n = 0; n < 2; ++n)
	{
		//X1
		sph_blake512_init(&ctx_blake);
		sph_blake512(&ctx_blake, tmphash, 64);
		sph_blake512_close(&ctx_blake, tmphash);

		//X2
		sph_bmw512_init(&ctx_bmw);
		sph_bmw512(&ctx_bmw, tmphash, 64);
		sph_bmw512_close(&ctx_bmw, tmphash);

		//X3
		sph_groestl512_init(&ctx_groestl);
		sph_groestl512(&ctx_groestl, tmphash, 64);
		sph_groestl512_close(&ctx_groestl, tmphash);

		//X4
		sph_skein512_init(&ctx_skein);
		sph_skein512(&ctx_skein, tmphash, 64);
		sph_skein512_close(&ctx_skein, tmphash);

		//X5
		sph_jh512_init(&ctx_jh);
		sph_jh512(&ctx_jh, tmphash, 64);
		sph_jh512_close(&ctx_jh, tmphash);

		//X6
		sph_keccak512_init(&ctx_keccak);
		sph_keccak512(&ctx_keccak, tmphash, 64);
		sph_keccak512_close(&ctx_keccak, tmphash);

		//X7
		sph_luffa512_init(&ctx_luffa);
		sph_luffa512(&ctx_luffa, tmphash, 64);
		sph_luffa512_close(&ctx_luffa, tmphash);

		//X8
		sph_cubehash512_init(&ctx_cubehash);
		sph_cubehash512(&ctx_cubehash, tmphash, 64);
		sph_cubehash512_close(&ctx_cubehash, tmphash);

		//X9
		sph_shavite512_init(&ctx_shavite);
		sph_shavite512(&ctx_shavite, tmphash, 64);
		sph_shavite512_close(&ctx_shavite, tmphash);

		//X10
		sph_simd512_init(&ctx_simd);
		sph_simd512(&ctx_simd, tmphash, 64);
		sph_simd512_close(&ctx_simd, tmphash);

		//X11
		sph_hamsi512_init(&ctx_hamsi);
		sph_hamsi512(&ctx_hamsi, tmphash, 64);
		sph_hamsi512_close(&ctx_hamsi, tmphash);

		//X12
		sph_fugue512_init(&ctx_fugue);
		sph_fugue512(&ctx_fugue, tmphash, 64);
		sph_fugue512_close(&ctx_fugue, tmphash);

		//X13
		sph_shabal512_init(&ctx_shabal);
		sph_shabal512(&ctx_shabal, tmphash, 64);
		sph_shabal512_close(&ctx_shabal, tmphash);
	}

	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5(&ctx_haval, (const void*)tmphash, 64);
	sph_haval256_5_close(&ctx_haval, hash);
}

#ifndef SHA256_OPENSSL_MBLOCK

#ifdef _ndagHASH_
uint64_t xdag_hash_final_multi(void *ctxv, uint64_t *nonce, int attempts, int step, xdag_hash_t hash)
{
	SHA256REF_CTX ctx;
	xdag_hash_t hash0;
	uint64_t min_nonce = 0;
	int i;

	for (i = 0; i < attempts; ++i) {
		xdag_hash_final(ctxv, (uint8_t*)nonce, sizeof(uint64_t), (uint8_t*)hash0);
		
		if (!i || xdag_cmphash(hash0, hash) < 0) {
			memcpy(hash, hash0, sizeof(xdag_hash_t));
			min_nonce = *nonce;
		}

		*nonce += step;
	}

	return min_nonce;
}
#else
uint64_t xdag_hash_final_multi(void *ctxv, uint64_t *nonce, int attempts, int step, xdag_hash_t hash)
{
	SHA256REF_CTX ctx;
	xdag_hash_t hash0;
	uint64_t min_nonce = 0;
	int i;

	for (i = 0; i < attempts; ++i) {
		memcpy(&ctx, ctxv, sizeof(ctx));
		sha256_update(&ctx, (uint8_t*)nonce, sizeof(uint64_t));
		sha256_final(&ctx, (uint8_t*)hash0);
		sha256_init(&ctx);
		sha256_update(&ctx, (uint8_t*)hash0, sizeof(xdag_hash_t));
		sha256_final(&ctx, (uint8_t*)hash0);

		if (!i || xdag_cmphash(hash0, hash) < 0) {
			memcpy(hash, hash0, sizeof(xdag_hash_t));
			min_nonce = *nonce;
		}

		*nonce += step;
	}

	return min_nonce;
}
#endif

#else

#define N 8

typedef struct {
	unsigned int A[8], B[8], C[8], D[8], E[8], F[8], G[8], H[8];
} SHA256_MB_CTX;
typedef struct {
	const unsigned char *ptr;
	int blocks;
} HASH_DESC;

extern void xsha256_multi_block(SHA256_MB_CTX *, const HASH_DESC *, int);

uint64_t xdag_hash_final_multi(void *ctxv, uint64_t *nonce, int attempts, int step, xdag_hash_t hash)
{
	SHA256_MB_CTX mctx1, mctx2, mctx;
	SHA256REF_CTX *ctx1 = (SHA256REF_CTX*)ctxv, ctx2[1];
	HASH_DESC desc1[N], desc2[N];
	uint64_t arr1[N * 16], arr2[N * 8];
	uint8_t *array1 = (uint8_t*)arr1, *array2 = (uint8_t*)arr2;
	xdag_hash_t hash0;
	uint64_t min_nonce = 0, nonce0;
	uint32_t *hash032 = (uint32_t*)(uint64_t*)hash0;
	int i, j;

	memset(array1, 0, 128);
	memcpy(array1, ctx1->data, 56);
	array1[64] = 0x80;
	array1[126] = 0x10;

	for (i = 1; i < N; ++i) {
		memcpy(array1 + i * 128, array1, 128);
	}

	for (i = 0; i < N; ++i) {
		desc1[i].ptr = array1 + i * 128, desc1[i].blocks = 2;
	}

	memset(array2, 0, 64);
	array2[32] = 0x80;
	array2[62] = 1;

	for (i = 1; i < N; ++i) {
		memcpy(array2 + i * 64, array2, 64);
	}

	for (i = 0; i < N; ++i) {
		desc2[i].ptr = array2 + i * 64, desc2[i].blocks = 1;
	}

	sha256_init(ctx2);

	for (i = 0; i < N; ++i) {
		mctx1.A[i] = ctx1->state[0]; mctx2.A[i] = ctx2->state[0];
		mctx1.B[i] = ctx1->state[1]; mctx2.B[i] = ctx2->state[1];
		mctx1.C[i] = ctx1->state[2]; mctx2.C[i] = ctx2->state[2];
		mctx1.D[i] = ctx1->state[3]; mctx2.D[i] = ctx2->state[3];
		mctx1.E[i] = ctx1->state[4]; mctx2.E[i] = ctx2->state[4];
		mctx1.F[i] = ctx1->state[5]; mctx2.F[i] = ctx2->state[5];
		mctx1.G[i] = ctx1->state[6]; mctx2.G[i] = ctx2->state[6];
		mctx1.H[i] = ctx1->state[7]; mctx2.H[i] = ctx2->state[7];
	}

	for (j = 0; j < attempts; j += N) {
		memcpy(&mctx, &mctx1, 8 * 8 * 4);
		nonce0 = *nonce;

		for (i = 0; i < N; ++i) {
			memcpy(array1 + i * 128 + 56, nonce, 8); *nonce += step;
		}
		xsha256_multi_block(&mctx, desc1, N / 4);

		for (i = 0; i < N; ++i) {
			((uint32_t*)array2)[i * 16 + 0] = htonl(mctx.A[i]);
			((uint32_t*)array2)[i * 16 + 1] = htonl(mctx.B[i]);
			((uint32_t*)array2)[i * 16 + 2] = htonl(mctx.C[i]);
			((uint32_t*)array2)[i * 16 + 3] = htonl(mctx.D[i]);
			((uint32_t*)array2)[i * 16 + 4] = htonl(mctx.E[i]);
			((uint32_t*)array2)[i * 16 + 5] = htonl(mctx.F[i]);
			((uint32_t*)array2)[i * 16 + 6] = htonl(mctx.G[i]);
			((uint32_t*)array2)[i * 16 + 7] = htonl(mctx.H[i]);
		}
		memcpy(&mctx, &mctx2, 8 * 8 * 4);
		xsha256_multi_block(&mctx, desc2, N / 4);

		for (i = 0; i < N; ++i, nonce0 += step) {
			hash032[0] = htonl(mctx.A[i]);
			hash032[1] = htonl(mctx.B[i]);
			hash032[2] = htonl(mctx.C[i]);
			hash032[3] = htonl(mctx.D[i]);
			hash032[4] = htonl(mctx.E[i]);
			hash032[5] = htonl(mctx.F[i]);
			hash032[6] = htonl(mctx.G[i]);
			hash032[7] = htonl(mctx.H[i]);
			if ((!i && !j) || xdag_cmphash(hash0, hash) < 0) {
				memcpy(hash, hash0, sizeof(xdag_hash_t));
				min_nonce = nonce0;
			}
		}
	}
	return min_nonce;
}

#undef N

#endif

void xdag_hash_get_state(void *ctxv, xdag_hash_t state)
{
	SHA256REF_CTX *ctx = (SHA256REF_CTX*)ctxv;

	memcpy(state, ctx->state, sizeof(xdag_hash_t));
}

void xdag_hash_set_state(void *ctxv, xdag_hash_t state, size_t size)
{
	SHA256REF_CTX *ctx = (SHA256REF_CTX*)ctxv;

	memcpy(ctx->state, state, sizeof(xdag_hash_t));
	ctx->datalen = 0;
	ctx->bitlen = size << 3;
	ctx->bitlenH = 0;
	ctx->md_len = SHA256_BLOCK_SIZE;
}

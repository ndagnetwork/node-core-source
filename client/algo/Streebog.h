#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include "Streebog_consts.h"

typedef struct HashContext
{
	uint8_t buffer[64];	// буфе?для очередного блок?хешируемог?сообщения
	uint8_t hash[64];	// итоговый результа?вычислений
	uint8_t h[64];		// промежуточны?результа?вычислений
	uint8_t N[64];
	uint8_t Sigma[64];	// контрольная сумм?	
	uint8_t v_0[64];	// инициализационны?вектор
	uint8_t v_512[64];	// инициализационны?вектор
	size_t buf_size;	// размер оставшей? част?сообщения, (которая оказалас?меньше очередны?64 байт)
	int hash_size;		// размер хе?сумм?(512 ил?256 би?
} HashContext;


void Hash_256(HashContext *CTX, const uint8_t *m, size_t len);
void Hash_512(HashContext *CTX, const uint8_t *m, size_t len);
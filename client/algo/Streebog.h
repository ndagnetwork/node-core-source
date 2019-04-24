#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include "Streebog_consts.h"

typedef struct HashContext
{
	uint8_t buffer[64];	// ����?��� ���������� ����?����������?���������
	uint8_t hash[64];	// �������� ��������?����������
	uint8_t h[64];		// ������������?��������?����������
	uint8_t N[64];
	uint8_t Sigma[64];	// ����������� ����?	
	uint8_t v_0[64];	// ����������������?������
	uint8_t v_512[64];	// ����������������?������
	size_t buf_size;	// ������ ��������? ����?���������, (������� ��������?������ ��������?64 ����)
	int hash_size;		// ������ ��?����?(512 ��?256 ��?
} HashContext;


void Hash_256(HashContext *CTX, const uint8_t *m, size_t len);
void Hash_512(HashContext *CTX, const uint8_t *m, size_t len);
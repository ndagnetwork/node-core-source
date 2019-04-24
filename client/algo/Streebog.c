#include "Streebog.h"

// �������� �� mod 512
static void AddMod512(const uint8_t *first_vector, const uint8_t *second_vector, uint8_t *result_vector)
{
	int t = 0;
	for (int i = 0; i < 64; i++)
	{
		t = first_vector[i] + second_vector[i] + (t >> 8);
		result_vector[i] = t & 0xff;
	}
}

// xor
static void X(const uint8_t *a, const uint8_t *k, uint8_t *out)
{
	for (int i = 0; i < 64; i++)
	{
		out[i] = a[i] ^ k[i];
	}
}

// �������������� ����������?
static void S(uint8_t *state)
{
	uint8_t t[64];
	for (int i = 63; i >= 0; i--)
	{
		t[i] = Pi[state[i]];
	}
	memcpy(state, t, 64);
}

// �������������� ������������
static void P(uint8_t *state)
{
	uint8_t t[64];
	for (int i = 63; i >= 0; i--)
	{
		t[i] = state[Tau[i]];
	}
	memcpy(state, t, 64);
}

// �������� ��������������
static void L(uint8_t *state)
{
	// �������� ������ ����?�� 8 ����
	uint64_t* in = (uint64_t*)state;
	uint64_t out[8];
	memset(out, 0x00, 64);
	for (int i = 7; i >= 0; i--)
	{
		// ���� ��������?��?����?1, �� ������ ��������?		// �������� ������?A ?����������?		
		for (int j = 63; j >= 0; j--)
			if ((in[i] >> j) & 1)
				out[i] ^= A[63 - j];
	}
	memcpy(state, out, 64);
}

// ������������ ��������?������
static void GetKey(uint8_t *K, int i)
{
	X(K, C[i], K);
	S(K);
	P(K);
	L(K);
}

// E-��������������
static void E(uint8_t *K, const uint8_t *m, uint8_t *state)
{
	memcpy(K, K, 64);
	X(m, K, state);
	for (int i = 0; i < 12; i++)
	{
		S(state);
		P(state);
		L(state);
		GetKey(K, i);
		X(state, K, state);
	}
}

// ������� ����?
static void g(const uint8_t *h, uint8_t *N, const uint8_t *m)
{
	uint8_t t[64], K[64];
	X(N, h, K);
	S(K);
	P(K);
	L(K);
	E(K, m, t);
	X(t, h, t);
	X(t, m, h);
}

// ���������� ������?
static void Padding(HashContext *CTX)
{
	uint8_t t[64];		// ������������?������
	if (CTX->buf_size < 64)
	{
		memset(t, 0x00, 64);	// ����?�� ������������?������
		memcpy(t, CTX->buffer, CTX->buf_size);	// ����?������?��������� ?������������?������
		t[CTX->buf_size] = 0x01;	// ��������� ?������ ����?������?		
		memcpy(CTX->buffer, t, 64);	// ������ ��? ��?����������, ������?	
	}
}

// ���� 1: �������������
void Init(HashContext *CTX, uint16_t hash_size)
{
	memset(CTX, 0x00, sizeof(HashContext));	// ����?�� ��?���������� ������?��������?	
	if (hash_size == 256)
		memset(CTX->h, 0x01, 64);	// ����?���� 256 ��?	
	else
		memset(CTX->h, 0x00, 64);	// ����?���� 512 ��?	
	CTX->hash_size = hash_size;
	CTX->v_512[1] = 0x02;	// �������������� ������ v_512
}

// ���� 2
static void Stage_2(HashContext *CTX, const uint8_t *m)
{
	g(CTX->h, CTX->N, m);
	AddMod512(CTX->N, CTX->v_512, CTX->N);
	AddMod512(CTX->Sigma, m, CTX->Sigma);
}

// ���� 3
static void Stage_3(HashContext *CTX)
{
	uint8_t t[64];
	memset(t, 0x00, 64);
	// ��������?������ ?�������� ���������
	t[1] = ((CTX->buf_size * 8) >> 8) & 0xff;
	t[0] = (CTX->buf_size * 8) & 0xff;

	Padding(CTX); // ��������� ��������? ����?�� �o���� 64 ����

	g(CTX->h, CTX->N, (const uint8_t*)&(CTX->buffer));

	// ��������?����������?����?���������
	AddMod512(CTX->N, t, CTX->N);
	AddMod512(CTX->Sigma, CTX->buffer, CTX->Sigma);

	g(CTX->h, CTX->v_0, (const uint8_t*)&(CTX->N));
	g(CTX->h, CTX->v_0, (const uint8_t*)&(CTX->Sigma));

	memcpy(CTX->hash, CTX->h, 64);	// ���������� ��������??������ ����?
}

void Update(HashContext *CTX, const uint8_t *m, size_t len)
{
	size_t chk_size;	//����?������������?����?������

	while ((len > 63) && (CTX->buf_size) == 0)
	{
		Stage_2(CTX, m);
		m += 64;
		len -= 64;
	}
	while (len)
	{
		chk_size = 64 - CTX->buf_size;
		if (chk_size > len)
			chk_size = len;
		// ���������� ������������?����?������
		memcpy(&CTX->buffer[CTX->buf_size], m, chk_size);
		CTX->buf_size += chk_size;
		len -= chk_size;
		m += chk_size;
		if (CTX->buf_size == 64)
		{
			// ���� ����?��������? ��������? �� ������ ��?���� ������ ����
			Stage_2(CTX, CTX->buffer);
			CTX->buf_size = 0;
		}
	}
}

void Final(HashContext *CTX)
{
	Stage_3(CTX);
	CTX->buf_size = 0;
}
#include "Streebog.h"

// сложение по mod 512
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

// преобразование подстановк?
static void S(uint8_t *state)
{
	uint8_t t[64];
	for (int i = 63; i >= 0; i--)
	{
		t[i] = Pi[state[i]];
	}
	memcpy(state, t, 64);
}

// преобразование перестановки
static void P(uint8_t *state)
{
	uint8_t t[64];
	for (int i = 63; i >= 0; i--)
	{
		t[i] = state[Tau[i]];
	}
	memcpy(state, t, 64);
}

// линейное преобразование
static void L(uint8_t *state)
{
	// исходный вектор дели?по 8 байт
	uint64_t* in = (uint64_t*)state;
	uint64_t out[8];
	memset(out, 0x00, 64);
	for (int i = 7; i >= 0; i--)
	{
		// если очередно?би?раве?1, то ксорим очередно?		// значение матриц?A ?предыдущим?		
		for (int j = 63; j >= 0; j--)
			if ((in[i] >> j) & 1)
				out[i] ^= A[63 - j];
	}
	memcpy(state, out, 64);
}

// формирование раундовы?ключей
static void GetKey(uint8_t *K, int i)
{
	X(K, C[i], K);
	S(K);
	P(K);
	L(K);
}

// E-преобразование
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

// функция сжат?
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

// дополнение вектор?
static void Padding(HashContext *CTX)
{
	uint8_t t[64];		// промежуточны?вектор
	if (CTX->buf_size < 64)
	{
		memset(t, 0x00, 64);	// обну?ем промежуточны?вектор
		memcpy(t, CTX->buffer, CTX->buf_size);	// пише?остато?сообщения ?промежуточны?вектор
		t[CTX->buf_size] = 0x01;	// добавляем ?нужное мест?единиц?		
		memcpy(CTX->buffer, t, 64);	// кладем вс? чт?получилось, обратн?	
	}
}

// Этап 1: инициализация
void Init(HashContext *CTX, uint16_t hash_size)
{
	memset(CTX, 0x00, sizeof(HashContext));	// Обну?ем вс?переменные базово?структур?	
	if (hash_size == 256)
		memset(CTX->h, 0x01, 64);	// Длин?хеша 256 би?	
	else
		memset(CTX->h, 0x00, 64);	// Длин?хеша 512 би?	
	CTX->hash_size = hash_size;
	CTX->v_512[1] = 0x02;	// Инициализируем вектор v_512
}

// Этап 2
static void Stage_2(HashContext *CTX, const uint8_t *m)
{
	g(CTX->h, CTX->N, m);
	AddMod512(CTX->N, CTX->v_512, CTX->N);
	AddMod512(CTX->Sigma, m, CTX->Sigma);
}

// Этап 3
static void Stage_3(HashContext *CTX)
{
	uint8_t t[64];
	memset(t, 0x00, 64);
	// формируе?строку ?размером сообщения
	t[1] = ((CTX->buf_size * 8) >> 8) & 0xff;
	t[0] = (CTX->buf_size * 8) & 0xff;

	Padding(CTX); // дополняем оставшую? част?до пoлных 64 байт

	g(CTX->h, CTX->N, (const uint8_t*)&(CTX->buffer));

	// формируе?контрольну?сумм?сообщения
	AddMod512(CTX->N, t, CTX->N);
	AddMod512(CTX->Sigma, CTX->buffer, CTX->Sigma);

	g(CTX->h, CTX->v_0, (const uint8_t*)&(CTX->N));
	g(CTX->h, CTX->v_0, (const uint8_t*)&(CTX->Sigma));

	memcpy(CTX->hash, CTX->h, 64);	// записываем результа??нужное мест?
}

void Update(HashContext *CTX, const uint8_t *m, size_t len)
{
	size_t chk_size;	//объе?незаполненно?част?буфера

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
		// дописываем незаполненну?част?буфера
		memcpy(&CTX->buffer[CTX->buf_size], m, chk_size);
		CTX->buf_size += chk_size;
		len -= chk_size;
		m += chk_size;
		if (CTX->buf_size == 64)
		{
			// Если буфе?заполнил? полность? то делаем ещ?один второй этап
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
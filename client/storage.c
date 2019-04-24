/* локальное хранилище, T13.663-T13.825 $DVS:time$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "storage.h"
#include "init.h"
#include "hash.h"
#include "utils/log.h"
#include "utils/utils.h"

#define STORAGE_DIR0            "storage%s"
#define STORAGE_DIR0_ARGS(t)    (g_xdag_testnet ? "-testnet" : "")
#define STORAGE_DIR1            STORAGE_DIR0 DELIMITER "%02x"
#define STORAGE_DIR1_ARGS(t)    STORAGE_DIR0_ARGS(t), (int)((t) >> 40)
#define STORAGE_DIR2            STORAGE_DIR1 DELIMITER "%02x"
#define STORAGE_DIR2_ARGS(t)    STORAGE_DIR1_ARGS(t), (int)((t) >> 32) & 0xff
#define STORAGE_DIR3            STORAGE_DIR2 DELIMITER "%02x"
#define STORAGE_DIR3_ARGS(t)    STORAGE_DIR2_ARGS(t), (int)((t) >> 24) & 0xff
#define STORAGE_FILE            STORAGE_DIR3 DELIMITER "%02x.dat"
#define STORAGE_FILE_ARGS(t)    STORAGE_DIR3_ARGS(t), (int)((t) >> 16) & 0xff
#define SUMS_FILE               "sums.dat"

static pthread_mutex_t storage_mutex = PTHREAD_MUTEX_INITIALIZER;
static int in_adding_all = 0;

static int correct_storage_sum(const char *path, int pos, const struct xdag_storage_sum *sum, int add)
{
	struct xdag_storage_sum sums[256];
	FILE *f = xdag_open_file(path, "r+b");

	if (f) {
		if (fread(sums, sizeof(struct xdag_storage_sum), 256, f) != 256) {
			xdag_close_file(f); xdag_err("Storage: sums file %s corrupted", path);
			return -1;
		}
		rewind(f);
	} else {
		f = xdag_open_file(path, "wb");
		if (!f) {
			xdag_err("Storage: can't create file %s", path);
			return -1;
		}
		memset(sums, 0, sizeof(sums));
	}

	if (!add) {
		if (sums[pos].size == sum->size && sums[pos].sum == sum->sum) {
			xdag_close_file(f); return 0;
		}

		if (sums[pos].size || sums[pos].sum) {
			sums[pos].size = sums[pos].sum = 0;
			xdag_err("Storage: corrupted, sums file %s, pos %x", path, pos);
		}
	}

	sums[pos].size += sum->size;
	sums[pos].sum += sum->sum;
	
	if (fwrite(sums, sizeof(struct xdag_storage_sum), 256, f) != 256) {
		xdag_close_file(f); xdag_err("Storage: can't write file %s", path); return -1;
	}
	
	xdag_close_file(f);
	
	return 1;
}

static int correct_storage_sums(xdag_time_t t, const struct xdag_storage_sum *sum, int add)
{
	char path[256];

	sprintf(path, STORAGE_DIR3 DELIMITER SUMS_FILE, STORAGE_DIR3_ARGS(t));
	int res = correct_storage_sum(path, (t >> 16) & 0xff, sum, add);
	if (res <= 0) return res;
	
	sprintf(path, STORAGE_DIR2 DELIMITER SUMS_FILE, STORAGE_DIR2_ARGS(t));
	res = correct_storage_sum(path, (t >> 24) & 0xff, sum, 1);
	if (res <= 0) return res;
	
	sprintf(path, STORAGE_DIR1 DELIMITER SUMS_FILE, STORAGE_DIR1_ARGS(t));
	res = correct_storage_sum(path, (t >> 32) & 0xff, sum, 1);
	if (res <= 0) return res;
	
	sprintf(path, STORAGE_DIR0 DELIMITER SUMS_FILE, STORAGE_DIR0_ARGS(t));
	res = correct_storage_sum(path, (t >> 40) & 0xff, sum, 1);
	if (res <= 0) return res;
	
	return 0;
}

/* Saves the block to local storage, returns its number or -1 in case of error */
int64_t xdag_storage_save(const struct xdag_block *b)
{
	struct xdag_storage_sum s;
	char path[256];
	int64_t res;

	if (in_adding_all) {
		return -1;
	}
	
	sprintf(path, STORAGE_DIR0, STORAGE_DIR0_ARGS(b->field[0].time));
	xdag_mkdir(path);
	
	sprintf(path, STORAGE_DIR1, STORAGE_DIR1_ARGS(b->field[0].time));
	xdag_mkdir(path);
	
	sprintf(path, STORAGE_DIR2, STORAGE_DIR2_ARGS(b->field[0].time));
	xdag_mkdir(path);
	
	sprintf(path, STORAGE_DIR3, STORAGE_DIR3_ARGS(b->field[0].time));
	xdag_mkdir(path);
	
	sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(b->field[0].time));
	
	pthread_mutex_lock(&storage_mutex);
	
	FILE *f = xdag_open_file(path, "ab");
	if (f) {
		fseek(f, 0, SEEK_END);
		res = ftell(f);
		fwrite(b, sizeof(struct xdag_block), 1, f);
		xdag_close_file(f);
		s.size = sizeof(struct xdag_block);
		s.sum = 0;

		for (int j = 0; j < sizeof(struct xdag_block) / sizeof(uint64_t); ++j) {
			s.sum += ((uint64_t*)b)[j];
		}

		if (correct_storage_sums(b->field[0].time, &s, 1)) {
			res = -1;
		}
	} else {
		res = -1;
	}

	pthread_mutex_unlock(&storage_mutex);
	
	return res;
}

/* reads a block and its number from the local repository; writes it to the buffer or returns a permanent reference, 0 in case of error */
struct xdag_block *xdag_storage_load(xdag_hash_t hash, xdag_time_t time, uint64_t pos, struct xdag_block *buf)
{
	xdag_hash_t hash0;
	char path[256];

	sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(time));

	pthread_mutex_lock(&storage_mutex);
	
	FILE *f = xdag_open_file(path, "rb");
	if (f) {
		if (fseek(f, pos, SEEK_SET) < 0 || fread(buf, sizeof(struct xdag_block), 1, f) != 1) {
			buf = 0;
		}
		xdag_close_file(f);
	} else {
		buf = 0;
	}

	pthread_mutex_unlock(&storage_mutex);
	
	if (buf) {
		xdag_hash(buf, sizeof(struct xdag_block), hash0);
		if (memcmp(hash, hash0, sizeof(xdag_hashlow_t))) {
			buf = 0;
		}
	}

	if (!buf) {
		xdag_blocks_reset();
	}

	return buf;
}

#define bufsize (0x100000 / sizeof(struct xdag_block))

static int sort_callback(const void *l, const void *r)
{
	struct xdag_block **L = (struct xdag_block **)l, **R = (struct xdag_block **)r;

	if ((*L)->field[0].time < (*R)->field[0].time) return -1;
	if ((*L)->field[0].time > (*R)->field[0].time) return 1;

	return 0;
}

/*
 Use double simple fifo queue to preload storage files while adding blocks to rbtree.
 One thread to preload storage files.
 The other one to add blocks to rbtree.
 */
#define SIMPLE_QUEUE_MAX_MEM (100000000) /* Max memory for queue 100MB */
#define QUEUE_SIZE 2
#define	QUEUE_WRITE 0x1
#define	QUEUE_DONE 0x2

struct queue_item {
	struct xdag_block *data;
	char filename[128];
	size_t size;
	struct queue_item *next;
};

struct simple_queue {
	struct queue_item *head;
	struct queue_item *tail;
	size_t totalsize;
	uint8_t status;
	size_t length;
};

static pthread_mutex_t simple_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct simple_queue g_msg_queue[QUEUE_SIZE];

static void simple_queue_init()
{
	for (int i = 0; i < QUEUE_SIZE; i++) {
		g_msg_queue[i].head = NULL;
		g_msg_queue[i].tail = NULL;
		g_msg_queue[i].totalsize = 0;
		g_msg_queue[i].status = QUEUE_WRITE;
		g_msg_queue[i].length = 0;
	}
}

static int simple_queue_push(void *data, size_t size/*, char *filename */)
{
	struct queue_item *item = (struct queue_item*)malloc(sizeof(struct queue_item));
	if(!item) {
		return -1;
	}
	
	item->data = data;
	item->size = size;
	
	/* strcpy(item->filename, filename); */
	
	item->next = NULL;
	
	pthread_mutex_lock(&simple_queue_mutex);
	
	uint8_t res = 0;
	for (int i = 0; i < QUEUE_SIZE; i++) {
		/* check if queue is ready for write. */
		if(g_msg_queue[i].totalsize + size >= SIMPLE_QUEUE_MAX_MEM) {
			g_msg_queue[i].status = !QUEUE_WRITE;
		}
		
		if(g_msg_queue[i].status & QUEUE_WRITE) {
			if(!g_msg_queue[i].head) {
				g_msg_queue[i].head = item;
				g_msg_queue[i].tail = item;
			} else {
				g_msg_queue[i].tail->next = item;
				g_msg_queue[i].tail = item;
			}
			g_msg_queue[i].totalsize += item->size;
			g_msg_queue[i].length ++;
			res = 1;
			break;
		}
	}
	
	pthread_mutex_unlock(&simple_queue_mutex);
	
	if(res == 0) {
		free(item);
	}
	
	return res;
}

static struct queue_item* simple_queue_splice()
{
	pthread_mutex_lock(&simple_queue_mutex);
	
	struct queue_item * res = NULL;
	for (int i = 0; i < QUEUE_SIZE; i++) {
		/* check if queue is ready for write. */
		if(g_msg_queue[i].head == NULL) {
			g_msg_queue[i].status |= QUEUE_WRITE;
			g_msg_queue[i].totalsize = 0;
		} else if(!(g_msg_queue[i].status & QUEUE_WRITE)) {
			res = g_msg_queue[i].head;
			g_msg_queue[i].head = res->next;
			g_msg_queue[i].totalsize -= res->size;
			g_msg_queue[i].length --;
			
			if(g_msg_queue[i].tail == res) {
				g_msg_queue[i].tail = NULL;
				g_msg_queue[i].status |= QUEUE_WRITE;
				g_msg_queue[i].totalsize = 0;
			}
			break;
		}
	}

	pthread_mutex_unlock(&simple_queue_mutex);
	return res;
}

struct init_storage_param {
	xdag_time_t start_time; 
	xdag_time_t end_time;
	xdag_time_t *data;
	void *(*callback)(void *, void *);
};

static void *init_storage_load_thread(void *data)
{   
	struct init_storage_param *param = (struct init_storage_param *)data;
	xdag_time_t start_time = param->start_time;
	xdag_time_t end_time = param->end_time;
	
	struct xdag_block readbuf[bufsize];
	struct xdag_storage_sum sum;
	sum.size = sum.sum = 0;
	
	char path[256];
	uint64_t pos = 0, mask;
	int64_t todo = 0;
	
	while (start_time < end_time) {
		sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(start_time));
				
		pthread_mutex_lock(&storage_mutex);
		FILE *f = xdag_open_file(path, "rb");
		if (f) {
			if (fseek(f, pos, SEEK_SET) < 0) todo = 0;
			else todo = fread(readbuf, sizeof(struct xdag_block), bufsize, f);
			xdag_close_file(f);
		} else {
			todo = 0;
		}
		pthread_mutex_unlock(&storage_mutex);
		
		if(todo > 0) {
			for (int i = 0; i < todo; ++i) {
				sum.size += sizeof(struct xdag_block);
				for (int j = 0; j < sizeof(struct xdag_block) / sizeof(uint64_t); ++j) {
					sum.sum += ((uint64_t*)(readbuf + i))[j];
				}
			}
			
			struct xdag_block *blocks = (struct xdag_block*)malloc(sizeof(struct xdag_block)*todo);
			memcpy(blocks, readbuf, sizeof(struct xdag_block)*todo);
			
			while (simple_queue_push(blocks, sizeof(struct xdag_block)*todo/*, path*/) == 0) {
				sleep(.001);
			}
		}
		
		if (todo != bufsize) {
			if (f) {
				pthread_mutex_lock(&storage_mutex);
				
				int res = correct_storage_sums(start_time, &sum, 0);
				
				pthread_mutex_unlock(&storage_mutex);
				
				if (res) {
					break;
				}
				
				sum.size = sum.sum = 0;
				mask = (1l << 16) - 1;
			} else if (sprintf(path, STORAGE_DIR3, STORAGE_DIR3_ARGS(start_time)), xdag_file_exists(path)) {
				mask = (1l << 16) - 1;
			} else if (sprintf(path, STORAGE_DIR2, STORAGE_DIR2_ARGS(start_time)), xdag_file_exists(path)) {
				mask = (1l << 24) - 1;
			} else if (sprintf(path, STORAGE_DIR1, STORAGE_DIR1_ARGS(start_time)), xdag_file_exists(path)) {
				mask = (1ll << 32) - 1;
			} else {
				mask = (1ll << 40) - 1;
			}
			
			start_time |= mask;
			start_time++;
			
			pos = 0;
		} else {
			pos += todo;
		}
	}
	
	for (int i = 0; i < QUEUE_SIZE; i++) {
		g_msg_queue[i].status = QUEUE_DONE;
	}
	
	return 0;
}

static void *init_storage_add_block_thread(void *data)
{
	struct init_storage_param *param = (struct init_storage_param *)data;
	struct queue_item *item = NULL;
	struct xdag_block *pbuffer[bufsize];
	struct xdag_storage_sum storageSum;
	storageSum.size = storageSum.sum = 0;
	
	uint64_t sum = 0, pos = 0;
	int64_t i, j, k;
	
	while (1) {
		int finish = 1;
		for (int ii = 0; ii < QUEUE_SIZE; ii++) {
			if (!(g_msg_queue[ii].status & QUEUE_DONE && g_msg_queue[ii].status & QUEUE_WRITE)) {
				finish = 0;
			}
		}
		if(finish) {
			break;
		}
		
		item = simple_queue_splice();
		if(!item) {
			sleep(.001);
			continue;
		}
				
		uint64_t todo = item->size / sizeof(struct xdag_block);
		uint64_t pos0 = pos;
		
//		memcpy(buffer, item->data, item->size);
		struct xdag_block *buffer = item->data;
		
		for (i = k = 0; i < todo; ++i, pos += sizeof(struct xdag_block)) {
			storageSum.size += sizeof(struct xdag_block);
//			if (buf[i].field[0].time >= start_time && buf[i].field[0].time < end_time) {
				for (j = 0; j < sizeof(struct xdag_block) / sizeof(uint64_t); ++j) {
					storageSum.sum += ((uint64_t*)(buffer + i))[j];
				}
				pbuffer[k++] = buffer + i;
//			}
		}
		
		if (k) {
			qsort(pbuffer, k, sizeof(struct xdag_block *), sort_callback);
		}
		
		for (i = 0; i < k; ++i) {
			pbuffer[i]->field[0].transport_header = pos0 + ((uint8_t*)pbuffer[i] - (uint8_t*)buffer);
			if ((param->callback)(pbuffer[i], param->data)) return 0;
			sum++;
		}
		
		if(todo != bufsize) {
			pos = 0;
		}
		
		free(item->data);
		free(item);
	}
	
	return 0;
}

void xdag_init_storage(xdag_time_t start_time, xdag_time_t end_time, void *data, void *(*callback)(void *, void *))
{
	simple_queue_init();
	
	struct init_storage_param param;
	param.start_time = start_time;
	param.end_time = end_time;
	param.data = data;
	param.callback = callback;
		
	pthread_t th_load;
	if(pthread_create(&th_load, NULL, &init_storage_load_thread, &param)) {
		xdag_err("create init storage thread failed!");
	}

	pthread_t th_add;
	if(pthread_create(&th_add, NULL, &init_storage_add_block_thread, &param)) {
		xdag_err("create add block thread failed!");
	}
	
	pthread_join(th_load, NULL);
	pthread_join(th_add, NULL);
}

/* Calls a callback for all blocks from the repository that are in specified time interval; returns the number of blocks */
uint64_t xdag_load_blocks(xdag_time_t start_time, xdag_time_t end_time, void *data, void *(*callback)(void *, void *))
{
	struct xdag_block buf[bufsize], *pbuf[bufsize];
	struct xdag_storage_sum s;
	char path[256];
	
	uint64_t sum = 0, pos = 0, mask;
	int64_t i, j, k, todo;

	s.size = s.sum = 0;

	while (start_time < end_time) {
		sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(start_time));

		pthread_mutex_lock(&storage_mutex);
		
		FILE *f = xdag_open_file(path, "rb");
		if (f) {
			if (fseek(f, pos, SEEK_SET) < 0) todo = 0;
			else todo = fread(buf, sizeof(struct xdag_block), bufsize, f);
			xdag_close_file(f);
		} else {
			todo = 0;
		}
		
		pthread_mutex_unlock(&storage_mutex);
		
		uint64_t pos0 = pos;

		for (i = k = 0; i < todo; ++i, pos += sizeof(struct xdag_block)) {
			if (buf[i].field[0].time >= start_time && buf[i].field[0].time < end_time) {
				s.size += sizeof(struct xdag_block);

				for (j = 0; j < sizeof(struct xdag_block) / sizeof(uint64_t); ++j) {
					s.sum += ((uint64_t*)(buf + i))[j];
				}

				pbuf[k++] = buf + i;
			}
		}

		if (k) {
			qsort(pbuf, k, sizeof(struct xdag_block *), sort_callback);
		}

		for (i = 0; i < k; ++i) {
			pbuf[i]->field[0].transport_header = pos0 + ((uint8_t*)pbuf[i] - (uint8_t*)buf);
			if (callback(pbuf[i], data)) return sum;
			sum++;
		}

		if (todo != bufsize) {
			if (f) {
				pthread_mutex_lock(&storage_mutex);
				
				int res = correct_storage_sums(start_time, &s, 0);
				
				pthread_mutex_unlock(&storage_mutex);
				
				if (res) break;
				
				s.size = s.sum = 0;
				mask = (1l << 16) - 1;
			} else if (sprintf(path, STORAGE_DIR3, STORAGE_DIR3_ARGS(start_time)), xdag_file_exists(path)) {
				mask = (1l << 16) - 1;
			} else if (sprintf(path, STORAGE_DIR2, STORAGE_DIR2_ARGS(start_time)), xdag_file_exists(path)) {
				mask = (1l << 24) - 1;
			} else if (sprintf(path, STORAGE_DIR1, STORAGE_DIR1_ARGS(start_time)), xdag_file_exists(path)) {
				mask = (1ll << 32) - 1;
			} else {
				mask = (1ll << 40) - 1;
			}

			start_time |= mask;
			start_time++;
			
			pos = 0;
		}
	}

	return sum;
}

/* places the sums of blocks in 'sums' array, blocks are filtered by interval from start_time to end_time, splitted to 16 parts;
 * end - start should be in form 16^k
 * (original russian comment is unclear too) */
int xdag_load_sums(xdag_time_t start_time, xdag_time_t end_time, struct xdag_storage_sum sums[16])
{
	struct xdag_storage_sum buf[256];
	char path[256];
	int i, level;

	end_time -= start_time;
	if (!end_time || end_time & (end_time - 1) || end_time & 0xFFFEEEEEEEEFFFFFl) return -1;

	for (level = -6; end_time; level++, end_time >>= 4);

	if (level < 2) {
		sprintf(path, STORAGE_DIR3 DELIMITER SUMS_FILE, STORAGE_DIR3_ARGS(start_time & 0xffffff000000l));
	} else if (level < 4) {
		sprintf(path, STORAGE_DIR2 DELIMITER SUMS_FILE, STORAGE_DIR2_ARGS(start_time & 0xffff00000000l));
	} else if (level < 6) {
		sprintf(path, STORAGE_DIR1 DELIMITER SUMS_FILE, STORAGE_DIR1_ARGS(start_time & 0xff0000000000l));
	} else {
		sprintf(path, STORAGE_DIR0 DELIMITER SUMS_FILE, STORAGE_DIR0_ARGS(start_time & 0x000000000000l));
	}

	FILE *f = xdag_open_file(path, "rb");
	if (f) {
		fread(buf, sizeof(struct xdag_storage_sum), 256, f); xdag_close_file(f);
	} else {
		memset(buf, 0, sizeof(buf));
	}

	if (level & 1) {
		memset(sums, 0, 16 * sizeof(struct xdag_storage_sum));

		for (i = 0; i < 256; ++i) {
			sums[i >> 4].size += buf[i].size, sums[i >> 4].sum += buf[i].sum;
		}
	} else {
		memcpy(sums, buf + (start_time >> ((level + 4) * 4) & 0xf0), 16 * sizeof(struct xdag_storage_sum));
	}

	return 1;
}

/* completes work with the storage */
void xdag_storage_finish(void)
{
	pthread_mutex_lock(&storage_mutex);
}

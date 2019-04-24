/* пул и майнер, T13.744-T13.895 $DVS:time$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "system.h"
#include "../dus/programs/dfstools/source/dfslib/dfslib_crypt.h"
#include "../dus/programs/dar/source/include/crc.h"
#include "address.h"
#include "block.h"
#include "init.h"
#include "miner.h"
#include "storage.h"
#include "sync.h"
#include "transport.h"
#include "mining_common.h"
#include "network.h"
#include "utils/log.h"
#include "utils/utils.h"
#include "uthash/utlist.h"

#define MINERS_PWD             "minersgonnamine"
#define SECTOR0_BASE           0x1947f3acu
#define SECTOR0_OFFSET         0x82e9d1b5u
#define SEND_PERIOD            10                                  /* share period of sending shares */
#define POOL_LIST_FILE         (g_xdag_testnet ? "pools-testnet.txt" : "pools.txt")

struct miner {
	struct xdag_field id;
	uint64_t nfield_in;
	uint64_t nfield_out;
};

static struct miner g_local_miner;
static pthread_mutex_t g_miner_mutex = PTHREAD_MUTEX_INITIALIZER;

/* a number of mining threads */
int g_xdag_mining_threads = 0;

static int g_socket = -1, g_stop_mining = 1;

static int can_send_share(time_t current_time, time_t task_time, time_t share_time)
{
	int can_send = current_time - share_time >= SEND_PERIOD && current_time - task_time <= 64;
	if(g_xdag_mining_threads == 0 && share_time >= task_time) {
		can_send = 0;  //we send only one share per task if mining is turned off
	}
	return can_send;
}

/* initialization of connection the miner to pool */
extern int xdag_initialize_miner(const char *pool_address)
{
	pthread_t th;

	memset(&g_local_miner, 0, sizeof(struct miner));
	xdag_get_our_block(g_local_miner.id.data);

	int err = pthread_create(&th, 0, miner_net_thread, (void*)pool_address);
	if(err != 0) {
		printf("create miner_net_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach miner_net_thread failed, error : %s\n", strerror(err));
		//return -1; //fixme: not sure why pthread_detach return 3
	}

	//add new 
	err = pthread_create(&th, 0, miner_command_thread, (void*)pool_address);
	if (err != 0) {
		printf("create miner_command_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if (err != 0) {
		printf("detach miner_command_thread failed, error : %s\n", strerror(err));
		//return -1; //fixme: not sure why pthread_detach return 3
	}
	//***

	return 0;
}

static int send_to_pool(struct xdag_field *srcflds, int nfld)
{
	struct xdag_field fields[XDAG_BLOCK_FIELDS];
	xdag_hash_t hash;
	struct miner *m = &g_local_miner;
	int todo = nfld * sizeof(struct xdag_field), done = 0;

	if(g_socket < 0) {
		return -1;
	}

	memcpy(fields, srcflds, todo);

	if(nfld == XDAG_BLOCK_FIELDS) {
		fields[0].transport_header = 0;

		xdag_hash(fields, sizeof(struct xdag_block), hash);

		fields[0].transport_header = BLOCK_HEADER_WORD;

		uint32_t crc = crc_of_array((uint8_t*)fields, sizeof(struct xdag_block));

		fields[0].transport_header |= (uint64_t)crc << 32;
	}

	for(int i = 0; i < nfld; ++i) {
		dfslib_encrypt_array(g_crypt, (uint32_t*)(fields + i), DATA_SIZE, m->nfield_out++);
	}

	while(todo) {
		struct pollfd p;

		p.fd = g_socket;
		p.events = POLLOUT;

		if(!poll(&p, 1, 1000)) continue;

		if(p.revents & (POLLHUP | POLLERR)) {
			return -1;
		}

		if(!(p.revents & POLLOUT)) continue;

		int res = write(g_socket, (uint8_t*)fields + done, todo);
		if(res <= 0) {
			return -1;
		}

		done += res;
		todo -= res;
	}

	if(nfld == XDAG_BLOCK_FIELDS) {
		xdag_info("Sent  : %016llx%016llx%016llx%016llx t=%llx res=%d",
			hash[3], hash[2], hash[1], hash[0], srcflds[0].time, 0);
	}

	return 0;
}

//add new by slavothin
int register_our_addresses(void* data, xdag_hash_t hash, xdag_amount_t amount, xdag_time_t t, int v)
{
	time_t tb;
	struct xdag_block block;
	const int64_t pos = xdag_get_block_pos(hash, &tb);
	if (pos < 0) {
		return -1;
	}

	struct xdag_block *blk = xdag_storage_load(hash, tb, pos, &block);
	if (!blk) {
		return -1;
	}
	if (blk != &block) memcpy(&block, blk, sizeof(struct xdag_block));

	pthread_mutex_lock(&g_miner_mutex);
	if (send_to_pool(block.field, XDAG_BLOCK_FIELDS) < 0) {
		pthread_mutex_unlock(&g_miner_mutex);
		return -1;
	}
	pthread_mutex_unlock(&g_miner_mutex);

	return 0;
}
typedef struct compare_hash_elements {
	xdag_hash_t hash;
	int exists;
}compare_hash_elements;

int compare_our_addresses(void* data, xdag_hash_t hash, xdag_amount_t amount, xdag_time_t t, int v)
{
	compare_hash_elements *el = (compare_hash_elements*)data;
	if (!el) return -1;
	if (memcmp(el->hash, hash, sizeof(xdag_hashlow_t))==0) {
		el->exists = 1;
		return 1;
	}
	return 0;
}

typedef struct command_list_elements {
	char address[SIZE_MAX_ADDRESS];
	xdag_amount_t amount;
	struct command_list_elements *next;
}command_list_elements;

command_list_elements *g_command_elements_list_head;
void *miner_command_thread(void *arg)
{
	int process = 0;
	char command[1024];
	command_list_elements *el, *tmp;
	while (!g_xdag_sync_on) {
		sleep(1);
	}

	for (;;) {
		process = 0;
		pthread_mutex_lock(&g_miner_mutex);
		LL_FOREACH_SAFE(g_command_elements_list_head, el, tmp)
		{
			LL_DELETE(g_command_elements_list_head, el);
			process = 1;
			sprintf(command, "%sbalancenotify %s %.9Lf %ld", g_xdag_current_path, el->address,amount2xdags(el->amount),get_timestamp());
			int out = system(command);
			if (out) {
				fprintf(stdout,"error: balancenotify (%s) returned %d\n", command,out);
			}
		}
		pthread_mutex_unlock(&g_miner_mutex);
		if (process) {
			fprintf(stdout, "ndag>");
		}

		if (!process) {
			sleep(1);
		}
	}
}
// ***

void *miner_net_thread(void *arg)
{
	struct xdag_block block;
	struct xdag_field data[2];
	xdag_hash_t miner_address_hash;
	const char *pool_address = (const char*)arg;
	const char *error_message = NULL;
	int res = 0;
	xdag_time_t t;
	struct miner *m = &g_local_miner;

	while(!g_xdag_sync_on) {
		sleep(1);
	}

begin:

	m->nfield_in = m->nfield_out = 0;

	int ndata = 0;
	int maxndata = sizeof(struct xdag_field);
	time_t share_time = 0;
	time_t task_time = 0;

	if(g_miner_address) {
		if(xdag_address2hash(g_miner_address, miner_address_hash)) {
			error_message = "incorrect miner address";
			goto err;
		}
	} else if(xdag_get_our_block(miner_address_hash)) {
		error_message = "can't create a block";
		goto err;
	}


	const int64_t pos = xdag_get_block_pos(miner_address_hash, &t);
	if(pos < 0) {
		error_message = "can't find the block";
		goto err;
	}

	struct xdag_block *blk = xdag_storage_load(miner_address_hash, t, pos, &block);
	if(!blk) {
		error_message = "can't load the block";
		goto err;
	}
	if(blk != &block) memcpy(&block, blk, sizeof(struct xdag_block));

	pthread_mutex_lock(&g_miner_mutex);
	g_socket = xdag_connect_pool(pool_address, &error_message);
	if(g_socket == INVALID_SOCKET) {
		pthread_mutex_unlock(&g_miner_mutex);
		goto err;
	}

	if(send_to_pool(block.field, XDAG_BLOCK_FIELDS) < 0) {
		error_message = "socket is closed";
		pthread_mutex_unlock(&g_miner_mutex);
		goto err;
	}
	pthread_mutex_unlock(&g_miner_mutex);

	//add new by slavothin
	if (g_is_exwallet) {
		xdag_traverse_our_blocks(0, register_our_addresses);
	}
	//***

	for(;;) {
		struct pollfd p;

		pthread_mutex_lock(&g_miner_mutex);

		if(g_socket < 0) {
			pthread_mutex_unlock(&g_miner_mutex);
			error_message = "socket is closed";
			goto err;
		}

		p.fd = g_socket;
		time_t current_time = time(0);
		p.events = POLLIN | (can_send_share(current_time, task_time, share_time) ? POLLOUT : 0);

		if(!poll(&p, 1, 0)) {
			pthread_mutex_unlock(&g_miner_mutex);
			sleep(1);
			continue;
		}

		if(p.revents & POLLHUP) {
			pthread_mutex_unlock(&g_miner_mutex);
			error_message = "socket hangup";
			goto err;
		}

		if(p.revents & POLLERR) {
			pthread_mutex_unlock(&g_miner_mutex);
			error_message = "socket error";
			goto err;
		}

		if(p.revents & POLLIN) {
			res = read(g_socket, (uint8_t*)data + ndata, maxndata - ndata);
			if(res < 0) {
				pthread_mutex_unlock(&g_miner_mutex); 
				error_message = "read error on socket"; 
				goto err;
			}
			ndata += res;
			if(ndata == maxndata) {
				struct xdag_field *last = data + (ndata / sizeof(struct xdag_field) - 1);

				dfslib_uncrypt_array(g_crypt, (uint32_t*)last->data, DATA_SIZE, m->nfield_in++);
				//new add by klomiman
				compare_hash_elements comp;
				memcpy(comp.hash, last->data, sizeof(xdag_hash_t));
				comp.exists = 0;
				xdag_traverse_our_blocks(&comp, compare_our_addresses);

				//if(!memcmp(last->data, miner_address_hash, sizeof(xdag_hashlow_t))) {
				if (comp.exists) {
					//xdag_set_balance(miner_address_hash, last->amount);
					if (g_balance_notify && xdag_get_balance(last->data) != last->amount ) {
						command_list_elements *comm = malloc(sizeof(command_list_elements));
						if (!comm) {
							pthread_mutex_unlock(&g_miner_mutex);
							error_message = "alloc memory for command";
							goto err;
						}
						xdag_hash2address(last->data, comm->address);
						comm->amount = last->amount;
						LL_APPEND(g_command_elements_list_head, comm);
					}
					xdag_set_balance(last->data, last->amount);

					pthread_mutex_lock(&g_transport_mutex);
					g_xdag_last_received = current_time;
					pthread_mutex_unlock(&g_transport_mutex);

					ndata = 0;

					maxndata = sizeof(struct xdag_field);
				} 
				//***
				else if(maxndata == 2 * sizeof(struct xdag_field)) {
					const uint64_t task_index = g_xdag_pool_task_index + 1;
					struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];

					task->task_time = xdag_main_time();
					xdag_hash_set_state(task->ctx1, data[0].data,
						sizeof(struct xdag_block) - 2 * sizeof(struct xdag_field));
					xdag_hash_update(task->ctx1, data[1].data, sizeof(struct xdag_field));
					xdag_hash_update(task->ctx1, miner_address_hash, sizeof(xdag_hashlow_t));

					xdag_generate_random_array(task->nonce.data, sizeof(xdag_hash_t));

					memcpy(task->nonce.data, miner_address_hash, sizeof(xdag_hashlow_t));
					memcpy(task->lastfield.data, task->nonce.data, sizeof(xdag_hash_t));//hash for miner account + nonce

					xdag_hash_final(task->ctx1, &task->nonce.amount, sizeof(uint64_t), task->min_hash.data);

					g_xdag_pool_task_index = task_index;
					task_time = time(0);

					xdag_info("Task  : t=%llx N=%llu", task->task_time << 16 | 0xffff, task_index);

					ndata = 0;
					maxndata = sizeof(struct xdag_field);
				} else {
					maxndata = 2 * sizeof(struct xdag_field);
				}
			}
		}

		if(p.revents & POLLOUT) {
			const uint64_t task_index = g_xdag_pool_task_index;
			struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];
			uint64_t *h = task->min_hash.data;

			share_time = time(0);
			res = send_to_pool(&task->lastfield, 1);
			pthread_mutex_unlock(&g_miner_mutex);

			xdag_info("Share : %016llx%016llx%016llx%016llx t=%llx res=%d",
				h[3], h[2], h[1], h[0], task->task_time << 16 | 0xffff, res);

			if(res) {
				error_message = "write error on socket"; goto err;
			}
		} else {
			pthread_mutex_unlock(&g_miner_mutex);
		}
	}

	return 0;

err:
	xdag_err("Miner: %s (error %d)", error_message, res);

	pthread_mutex_lock(&g_miner_mutex);

	if(g_socket != INVALID_SOCKET) {
		close(g_socket);
		g_socket = INVALID_SOCKET;
	}

	pthread_mutex_unlock(&g_miner_mutex);

	sleep(5);

	goto begin;
}

static void *mining_thread(void *arg)
{
	xdag_hash_t hash;
	struct xdag_field lastfield;
	const int nthread = (int)(uintptr_t)arg;
	uint64_t oldntask = 0;
	uint64_t nonce;

	while(!g_xdag_sync_on && !g_stop_mining) {
		sleep(1);
	}

	while(!g_stop_mining) {
		const uint64_t ntask = g_xdag_pool_task_index;
		struct xdag_pool_task *task = &g_xdag_pool_task[ntask & 1];

		if(!ntask) {
			sleep(1);
			continue;
		}

		if(ntask != oldntask) {
			oldntask = ntask;
			memcpy(lastfield.data, task->nonce.data, sizeof(xdag_hash_t));
			nonce = lastfield.amount + nthread;
		}

		lastfield.amount = xdag_hash_final_multi(task->ctx1, &nonce, 4096, g_xdag_mining_threads, hash);
		g_xdag_extstats.nhashes += 4096;

		xdag_set_min_share(task, lastfield.data, hash);
	}

	return 0;
}

/* changes the number of mining threads */
int xdag_mining_start(int n_mining_threads)
{
	pthread_t th;

	if(n_mining_threads == g_xdag_mining_threads) {

	} else if(!n_mining_threads) {
		g_stop_mining = 1;
		g_xdag_mining_threads = 0;
	} else if(!g_xdag_mining_threads) {
		g_stop_mining = 0;
	} else if(g_xdag_mining_threads > n_mining_threads) {
		g_stop_mining = 1;
		sleep(5);
		g_stop_mining = 0;
		g_xdag_mining_threads = 0;
	}

	while(g_xdag_mining_threads < n_mining_threads) {
		g_xdag_mining_threads++;
		int err = pthread_create(&th, 0, mining_thread, (void*)(uintptr_t)g_xdag_mining_threads);
		if(err != 0) {
			printf("create mining_thread failed, error : %s\n", strerror(err));
			continue;
		}

		err = pthread_detach(th);
		if(err != 0) {
			printf("detach mining_thread failed, error : %s\n", strerror(err));
			continue;
		}
	}

	return 0;
}

/* send block to network via pool */
int xdag_send_block_via_pool(struct xdag_block *b)
{
	if(g_socket < 0) return -1;

	pthread_mutex_lock(&g_miner_mutex);
	int ret = send_to_pool(b->field, XDAG_BLOCK_FIELDS);
	pthread_mutex_unlock(&g_miner_mutex);
	return ret;
}

/* picks random pool from the list of pools */
int xdag_search_pool(char *pool_address)
{
	char addresses[30][50];
	const char *error_message;
	srand(time(NULL));
	
	int count = 0;
	FILE *fp = xdag_open_file(POOL_LIST_FILE, "r");
	if(!fp) {
		printf("List of pools is not found\n");
		return 0;
	}
	while(fgets(addresses[count], 50, fp)) {
		// remove trailing newline character
		addresses[count][strcspn(addresses[count], "\n")] = 0;
		++count;
	}
	fclose(fp);

	int start_index = count ? rand() % count : 0;
	int index = start_index;
	do {
		int socket = xdag_connect_pool(addresses[index], &error_message);
		if(socket != INVALID_SOCKET) {
			xdag_connection_close(socket);
			strcpy(pool_address, addresses[index]);
			return 1;
		} else {
			++index;
			if(index >= count) {
				index = 0;
			}
		}
	} while(index != start_index);

	printf("Wallet is unable to connect to network. Check your network connection\n");
	return 0;
}

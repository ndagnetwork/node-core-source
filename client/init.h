/* basic variables, T13.714-T13.895 $DVS:time$ */

#ifndef XDAG_MAIN_H
#define XDAG_MAIN_H

#include <time.h>
#include "block.h"
#include "system.h"

enum xdag_states
{
#define xdag_state(n,s) XDAG_STATE_##n ,
#include "state.h"
#undef xdag_state
};

enum ndag_node
{
	NDAG_NODE_CORE		= 0x01,
	NDAG_NODE_EXWALLET	= 0x02,
	NDAG_NODE_LIGHTWALLET= 0x10,
	NDAG_NODE_FULLWALLET = 0x20
};
/* the maximum period of time for which blocks are requested, not their amounts */
#define REQUEST_BLOCKS_MAX_TIME	(1 << 20)

extern struct xdag_stats
{
    xdag_diff_t difficulty, max_difficulty;
    uint64_t nblocks, total_nblocks;
    uint64_t nmain, total_nmain;
    uint32_t nhosts, total_nhosts, reserved1, reserved2;
} g_xdag_stats;

#define HASHRATE_LAST_MAX_TIME	(64 * 4) // numbers of main blocks in about 4H, to calculate the pool and network mean hashrate

extern struct xdag_ext_stats
{
	xdag_diff_t hashrate_total[HASHRATE_LAST_MAX_TIME];
	xdag_diff_t hashrate_ours[HASHRATE_LAST_MAX_TIME];
	xdag_time_t hashrate_last_time;
	uint64_t nnoref;
	uint64_t nhashes;
	double hashrate_s;
	uint32_t nwaitsync;
	uint32_t cache_size;
	uint32_t cache_usage;
	double cache_hitrate;
} g_xdag_extstats;

#ifdef __cplusplus
extern "C" {
#endif

/* the program state */
extern int g_xdag_state;

/* is there command 'run' */
extern int g_xdag_run;

/* 1 - the program works in a test network */
extern int g_xdag_testnet;

/* coin token and program name */
extern char *g_coinname, *g_progname;

//defines if client runs as miner or pool
extern int g_is_miner;

//defines if client runs as exwallet
extern int g_is_exwallet;

//defines if exwallet set to notify balance changing
extern int g_balance_notify;

//defines if mining is disabled (pool)
extern int g_disable_mining;

//Default type of the block header
//Test network and main network have different types of the block headers, so blocks from different networks are incompatible
extern enum xdag_field_type g_block_header_type;

extern int xdag_init(int argc, char **argv, enum ndag_node node);

extern int xdag_set_password_callback(int(*callback)(const char *prompt, char *buf, unsigned size));

extern int(*g_xdag_show_state)(const char *state, const char *balance, const char *address);

#ifdef __cplusplus
};
#endif

#define xdag_amount2xdag(amount) ((unsigned)((amount) >> 32))
#define xdag_amount2cheato(amount) ((unsigned)(((uint64_t)(unsigned)(amount) * 1000000000) >> 32))

#endif

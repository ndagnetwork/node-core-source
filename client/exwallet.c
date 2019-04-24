/* xdag main, T13.654-T13.895 $DVS:time$ */

#include "init.h"

int showstate(const char *state, const char *balance, const char *address){return 0;}

int main(int argc, char **argv)
{
	const char *exargv[] = { "exwallet" , "-rpc-enable", "-rpc-port", "13300", "-dm","-balance-notify" };
	g_xdag_show_state = &showstate;
	xdag_init(sizeof(exargv)/sizeof(exargv[0]), (char**)exargv, POC_NODE_EXWALLET);
	return 0;
}
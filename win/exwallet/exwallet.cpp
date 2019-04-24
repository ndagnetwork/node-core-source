#include "pch.h"
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include "../../client/init.h"
#include "../../client/commands.h"
#ifdef __cplusplus
}
#endif 

int showstate(const char *state, const char *balance, const char *address)
{
	return 0;
}

int main(int argc, char **argv)
{
	const char *nargv[] = { "ndag.exe" , "-rpc-enable", "-rpc-port", "13300", "-dm","-balance-notify" };
	g_xdag_show_state = &showstate;
	xdag_init(sizeof(nargv)/sizeof(nargv[0]), (char**)nargv, NDAG_NODE_EXWALLET);
	return 0;
}


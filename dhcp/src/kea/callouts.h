#ifndef CALLOUTS_H
#define CALLOUTS_H

#include <hooks/hooks.h>

using namespace isc::hooks;

extern "C" {
	int pkt4_receive(CalloutHandle &handle);
	int subnet4_select(CalloutHandle &handle);
	int lease4_select(CalloutHandle &handle);
	int pkt4_send(CalloutHandle &handle);
	int pkt4_send(CalloutHandle &handle);
}

#endif

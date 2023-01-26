// loging.cpp
//

#include "stdafx.h"
#include "loging.h"


HHOOK g_hhook = NULL;

static LRESULT WINAPI GetMsgProc(int code, WPARAM wParam, LPARAM lParam)
{
	return(CallNextHookEx(NULL, code, wParam, lParam));	// 消息传递给下一个钩子过程
}


LOGING_API int CallSetWindowsHookEx(VOID) 
{
	if(g_hhook != NULL)
		return -1;

	MEMORY_BASIC_INFORMATION mbi;
	if(VirtualQuery(CallSetWindowsHookEx, &mbi, sizeof(mbi)) == 0)
		return -1;
	HMODULE hModule = (HMODULE) mbi.AllocationBase;

	g_hhook = SetWindowsHookEx( // 将 GetMsgProc 设置为钩子进程，系统消息传递给原本的窗口进程前会先传递给钩子进程
		WH_GETMESSAGE, GetMsgProc, hModule, 0);
	if(g_hhook == NULL)
		return -1;

	return 0;
}


LOGING_API int CallUnhookWindowsHookEx(VOID) 
{
	if(g_hhook == NULL)
		return -1;

	UnhookWindowsHookEx(g_hhook);
	g_hhook = NULL;
	return 0;
}
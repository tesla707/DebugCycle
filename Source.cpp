#include <Windows.h>
#include <Psapi.h>
#include <iostream>

#if _UNCIDOE || UNICODE
#define tmain wmain
#define tcout std::wcout
#define tcin std::wcin
#define tcscmp wcscmp
#else
#define tmain main
#define tcout std::cout
#define tcin std::cin
#define tcscmp strcmp
#endif // _UNCIDOE || UNICODE

int tmain() {

	HANDLE hToken = nullptr;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	constexpr auto SE_DEBUG_PRIVILEGE = (20L);

	if (!OpenProcessToken(INVALID_HANDLE_VALUE, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
		goto Release;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
		goto Release;
	}

	if (ERROR_SUCCESS != GetLastError()) {
		tcout << TEXT("Privileges succeeded, but last error = 0x") << std::hex << GetLastError() << std::endl;
		goto Release;
	}

	tcout << TEXT("Debug Privileges Enabled!\n") << std::endl;

Release: if (hToken) CloseHandle(hToken);

	tcout << TEXT("Enter ProcessId: ");
	DWORD dwProcessId = 0;
	tcin >> dwProcessId;
	tcin.get();

	if (!DebugActiveProcess(dwProcessId)) {
		tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
		tcin.get();
		exit(-1);
	}
	else tcout << TEXT("Process attached!\n") << std::endl;

	HANDLE hProcess = nullptr;
	DEBUG_EVENT DbgEvent = { 0 };
	TCHAR FileName[MAX_PATH] = TEXT("");
	WIN32_FIND_DATA Data = { 0 };
	HMODULE hMod = nullptr;

	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);

	do {
		if (!WaitForDebugEvent(&DbgEvent, INFINITE)) {
			tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
			tcin.get();
			exit(-1);
		}

		switch (DbgEvent.dwDebugEventCode) {

		case EXCEPTION_DEBUG_EVENT:
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			case CREATE_THREAD_DEBUG_EVENT:
			tcout << TEXT(" dwThreadId: ") << DbgEvent.dwThreadId << TEXT(" (Start Address: 0x")
				<< DbgEvent.u.CreateThread.lpStartAddress << TEXT(", Name: )") << std::endl;
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			break;

		case LOAD_DLL_DEBUG_EVENT:
			GetFinalPathNameByHandle(DbgEvent.u.LoadDll.hFile, FileName, MAX_PATH, FILE_NAME_NORMALIZED);
			FindFirstFile(FileName, &Data);
			hMod = LoadLibrary(Data.cFileName);
			if (!hMod) hMod = LoadLibrary(FileName);
			tcout << Data.cFileName << TEXT(" - 0x") << hMod << std::endl;
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;

		case RIP_EVENT:
			break;

		default:
			break;
		}

		ContinueDebugEvent(DbgEvent.dwProcessId, DbgEvent.dwThreadId, DBG_CONTINUE);

	} while (DbgEvent.u.ExitProcess.dwExitCode != 0);

	tcin.get();

	CloseHandle(hProcess);

	if (!DebugActiveProcessStop(dwProcessId)) {
		tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
		tcin.get();
		exit(-1);
	}
	else tcout << TEXT("Process detached!") << std::endl;

	tcin.get();

	return 0;
}

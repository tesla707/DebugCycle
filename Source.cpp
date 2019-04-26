#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <iostream>

#ifdef UNICODE
#define tmain wmain
#define tcout std::wcout
#define tcin std::wcin
#define tcscmp wcscmp
#else
#define tmain main
#define tcout std::cout
#define tcin std::cin
#define tcscmp strcmp
#endif // !UNICODE

int tmain() {
	//====================================================================================================================
	//=============================================== Global values ======================================================
	//====================================================================================================================
	
	HANDLE hToken = nullptr, hSnapshop = nullptr, hProcess = nullptr;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	constexpr auto SE_DEBUG_PRIVILEGE = (20L);
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };
	DEBUG_EVENT DebugEvent = { 0 };
	TCHAR ProcessName[MAX_PATH] = TEXT(""), ModuleName[MAX_PATH] = TEXT("");
	WIN32_FIND_DATA Win32FindData = { 0 };
	HMODULE hModule[1024] = { 0 };
	MODULEINFO ModuleInfo = { 0 };
	DWORD dwProcessId = 0, cbNeeded = 0, ThreadExitCode = 0;

	//====================================================================================================================
	//============================================== Debug privileges ====================================================
	//====================================================================================================================

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

	tcout << TEXT("Debug privileges enabled!\n") << std::endl;

Release: if (hToken) CloseHandle(hToken);

	//====================================================================================================================
	//========================================= Searching processId and attach ===========================================
	//====================================================================================================================

	tcout << TEXT("Enter process name: ");
	tcin >> ProcessName;
	tcin.get();

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (tcscmp(ProcessEntry.szExeFile, ProcessName) == 0) {
				dwProcessId = ProcessEntry.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}

	CloseHandle(hSnapshop);

	if (!DebugActiveProcess(dwProcessId)) {
		tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
		tcin.get();
		exit(-1);
	}
	else tcout << TEXT("Process attached!\n") << std::endl;

	//====================================================================================================================	
	//====================================================================================================================
	//====================================================================================================================

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);

	if (EnumProcessModules(hProcess, hModule, sizeof(hModule), &cbNeeded))
		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			if (GetModuleFileNameEx(hProcess, hModule[i], ModuleName, sizeof(ModuleName) / sizeof(TCHAR))) {
				GetModuleInformation(hProcess, hModule[i], &ModuleInfo, sizeof(MODULEINFO));
				FindFirstFile(ModuleName, &Win32FindData);
				tcout << hModule[i] << TEXT(" - ") << Win32FindData.cFileName << std::endl;
			}

	CloseHandle(hProcess);

	//====================================================================================================================
	//====================================================================================================================
	//====================================================================================================================

	do {
		if (!WaitForDebugEvent(&DebugEvent, INFINITE)) {
			tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
			tcin.get();
			exit(-1);
		}

		switch (DebugEvent.dwDebugEventCode) {

		case EXCEPTION_DEBUG_EVENT:
			break;

		case CREATE_THREAD_DEBUG_EVENT:
				tcout << TEXT(" dwThreadId: ") << DebugEvent.dwThreadId << TEXT(" (Start address: 0x") <<
				DebugEvent.u.CreateThread.lpStartAddress << TEXT(", Name: ") << TEXT(")") << std::endl;

				//if ((INT)DebugEvent.u.CreateThread.lpStartAddress == 0x7710B370)
					//if (TerminateThread(DebugEvent.u.CreateThread.hThread, 0))
						//tcout << TEXT("\ndwThreadId: ") << DebugEvent.dwThreadId << TEXT(" {ntdll.DbgUiRemoteBreakin is terminated!") << std::endl;
			break;
			
		case CREATE_PROCESS_DEBUG_EVENT:
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			break;

		case LOAD_DLL_DEBUG_EVENT:
			//GetFinalPathNameByHandle(DbgEvent.u.LoadDll.hFile, FileName, MAX_PATH, FILE_NAME_NORMALIZED);
			//FindFirstFile(FileName, &Data);
			//hMod = GetModuleHandle(Data.cFileName);
			//tcout << Data.cFileName << TEXT(" - 0x") << hMod << std::endl;
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

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

		

	} while (DebugEvent.u.ExitProcess.dwExitCode != 0);

	//====================================================================================================================
	//============================================= Deattach and exit ====================================================
	//====================================================================================================================

	tcin.get();

	if (!DebugActiveProcessStop(dwProcessId)) {
		tcout << TEXT("Error: 0x") << std::hex << GetLastError() << std::endl;
		tcin.get();
		exit(-1);
	}
	else tcout << TEXT("Process detached!") << std::endl;

	tcin.get();

	return 0;
}

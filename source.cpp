#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Psapi.h>
#include <winternl.h>

#pragma comment (lib, "ntdll.lib")

void EnableDebugPrivilege(const _TCHAR *pName) {
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	HANDLE hToken = (HANDLE)NULL;

	if (!OpenProcessToken(INVALID_HANDLE_VALUE, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		_tprintf(_TEXT("OpenProcessToken failed, error = 0x%.X.\r\n"), GetLastError());
		goto Finish;
	}

	if (!LookupPrivilegeValue((const _TCHAR *)NULL, pName, &TokenPrivileges.Privileges[0].Luid)) {
		_tprintf(_TEXT("LookupPrivilegeValueW failed, error = 0x%.X.\r\n"), GetLastError());
		goto Finish;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		_tprintf(_TEXT("AdjustTokenPrivileges failed, error = 0x%.X.\r\n"), GetLastError());
		goto Finish;
	}

	if (ERROR_SUCCESS != GetLastError()) {
		_tprintf(_TEXT("AdjustTokenPrivileges succeeded, but last error is 0x%.X.\r\n"), GetLastError());
		goto Finish;
	}

	_tprintf(_TEXT("Debug Privileges Enabled!\r\n"));

Finish:
	if (hToken) {
		CloseHandle(hToken);
	}
}

int _tmain() {
	EnableDebugPrivilege(SE_DEBUG_NAME);

	HANDLE hProcess = (HANDLE)NULL, hThread = (HANDLE)NULL;
	HMODULE hModule = (HMODULE)NULL;
	DWORD dwProcessId = 0, dwThreadId = 0, OldProtect = 0, get_set_old_value = 0, set_new_value = 0xDEADC0DE, get_new_value = 0, get_new_old_value = 0, cbNeeded = 0;

	_tprintf(_TEXT("Enter pID: "));
	_tscanf_s(_TEXT("%u"), &dwProcessId);
	_gettchar();

	if (!(hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId))) {
		switch (GetLastError()) {
		case ERROR_ACCESS_DENIED:
			_tprintf(_TEXT("Access is denied, error = 0x%.X.\r\n"), GetLastError());
			PROCESS_PROTECTION_LEVEL_INFORMATION ProcProtLevel;
			GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &ProcProtLevel, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION));
			switch (ProcProtLevel.ProtectionLevel) {
			case PROTECTION_LEVEL_PPL_APP:
				_tprintf(_TEXT("The process is a third party app that is using process protection.\r\n"));
			default:
				_tprintf(_TEXT("For internal use only.\r\n"));
				break;
			}
			break;
		case ERROR_INVALID_PARAMETER:
			_tprintf(_TEXT("Incorrect pID, error = 0x%.X.\r\n"), GetLastError());
			break;
		default:
			_tprintf(_TEXT("Error = 0x%.X.\r\n"), GetLastError());
			break;
		}
		CloseHandle(hProcess);
		getchar();
		return EXIT_FAILURE;
	}

	K32EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded);

	WIN32_FIND_DATA FindData = { 0 };
	_TCHAR Path[MAX_PATH];
	GetModuleFileNameEx(hProcess, hModule, Path, sizeof(Path) / sizeof(_TCHAR));
	FindFirstFile(Path, &FindData);
	_tprintf(_TEXT("Module name: %s (hProcess: 0x%X)\r\n"), FindData.cFileName, HandleToLong(hProcess));

	MODULEINFO ModuleInfo = { 0 };
	K32GetModuleInformation(hProcess, hModule, &ModuleInfo, sizeof(ModuleInfo));
	_tprintf(_TEXT("AllocationBase: 0x%.16llX\r\nEntryPoint: 0x%.16llX\r\n"), (UINT64)ModuleInfo.lpBaseOfDll, (UINT64)ModuleInfo.EntryPoint);

	//===============================================================================================
	
	if (!VirtualProtectEx(hProcess, ModuleInfo.EntryPoint, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &OldProtect)) {
		_tprintf(_TEXT("Error = 0x%.X.\r\n"), GetLastError());
	}

	ReadProcessMemory(hProcess, ModuleInfo.EntryPoint, &get_set_old_value, sizeof(get_set_old_value), (ULONG_PTR)NULL);
	_tprintf(_TEXT("Old Bytes: %.8lX\r\n"), get_set_old_value);

	WriteProcessMemory(hProcess, ModuleInfo.EntryPoint, &set_new_value, sizeof(set_new_value), (ULONG_PTR)NULL);

	ReadProcessMemory(hProcess, ModuleInfo.EntryPoint, &get_new_value, sizeof(get_new_value), (ULONG_PTR)NULL);
	_tprintf(_TEXT("New Bytes: %.8lX\r\n"), get_new_value);

	WriteProcessMemory(hProcess, ModuleInfo.EntryPoint, &get_set_old_value, sizeof(get_set_old_value), (ULONG_PTR)NULL);

	ReadProcessMemory(hProcess, ModuleInfo.EntryPoint, &get_new_old_value, sizeof(get_new_old_value), (ULONG_PTR)NULL);
	_tprintf(_TEXT("New Old Bytes: %.8lX\r\n"), get_new_old_value);

	PROCESS_BASIC_INFORMATION pInfo = { 0 };
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pInfo, sizeof(pInfo), (PULONG)NULL);
	DWORD a = 0;
	ReadProcessMemory(hProcess, pInfo.PebBaseAddress, &a, sizeof(a), (ULONG_PTR)NULL);

	if (!VirtualProtectEx(hProcess, ModuleInfo.EntryPoint, sizeof(DWORD), OldProtect, &OldProtect)) {
		_tprintf(_TEXT("Error = 0x%.X.\r\n"), GetLastError());
	}

	//===============================================================================================

	CloseHandle(hThread);
	CloseHandle(hProcess);
	_gettchar();
	return EXIT_SUCCESS;
}

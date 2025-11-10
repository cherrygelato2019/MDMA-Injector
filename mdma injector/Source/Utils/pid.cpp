#include "pid.h"
#include "log.h"

namespace pid {

	bool is_correct_arch(HANDLE h_proc) {
		BOOL b_target = FALSE;
		if (!IsWow64Process(h_proc, &b_target)) { log_error("failed to check target architecture (0x%X)\n", GetLastError()); return false; }

		BOOL b_host = FALSE;
		IsWow64Process(GetCurrentProcess(), &b_host);

		return (b_target == b_host);
	}

	DWORD get_by_name(wchar_t* name) {
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot == INVALID_HANDLE_VALUE) return 0;

		if (Process32First(snapshot, &entry) == TRUE) {
			while (Process32Next(snapshot, &entry) == TRUE) {
				if (_wcsicmp(entry.szExeFile, name) == 0) { CloseHandle(snapshot); return entry.th32ProcessID; }
			}
		}

		CloseHandle(snapshot);
		return 0;
	}

	bool enable_debug_priv() {
		TOKEN_PRIVILEGES priv = { 0 };
		HANDLE h_token = NULL;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) return false;

		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) AdjustTokenPrivileges(h_token, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(h_token);
		return true;
	}

}


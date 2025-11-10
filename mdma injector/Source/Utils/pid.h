#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <string>

namespace pid {
	bool is_correct_arch(HANDLE h_proc);
	DWORD get_by_name(wchar_t* name);
	bool enable_debug_priv();
}


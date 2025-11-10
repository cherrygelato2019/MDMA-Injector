#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

using f_load_library_a = HINSTANCE(WINAPI*)(const char* lp_lib_filename);
using f_get_proc_address = FARPROC(WINAPI*)(HMODULE h_module, LPCSTR lp_proc_name);
using f_dll_entry_point = BOOL(WINAPI*)(void* h_dll, DWORD dw_reason, void* p_reserved);

#ifdef _WIN64
using f_rtl_add_function_table = BOOL(WINAPIV*)(PRUNTIME_FUNCTION function_table, DWORD entry_count, DWORD64 base_address);
#endif

struct manual_mapping_data {
	f_load_library_a p_load_library_a;
	f_get_proc_address p_get_proc_address;
#ifdef _WIN64
	f_rtl_add_function_table p_rtl_add_function_table;
#endif
	BYTE* p_base;
	HINSTANCE h_mod;
	DWORD fdw_reason_param;
	LPVOID reserved_param;
	BOOL seh_support;
};

bool manual_map_dll(HANDLE h_proc, BYTE* p_src_data, SIZE_T file_size, bool clear_header = true, bool clear_non_needed_sections = true, bool adjust_protections = true, bool seh_exception_support = true, DWORD fdw_reason = DLL_PROCESS_ATTACH, LPVOID lp_reserved = 0);

void __stdcall shellcode(manual_mapping_data* p_data);

extern "C" void shellcode_asm(manual_mapping_data* p_data);

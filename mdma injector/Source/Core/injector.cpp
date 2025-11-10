#include "injector.h"
#include "../Utils/log.h"

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

#define USE_ASM_SHELLCODE false

bool manual_map_dll(HANDLE h_proc, BYTE* p_src_data, SIZE_T file_size, bool clear_header, bool clear_non_needed_sections, bool adjust_protections, bool seh_exception_support, DWORD fdw_reason, LPVOID lp_reserved) {
	IMAGE_NT_HEADERS* p_old_nt_header = nullptr;
	IMAGE_OPTIONAL_HEADER* p_old_opt_header = nullptr;
	IMAGE_FILE_HEADER* p_old_file_header = nullptr;
	BYTE* p_target_base = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(p_src_data)->e_magic != 0x5A4D) { log_error("invalid pe signature\n"); return false; }

	p_old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(p_src_data + reinterpret_cast<IMAGE_DOS_HEADER*>(p_src_data)->e_lfanew);
	p_old_opt_header = &p_old_nt_header->OptionalHeader;
	p_old_file_header = &p_old_nt_header->FileHeader;

	if (p_old_file_header->Machine != CURRENT_ARCH) { log_error("architecture mismatch\n"); return false; }

	log_status("pe validation passed\n");

	p_target_base = reinterpret_cast<BYTE*>(VirtualAllocEx(h_proc, nullptr, p_old_opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!p_target_base) { log_error("failed to allocate memory in target (0x%X)\n", GetLastError()); return false; }

	log_info("base address -> 0x%p\n", p_target_base);

	DWORD old_protect = 0;
	VirtualProtectEx(h_proc, p_target_base, p_old_opt_header->SizeOfImage, PAGE_EXECUTE_READWRITE, &old_protect);

	manual_mapping_data data{ 0 };
	data.p_load_library_a = LoadLibraryA;
	data.p_get_proc_address = GetProcAddress;
#ifdef _WIN64
	data.p_rtl_add_function_table = (f_rtl_add_function_table)RtlAddFunctionTable;
#else 
	seh_exception_support = false;
#endif
	data.p_base = p_target_base;
	data.fdw_reason_param = fdw_reason;
	data.reserved_param = lp_reserved;
	data.seh_support = seh_exception_support;

	if (!WriteProcessMemory(h_proc, p_target_base, p_src_data, 0x1000, nullptr)) { log_error("failed to write pe header (0x%X)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); return false; }

	IMAGE_SECTION_HEADER* p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
	for (UINT i = 0; i != p_old_file_header->NumberOfSections; ++i, ++p_section_header) {
		if (p_section_header->SizeOfRawData) {
			if (!WriteProcessMemory(h_proc, p_target_base + p_section_header->VirtualAddress, p_src_data + p_section_header->PointerToRawData, p_section_header->SizeOfRawData, nullptr)) { log_error("failed to map section (0x%x)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); return false; }
		}
	}

	log_status("sections mapped\n");

	BYTE* p_mapping_data_alloc = reinterpret_cast<BYTE*>(VirtualAllocEx(h_proc, nullptr, sizeof(manual_mapping_data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!p_mapping_data_alloc) { log_error("failed to allocate mapping data (0x%X)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); return false; }

	if (!WriteProcessMemory(h_proc, p_mapping_data_alloc, &data, sizeof(manual_mapping_data), nullptr)) { log_error("failed to write mapping data (0x%X)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_mapping_data_alloc, 0, MEM_RELEASE); return false; }

	void* p_shellcode = VirtualAllocEx(h_proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!p_shellcode) { log_error("failed to allocate shellcode (0x%X)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_mapping_data_alloc, 0, MEM_RELEASE); return false; }

#if USE_ASM_SHELLCODE
	void* shellcode_func = (void*)&shellcode_asm;
	log_status("using asm shellcode\n");
#else
	void* shellcode_func = (void*)&shellcode;
	log_status("using c++ shellcode\n");
#endif

	if (!WriteProcessMemory(h_proc, p_shellcode, shellcode_func, 0x1000, nullptr)) { log_error("failed to write shellcode (0x%X)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_mapping_data_alloc, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE); return false; }

	log_info("shellcode address -> 0x%p\n", p_shellcode);
	log_info("mapping data -> 0x%p\n", p_mapping_data_alloc);

	HANDLE h_thread = CreateRemoteThread(h_proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(p_shellcode), p_mapping_data_alloc, 0, nullptr);
	if (!h_thread) { log_error("failed to create thread (0x%X)\n", GetLastError()); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_mapping_data_alloc, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE); return false; }
	CloseHandle(h_thread);

	log_status("waiting for shellcode execution...\n");

	HINSTANCE h_check = NULL;
	while (!h_check) {
		DWORD exit_code = 0;
		GetExitCodeProcess(h_proc, &exit_code);
		if (exit_code != STILL_ACTIVE) { log_error("target process crashed (exit code: %d)\n", exit_code); return false; }

		manual_mapping_data data_checked{ 0 };
		ReadProcessMemory(h_proc, p_mapping_data_alloc, &data_checked, sizeof(data_checked), nullptr);
		h_check = data_checked.h_mod;

		if (h_check == (HINSTANCE)0x404040) { log_error("invalid mapping pointer\n"); VirtualFreeEx(h_proc, p_target_base, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_mapping_data_alloc, 0, MEM_RELEASE); VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE); return false; }
		else if (h_check == (HINSTANCE)0x505050) { log_error("seh exception support failed\n"); }

		Sleep(10);
	}

	log_info("dll loaded at -> 0x%p\n", h_check);

	BYTE* empty_buffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (empty_buffer == nullptr) { log_error("failed to allocate cleanup buffer\n"); return false; }
	memset(empty_buffer, 0, 1024 * 1024 * 20);

	if (clear_header) {
		if (!WriteProcessMemory(h_proc, p_target_base, empty_buffer, 0x1000, nullptr)) { log_error("failed to clear pe header\n"); }
		else { log_status("pe header cleared\n"); }
	}

	if (clear_non_needed_sections) {
		p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
		for (UINT i = 0; i != p_old_file_header->NumberOfSections; ++i, ++p_section_header) {
			if (p_section_header->Misc.VirtualSize) {
				if ((seh_exception_support ? 0 : strcmp((char*)p_section_header->Name, ".pdata") == 0) || strcmp((char*)p_section_header->Name, ".rsrc") == 0 || strcmp((char*)p_section_header->Name, ".reloc") == 0) {
					if (!WriteProcessMemory(h_proc, p_target_base + p_section_header->VirtualAddress, empty_buffer, p_section_header->Misc.VirtualSize, nullptr)) { log_error("failed to clear section %s\n", p_section_header->Name); }
					else { log_status("cleared section %s\n", p_section_header->Name); }
				}
			}
		}
	}

	if (adjust_protections) {
		p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
		for (UINT i = 0; i != p_old_file_header->NumberOfSections; ++i, ++p_section_header) {
			if (p_section_header->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD new_protection = PAGE_READONLY;

				if ((p_section_header->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) { new_protection = PAGE_READWRITE; }
				else if ((p_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) { new_protection = PAGE_EXECUTE_READ; }
				
				if (VirtualProtectEx(h_proc, p_target_base + p_section_header->VirtualAddress, p_section_header->Misc.VirtualSize, new_protection, &old)) { log_status("section %s protection -> 0x%lX\n", (char*)p_section_header->Name, new_protection); }
			}
		}
		DWORD old = 0;
		VirtualProtectEx(h_proc, p_target_base, IMAGE_FIRST_SECTION(p_old_nt_header)->VirtualAddress, PAGE_READONLY, &old);
	}

	WriteProcessMemory(h_proc, p_shellcode, empty_buffer, 0x1000, nullptr);
	VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE);
	VirtualFreeEx(h_proc, p_mapping_data_alloc, 0, MEM_RELEASE);

	free(empty_buffer);
	return true;
}

#define RELOC_FLAG32(rel_info) ((rel_info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(rel_info) ((rel_info >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall shellcode(manual_mapping_data* p_data) {
	if (!p_data) { p_data->h_mod = (HINSTANCE)0x404040; return; }

	BYTE* p_base = p_data->p_base;
	auto* p_opt = &reinterpret_cast<IMAGE_NT_HEADERS*>(p_base + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)p_base)->e_lfanew)->OptionalHeader;

	auto _load_library_a = p_data->p_load_library_a;
	auto _get_proc_address = p_data->p_get_proc_address;
#ifdef _WIN64
	auto _rtl_add_function_table = p_data->p_rtl_add_function_table;
#endif
	auto _dll_main = reinterpret_cast<f_dll_entry_point>(p_base + p_opt->AddressOfEntryPoint);

	BYTE* location_delta = p_base - p_opt->ImageBase;
	if (location_delta) {
		if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* p_reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* p_reloc_end = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(p_reloc_data) + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (p_reloc_data < p_reloc_end && p_reloc_data->SizeOfBlock) {
				UINT amount_of_entries = (p_reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* p_relative_info = reinterpret_cast<WORD*>(p_reloc_data + 1);

				for (UINT i = 0; i != amount_of_entries; ++i, ++p_relative_info) {
					if (RELOC_FLAG(*p_relative_info)) {
						UINT_PTR* p_patch = reinterpret_cast<UINT_PTR*>(p_base + p_reloc_data->VirtualAddress + ((*p_relative_info) & 0xFFF));
						*p_patch += reinterpret_cast<UINT_PTR>(location_delta);
					}
				}
				p_reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(p_reloc_data) + p_reloc_data->SizeOfBlock);
			}
		}
	}

	if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* p_import_descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (p_import_descr->Name) {
			char* sz_mod = reinterpret_cast<char*>(p_base + p_import_descr->Name);
			HINSTANCE h_dll = _load_library_a(sz_mod);

			ULONG_PTR* p_thunk_ref = reinterpret_cast<ULONG_PTR*>(p_base + p_import_descr->OriginalFirstThunk);
			ULONG_PTR* p_func_ref = reinterpret_cast<ULONG_PTR*>(p_base + p_import_descr->FirstThunk);

			if (!p_import_descr->OriginalFirstThunk) p_thunk_ref = p_func_ref;

			for (; *p_thunk_ref; ++p_thunk_ref, ++p_func_ref) {
				if (IMAGE_SNAP_BY_ORDINAL(*p_thunk_ref)) { *p_func_ref = (ULONG_PTR)_get_proc_address(h_dll, reinterpret_cast<char*>(*p_thunk_ref & 0xFFFF)); }
				else {
					auto* p_import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(p_base + (*p_thunk_ref));
					*p_func_ref = (ULONG_PTR)_get_proc_address(h_dll, p_import->Name);
				}
			}
			++p_import_descr;
		}
	}

	if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* p_tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* p_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(p_tls->AddressOfCallBacks);
		for (; p_callback && *p_callback; ++p_callback) (*p_callback)(p_base, DLL_PROCESS_ATTACH, nullptr);
	}

	bool exception_support_failed = false;

#ifdef _WIN64
	if (p_data->seh_support) {
		auto excep = p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_rtl_add_function_table(reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(p_base + excep.VirtualAddress), excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)p_base)) { exception_support_failed = true; }
		}
	}
#endif

	_dll_main(p_base, p_data->fdw_reason_param, p_data->reserved_param);

	if (exception_support_failed) p_data->h_mod = reinterpret_cast<HINSTANCE>(0x505050);
	else p_data->h_mod = reinterpret_cast<HINSTANCE>(p_base);
}
#pragma runtime_checks( "", restore )
#pragma optimize( "", on )

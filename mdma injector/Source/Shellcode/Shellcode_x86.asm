.686
.model flat, stdcall
option casemap:none

.code

; manual_mapping_data structure offsets (x86):
; +0x00: p_load_library_a
; +0x04: p_get_proc_address
; +0x08: p_base
; +0x0C: h_mod
; +0x10: fdw_reason_param
; +0x14: reserved_param
; +0x18: seh_support

IMAGE_DOS_SIGNATURE EQU 5A4Dh
IMAGE_NT_SIGNATURE EQU 4550h
IMAGE_DIRECTORY_ENTRY_IMPORT EQU 1
IMAGE_DIRECTORY_ENTRY_BASERELOC EQU 5
IMAGE_DIRECTORY_ENTRY_TLS EQU 9
IMAGE_REL_BASED_HIGHLOW EQU 3

shellcode_asm PROC stdcall p_data:DWORD
    pushad
    pushfd
    
    mov ebx, p_data
    test ebx, ebx
    jz error_exit
    
    mov esi, [ebx + 8]
    movzx eax, word ptr [esi]
    cmp ax, IMAGE_DOS_SIGNATURE
    jne error_exit
    
    mov eax, [esi + 3Ch]
    add eax, esi
    mov edi, eax
    add edi, 18h
    
    mov eax, [edi + 1Ch]
    mov ecx, esi
    sub ecx, eax
    
    test ecx, ecx
    jz skip_relocations
    
    mov eax, [edi + 0A0h]
    test eax, eax
    jz skip_relocations
    
    add eax, esi
    push eax
    mov edx, [edi + 0A4h]
    add edx, eax
    push edx
    
process_reloc_block:
    pop edx
    pop eax
    cmp eax, edx
    jae skip_relocations
    
    push eax
    push edx
    mov edx, [eax + 4]
    test edx, edx
    jz cleanup_reloc
    
    sub edx, 8
    shr edx, 1
    lea ebp, [eax + 8]
    
process_reloc_entry:
    test edx, edx
    jz next_reloc_block
    
    movzx edi, word ptr [ebp]
    push edx
    mov edx, edi
    shr edx, 12
    cmp edx, IMAGE_REL_BASED_HIGHLOW
    jne skip_entry
    
    and edi, 0FFFh
    mov edx, [eax]
    add edx, esi
    add edx, edi
    add [edx], ecx
    
skip_entry:
    pop edx
    add ebp, 2
    dec edx
    jmp process_reloc_entry
    
next_reloc_block:
    pop edx
    pop eax
    add eax, [eax + 4]
    push eax
    push edx
    jmp process_reloc_block
    
cleanup_reloc:
    pop edx
    pop eax
    
skip_relocations:
    mov eax, [esi + 3Ch]
    add eax, esi
    lea edi, [eax + 18h]
    
    mov eax, [edi + 78h]
    test eax, eax
    jz skip_imports
    
    add eax, esi
    push eax
    
process_import_descriptor:
    pop eax
    mov edx, [eax + 0Ch]
    test edx, edx
    jz skip_imports
    
    push eax
    add edx, esi
    push edx
    call dword ptr [ebx]
    test eax, eax
    jz next_import_descriptor
    
    mov edi, eax
    pop eax
    push eax
    
    mov edx, [eax]
    test edx, edx
    jz use_first_thunk
    
    add edx, esi
    jmp got_thunk_ref
    
use_first_thunk:
    mov edx, [eax + 10h]
    add edx, esi
    
got_thunk_ref:
    push edx
    mov edx, [eax + 10h]
    add edx, esi
    push edx
    
process_import_function:
    pop edx
    pop ecx
    mov eax, [ecx]
    test eax, eax
    jz next_import_descriptor
    
    push ecx
    push edx
    test eax, eax
    js import_by_ordinal
    
    add eax, esi
    add eax, 2
    push eax
    push edi
    call dword ptr [ebx + 4]
    pop edx
    mov [edx], eax
    jmp next_import_function
    
import_by_ordinal:
    and eax, 0FFFFh
    push eax
    push edi
    call dword ptr [ebx + 4]
    pop edx
    mov [edx], eax
    
next_import_function:
    pop ecx
    add ecx, 4
    push ecx
    add edx, 4
    push edx
    jmp process_import_function
    
next_import_descriptor:
    pop eax
    pop eax
    pop eax
    add eax, 14h
    push eax
    jmp process_import_descriptor
    
skip_imports:
    mov eax, [esi + 3Ch]
    add eax, esi
    lea edi, [eax + 18h]
    
    mov eax, [edi + 0C0h]
    test eax, eax
    jz skip_tls
    
    add eax, esi
    mov eax, [eax + 0Ch]
    test eax, eax
    jz skip_tls
    
process_tls_callback:
    mov ecx, [eax]
    test ecx, ecx
    jz skip_tls
    
    push eax
    push 0
    push 1
    push esi
    call ecx
    pop eax
    add eax, 4
    jmp process_tls_callback
    
skip_tls:
    mov eax, [esi + 3Ch]
    add eax, esi
    lea edi, [eax + 18h]
    
    mov eax, [edi + 10h]
    add eax, esi
    push dword ptr [ebx + 14h]
    push dword ptr [ebx + 10h]
    push esi
    call eax
    
    mov [ebx + 0Ch], esi
    
exit_shellcode:
    popfd
    popad
    ret 4
    
error_exit:
    mov dword ptr [ebx + 0Ch], 404040h
    jmp exit_shellcode
    
shellcode_asm ENDP

END

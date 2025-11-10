.code

; manual_mapping_data structure offsets (x64):
; +0x00: p_load_library_a
; +0x08: p_get_proc_address
; +0x10: p_rtl_add_function_table
; +0x18: p_base
; +0x20: h_mod
; +0x28: fdw_reason_param
; +0x30: reserved_param
; +0x38: seh_support

IMAGE_DOS_SIGNATURE EQU 5A4Dh
IMAGE_NT_SIGNATURE EQU 4550h
IMAGE_DIRECTORY_ENTRY_IMPORT EQU 1
IMAGE_DIRECTORY_ENTRY_BASERELOC EQU 5
IMAGE_DIRECTORY_ENTRY_TLS EQU 9
IMAGE_DIRECTORY_ENTRY_EXCEPTION EQU 3
IMAGE_REL_BASED_DIR64 EQU 10

shellcode_asm PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 28h
    
    test rcx, rcx
    jz error_exit
    
    mov rbx, rcx
    mov r12, [rbx + 18h]
    
    movzx eax, word ptr [r12]
    cmp ax, IMAGE_DOS_SIGNATURE
    jne error_exit
    
    mov eax, [r12 + 3Ch]
    add rax, r12
    mov r13, rax
    add r13, 18h
    
    mov r14, [r13 + 18h]
    mov rdi, r12
    sub rdi, r14
    
    test rdi, rdi
    jz skip_relocations
    
    mov rax, [r13 + 98h]
    test rax, rax
    jz skip_relocations
    
    add rax, r12
    mov rsi, rax
    mov ecx, [r13 + 9Ch]
    add rcx, rax
    
process_reloc_block:
    cmp rsi, rcx
    jae skip_relocations
    
    mov edx, [rsi + 4]
    test edx, edx
    jz skip_relocations
    
    sub edx, 8
    shr edx, 1
    lea r8, [rsi + 8]
    
process_reloc_entry:
    test edx, edx
    jz next_reloc_block
    
    movzx eax, word ptr [r8]
    mov r9d, eax
    shr r9d, 12
    cmp r9d, IMAGE_REL_BASED_DIR64
    jne skip_entry
    
    and eax, 0FFFh
    mov r9d, [rsi]
    add r9, r12
    add r9, rax
    mov rax, [r9]
    add rax, rdi
    mov [r9], rax
    
skip_entry:
    add r8, 2
    dec edx
    jmp process_reloc_entry
    
next_reloc_block:
    mov edx, [rsi + 4]
    add rsi, rdx
    jmp process_reloc_block
    
skip_relocations:
    mov rax, [r13 + 78h]
    test rax, rax
    jz skip_imports
    
    add rax, r12
    mov rsi, rax
    
process_import_descriptor:
    mov eax, [rsi + 0Ch]
    test eax, eax
    jz skip_imports
    
    add rax, r12
    mov rcx, rax
    call qword ptr [rbx]
    test rax, rax
    jz next_import_descriptor
    
    mov r14, rax
    mov eax, [rsi]
    test eax, eax
    jz use_first_thunk
    
    add rax, r12
    jmp got_thunk_ref
    
use_first_thunk:
    mov eax, [rsi + 10h]
    add rax, r12
    
got_thunk_ref:
    mov r8, rax
    mov eax, [rsi + 10h]
    add rax, r12
    mov r9, rax
    
process_import_function:
    mov rax, [r8]
    test rax, rax
    jz next_import_descriptor
    
    mov r10, rax
    shl r10, 1
    jc import_by_ordinal
    
    add rax, r12
    add rax, 2
    mov rcx, r14
    mov rdx, rax
    call qword ptr [rbx + 8]
    mov [r9], rax
    jmp next_import_function
    
import_by_ordinal:
    and rax, 0FFFFh
    mov rcx, r14
    mov rdx, rax
    call qword ptr [rbx + 8]
    mov [r9], rax
    
next_import_function:
    add r8, 8
    add r9, 8
    jmp process_import_function
    
next_import_descriptor:
    add rsi, 14h
    jmp process_import_descriptor
    
skip_imports:
    mov rax, [r13 + 0C8h]
    test rax, rax
    jz skip_tls
    
    add rax, r12
    mov rax, [rax + 18h]
    test rax, rax
    jz skip_tls
    
    mov rsi, rax
    
process_tls_callback:
    mov rax, [rsi]
    test rax, rax
    jz skip_tls
    
    mov rcx, r12
    mov edx, 1
    xor r8, r8
    call rax
    
    add rsi, 8
    jmp process_tls_callback
    
skip_tls:
    mov al, [rbx + 38h]
    test al, al
    jz skip_seh
    
    mov rax, [r13 + 0B8h]
    test rax, rax
    jz skip_seh
    
    mov ecx, [r13 + 0BCh]
    test ecx, ecx
    jz skip_seh
    
    add rax, r12
    mov rcx, rax
    shr ecx, 3
    mov edx, ecx
    mov r8, r12
    call qword ptr [rbx + 10h]
    test eax, eax
    jnz skip_seh
    
    mov qword ptr [rbx + 20h], 505050h
    jmp call_dllmain
    
skip_seh:
call_dllmain:
    mov rax, [r13 + 10h]
    add rax, r12
    mov rcx, r12
    mov edx, [rbx + 28h]
    mov r8, [rbx + 30h]
    call rax
    
    mov rax, [rbx + 20h]
    cmp rax, 505050h
    je exit_shellcode
    
    mov rax, r12
    mov [rbx + 20h], rax
    
exit_shellcode:
    add rsp, 28h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
error_exit:
    mov qword ptr [rbx + 20h], 404040h
    jmp exit_shellcode
    
shellcode_asm ENDP

END

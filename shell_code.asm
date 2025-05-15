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




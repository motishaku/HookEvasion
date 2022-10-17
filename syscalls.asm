.code

MyNtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
MyNtAllocateVirtualMemory endp

MyNtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
MyNtProtectVirtualMemory endp

MyNtCreateThreadEx proc
		mov r10, rcx
		mov eax, 0C1h
		syscall
		ret
MyNtCreateThreadEx endp

MyNtWaitForSingleObject proc
		mov r10, rcx
		mov eax, 4
		syscall
		ret
MyNtWaitForSingleObject endp

MyNtQueryInformationFile proc
		mov r10, rcx
		mov eax, 11h
		syscall
		ret
MyNtQueryInformationFile endp

MyNtCreateFile proc
		mov r10, rcx
		mov eax, 55h
		syscall
		ret
MyNtCreateFile endp

MyNtReadFile proc
		mov r10, rcx
		mov eax, 6
		syscall
		ret
MyNtReadFile endp
end
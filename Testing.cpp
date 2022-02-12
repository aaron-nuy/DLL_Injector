#include <iostream>
#include <Windows.h>
#include <WinUser.h>
#include <string>
#include <thread>
#include <string.h>
#include <TlHelp32.h>
#include <stdlib.h>


DWORD Win32ReturnProcessID(const std::wstring& pProcessName) {
	HANDLE hToolHelper = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x0);
	PROCESSENTRY32 p32ProcessEntry = { 0 };
	p32ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	if (hToolHelper == NULL) {
		throw std::exception("Couldn't take snapchot of running processes\n");
	}

	if (!Process32First(hToolHelper, &p32ProcessEntry)) {
		CloseHandle(hToolHelper);
		throw std::exception("Unexpected error\n");
	}

	do {
		if (!wcscmp(p32ProcessEntry.szExeFile, pProcessName.c_str())) {
			CloseHandle(hToolHelper);
			std::wcout << p32ProcessEntry.szExeFile << ": " << p32ProcessEntry.th32ProcessID << std::endl;
			return p32ProcessEntry.th32ProcessID;
		}

	} while (Process32Next(hToolHelper, &p32ProcessEntry));

	throw std::exception("Couldn't find process with that name\n");
}




BOOL Win32InjectDLLToProcess(DWORD pID, const std::wstring& myDllPath) {


	DWORD fullPathLength;
	DWORD fullPathBufferSize;
	TCHAR fullPathBuffer[MAX_PATH] = { 0 };
	fullPathLength = GetFullPathNameW(myDllPath.c_str(), MAX_PATH, fullPathBuffer, NULL) + 1;
	fullPathBufferSize = fullPathLength * sizeof(TCHAR);





	HANDLE hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (hProcessHandle == NULL) {
		throw std::exception("Could not open process\n");
	}

	HMODULE hKernelHandle = GetModuleHandleA("kernel32.dll");
	if (hKernelHandle == NULL) {
		CloseHandle(hProcessHandle);
		throw std::exception("Could not load library\n");
	}


	LPVOID lpLoadLib = reinterpret_cast<LPVOID>(GetProcAddress(hKernelHandle, "LoadLibraryW"));
	if (lpLoadLib == NULL) {
		CloseHandle(hProcessHandle);
		CloseHandle(hKernelHandle);
		throw std::exception("Could not load function\n");
	}
				

	LPVOID lpLoadLocation = VirtualAllocEx(hProcessHandle, NULL, fullPathBufferSize,
					MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpLoadLocation == NULL) {
		CloseHandle(hProcessHandle);
		CloseHandle(hKernelHandle);
		throw std::exception("Could not allocate\n");
	}


	if (!WriteProcessMemory(hProcessHandle, lpLoadLocation, fullPathBuffer,
		fullPathBufferSize, NULL)) {
		CloseHandle(hProcessHandle);
		CloseHandle(hKernelHandle);
		throw std::exception("Could not write memory\n");  
	}


	HANDLE hRemoteThread = CreateRemoteThread(hProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLib,
								lpLoadLocation,0,NULL);
	if (hRemoteThread == NULL) {

		CloseHandle(hProcessHandle);
		CloseHandle(hKernelHandle);
		throw std::exception("Could not create thread\n");
	}

	WaitForSingleObject(hRemoteThread, INFINITE);


	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcessHandle, lpLoadLocation, 0, MEM_RELEASE);
	CloseHandle(hProcessHandle);
	CloseHandle(hKernelHandle);
	return TRUE;
}



int main()
{
	std::wstring myDll;
	std::cout << "Dll Name: ";
	std::wcin >> myDll;
	std::cout << std::endl;


	std::wstring processName;
	std::cout << "Target Process: ";
	std::wcin >> processName;
	std::cout << std::endl;

	try {
		DWORD PID = Win32ReturnProcessID(processName);
		if(Win32InjectDLLToProcess(PID, myDll )) std::cout << "Injected Successfully" << std::endl;
	}
	catch (std::exception& e) {
		std::cerr << e.what();
	}
}

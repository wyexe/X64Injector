#include <Windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h> // CreateToolhelp32Snapshot

#include <Shlwapi.h> // Method PathFileExistsW
#pragma comment(lib,"Shlwapi.lib")

template<typename _fnPtr>
static std::wstring MakeTextTo(_In_ CONST std::wstring& wsText, _In_ _fnPtr fnPtr)
{
	std::wstring tmpText;
	for (auto& itm : wsText)
		tmpText.push_back(static_cast<wchar_t>(fnPtr(itm)));

	return tmpText;
}

std::wstring MakeTextToLower(_In_ CONST std::wstring& wsText)
{
	return MakeTextTo(wsText, tolower);
}

std::wstring MakeTextToUpper(_In_ CONST std::wstring& wsText)
{
	return MakeTextTo(wsText, toupper);
}

// Get Pid
DWORD GetPid_For_ProcName(_In_ CONST std::wstring& wsProcName)
{
	HANDLE hThSnap32 = NULL;
	PROCESSENTRY32W pe32;

	hThSnap32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hThSnap32 == INVALID_HANDLE_VALUE)
		return NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32FirstW(hThSnap32, &pe32))
	{
		::CloseHandle(hThSnap32);
		return NULL;
	}

	do
	{
		//比对进程名
		if (MakeTextToLower(pe32.szExeFile) == MakeTextToLower(wsProcName))
		{
			DWORD dwPid = pe32.th32ProcessID;
			::CloseHandle(hThSnap32);
			return dwPid;
		}

	} while (Process32NextW(hThSnap32, &pe32));
	::CloseHandle(hThSnap32);
	return NULL;
}

BOOL LoadRemoteDLL(_In_ DWORD dwPid, _In_ LPCWSTR pwszDllPath)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		std::wcout << L"Permission Denied! try to Run as Administrator!" << std::endl;
		return FALSE;
	}

	auto dwDLLSize = (wcslen(pwszDllPath) + 1) * 2;

	// Alloc in Target Process
	LPVOID pAllocMem = VirtualAllocEx(hProcess, NULL, dwDLLSize, MEM_COMMIT, PAGE_READWRITE);
	if (pAllocMem == nullptr)
	{
		std::wcout << L"Alloc Virtual Memory in Process Faild! Err=" << ::GetLastError() << std::endl;
		return FALSE;
	}

	// Copy Text 'DLL Path' to Target Process Memory
	BOOL bRetCode = WriteProcessMemory(hProcess, (PVOID)pAllocMem, (PVOID)pwszDllPath, dwDLLSize, NULL);
	if (!bRetCode)
	{
		std::wcout << L"WriteProcessMemory in Process Faild! Err=" << ::GetLastError() << std::endl;
		return FALSE;
	}

	// Get kernel32.dll Addr
	HMODULE hmKernel32 = ::GetModuleHandle(TEXT("Kernel32"));
	if (hmKernel32 == NULL)
	{
		std::wcout << L"GetModuleHandle 'Kernel32' Faild!" << std::endl;
		return FALSE;
	}

	PTHREAD_START_ROUTINE pfnThreadRrn = (PTHREAD_START_ROUTINE)GetProcAddress(hmKernel32, "LoadLibraryW");
	if (pfnThreadRrn == NULL)
	{
		std::wcout << L"UnExist 'LoadLibraryW' in Kernel32!" << std::endl;
		return FALSE;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRrn, (PVOID)pAllocMem, 0, NULL);
	if (hThread == NULL)
	{
		std::wcout << L"CreateRemoteThread Faild! Err=" << ::GetLastError() << std::endl;
		return FALSE;
	}

	//等待远程线程终止  
	WaitForSingleObject(hThread, INFINITE);

	if (pAllocMem != NULL)
		VirtualFreeEx(hProcess, (PVOID)pAllocMem, 0, MEM_RELEASE);
	if (hThread != NULL)
		CloseHandle(hThread);
	if (hProcess != NULL)
		CloseHandle(hProcess);

	std::wcout << L"Succ!" << std::endl;
	return TRUE;
}

int main()
{
	for(;;)
	{
		std::wcout << L"Typeing Process Name:";

		std::wstring wsProcName;
		std::getline(std::wcin, wsProcName);

		DWORD dwPid = GetPid_For_ProcName(wsProcName);
		if (dwPid == NULL)
		{
			std::wcout << L"UnExist Process if ProcName = " << wsProcName << std::endl;
			continue;
		}

		std::wcout << L"Pid=" << dwPid << L", Typeing DLL Path:";

		std::wstring wsPath;
		std::getline(std::wcin, wsPath);

		if (!PathFileExistsW(wsPath.c_str()))
		{
			std::wcout << L"DLL:" << wsPath << L" UnExist!";
			continue;
		}

		LoadRemoteDLL(dwPid, wsPath.c_str());
	}
}
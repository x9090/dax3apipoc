#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <comdef.h>
#include "FileOpLock.h"

BOOL SetOpLock(LPCWSTR Target, LPCWSTR ShareMode, LPVOID Handler) {
	

	FileOpLock* oplock = nullptr; oplock = FileOpLock::CreateLock(Target, ShareMode, (FileOpLock::UserCallback)Handler);
	if (oplock != nullptr)
	{
		oplock->WaitForLock(INFINITE);

		delete oplock;
	}
	else
	{
		printf("Error creating oplock\n");
		return 1;
	}

}
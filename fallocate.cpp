#include <windows.h>
#include <errno.h>
#include <io.h>
#include "fallocate.h"

// Check windows
#if !defined(_WIN32) && !defined(_WIN16) && !defined(_WIN64)
#if WIN16 || _WIN16_ || ___WIN16 || ___WIN16__ || WIN32 || _WIN32_ || ___WIN32 || ___WIN32__ || WIN64 || _WIN64_ || ___WIN64 || ___WIN64__
#if WIN64 || _WIN64_ || ___WIN64 || ___WIN64__
#define _WIN64
#elif WIN16 || _WIN16_ || ___WIN16 || ___WIN16__
#define _WIN16
#else
#define _WIN32
#endif
#endif
#endif

// Check GCC
#if !defined(_WIN32) && !defined(_WIN16) && !defined(_WIN64)
#if __GNUC__
#if __x86_64__ || __ppc64__
#define _WIN64
#else
#define _WIN32
#endif
#endif
#endif

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

typedef struct _LLUID {
  DWORD LowPart;
  LONG  HighPart;
} LLUID, *PLLUID;

typedef struct _LLUID FAR * LPLLUID;

typedef struct _LLUID_AND_ATTRIBUTES {
  LLUID  Luid;
  DWORD Attributes;
} LLUID_AND_ATTRIBUTES, *PLLUID_AND_ATTRIBUTES;

typedef struct _LLUID_AND_ATTRIBUTES FAR *LPLLUID_AND_ATTRIBUTES;

typedef struct _LTOKEN_PRIVILEGES {
  DWORD               PrivilegeCount;
  LLUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} LTOKEN_PRIVILEGES, *PLTOKEN_PRIVILEGES;

typedef struct _LTOKEN_PRIVILEGES FAR *LPLTOKEN_PRIVILEGES;

#ifndef TOKEN_QUERY
#define TOKEN_QUERY 0x00000008
#endif

#ifndef TOKEN_ADJUST_PRIVILEGES
#define TOKEN_ADJUST_PRIVILEGES 0x00000020
#endif

#ifndef SE_MANAGE_VOLUME_NAME
#define SE_MANAGE_VOLUME_NAME "SeManageVolumePrivilege"
#endif

#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER ((DWORD)0xFFFF)
#endif

#ifndef FSCTL_SET_SPARSE
#define FSCTL_SET_SPARSE 0x000900c4
#endif

#ifndef FSCTL_SET_ZERO_DATA
#define FSCTL_SET_ZERO_DATA 0x000980c8
#endif

typedef union _LLARGE_INTEGER {
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } u;
  LONGLONG QuadPart;
} LLARGE_INTEGER;

typedef union _LLARGE_INTEGER * PLLARGE_INTEGER;
typedef union _LLARGE_INTEGER FAR * LPLLARGE_INTEGER;

typedef struct _LFILE_ZERO_DATA_INFORMATION {
  LLARGE_INTEGER FileOffset;
  LLARGE_INTEGER BeyondFinalZero;
} LFILE_ZERO_DATA_INFORMATION, *PLFILE_ZERO_DATA_INFORMATION;

typedef struct _LFILE_ZERO_DATA_INFORMATION FAR * LPLFILE_ZERO_DATA_INFORMATION;

typedef BOOL (WINAPI *POpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL (WINAPI FAR *LPOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef HANDLE (WINAPI *PGetCurrentProcess)();
typedef HANDLE (WINAPI FAR *LPGetCurrentProcess)();

typedef BOOL (WINAPI *PAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PLTOKEN_PRIVILEGES NewState, DWORD BufferLength, PLTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
typedef BOOL (WINAPI FAR *LPAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PLTOKEN_PRIVILEGES NewState, DWORD BufferLength, PLTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

typedef BOOL (WINAPI *PLookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLLUID lpLuid);
typedef BOOL (WINAPI FAR *LPLookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLLUID lpLuid);

typedef BOOL (WINAPI *PSetFilePointerEx)(HANDLE hFile, LLARGE_INTEGER liDistanceToMove, PLLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod);
typedef BOOL (WINAPI FAR *LPSetFilePointerEx)(HANDLE hFile, LLARGE_INTEGER liDistanceToMove, PLLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod);

typedef DWORD (WINAPI *PSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef DWORD (WINAPI FAR *LPSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

typedef BOOL (WINAPI *PSetEndOfFile)(HANDLE hFile);
typedef BOOL (WINAPI FAR *LPSetEndOfFile)(HANDLE hFile);

typedef BOOL (WINAPI * PSetFileValidData)(HANDLE hFile, LONGLONG ValidDataLength);
typedef BOOL (WINAPI FAR * LPSetFileValidData)(HANDLE hFile, LONGLONG ValidDataLength);

typedef BOOL (WINAPI *PDeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI FAR *LPDeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

class Fallocate
{
private:
	static int instanceCount;
	static HMODULE hAdvapi32;
	static HMODULE hKernel32;
	static FARPROC fpOpenProcessToken;
	static FARPROC fpGetCurrentProcess;
	static FARPROC fpLookupPrivilegeValueA;
	static FARPROC fpAdjustTokenPrivileges;
	static FARPROC fpSetFilePointerEx;
	static FARPROC fpSetFilePointer;
	static FARPROC fpSetEndOfFile;
	static FARPROC fpSetFileValidData;
	static FARPROC fpDeviceIoControl;

	static int SetPos(HANDLE hFile, LLARGE_INTEGER liDistanceToMove, PLLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
	{
		if(fpSetFilePointerEx)
		{
			if (!((LPSetFilePointerEx)fpSetFilePointerEx)(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod))
				return EBADF;
		}
		else if(fpSetFilePointer)
		{
			LONG resHigh = liDistanceToMove.u.HighPart;
			DWORD resLow = ((LPSetFilePointer)fpSetFilePointer)(hFile, liDistanceToMove.u.LowPart, &resHigh, dwMoveMethod);
			if (resLow == INVALID_SET_FILE_POINTER)
				return EBADF;

			if(lpNewFilePointer != NULL)
			{
				lpNewFilePointer->u.LowPart = resLow;
				lpNewFilePointer->u.HighPart = resHigh;
			}
		}
		else
		{
			return ENOSYS; // TODO: what now?
		}
		
		return 0;
	}
public:
	Fallocate()
	{
		if(instanceCount == 0)
		{
			hAdvapi32 = LoadLibrary(TEXT("Advapi32"));
			hKernel32 = LoadLibrary(TEXT("Kernel32"));

			if(hAdvapi32 != 0)
			{
				fpOpenProcessToken = GetProcAddress(hAdvapi32, "OpenProcessToken");
				fpLookupPrivilegeValueA = GetProcAddress(hAdvapi32, "LookupPrivilegeValueA");

				if(fpLookupPrivilegeValueA == 0)
				{
					fpLookupPrivilegeValueA = GetProcAddress(hAdvapi32, "LookupPrivilegeValue");
				}

				fpAdjustTokenPrivileges = GetProcAddress(hAdvapi32, "AdjustTokenPrivileges");
			}

			if(hKernel32 != 0)
			{
				fpGetCurrentProcess = GetProcAddress(hKernel32, "GetCurrentProcess");
				fpSetFilePointer = GetProcAddress(hKernel32, "SetFilePointer");
				fpSetFilePointerEx = GetProcAddress(hKernel32, "SetFilePointerEx");
				fpSetEndOfFile = GetProcAddress(hKernel32, "SetEndOfFile");
				fpSetFileValidData = GetProcAddress(hKernel32, "SetFileValidData");
				fpDeviceIoControl = GetProcAddress(hKernel32, "DeviceIoControl");
			}

			instanceCount++;

			HANDLE cur_token = NULL;
			LTOKEN_PRIVILEGES new_tp;
			LLUID luid;
			if(fpOpenProcessToken)
			{          
				if (!((LPOpenProcessToken)fpOpenProcessToken) (((LPGetCurrentProcess)fpGetCurrentProcess)(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
					&cur_token))
				{
					return;
				}
			}

			if(fpLookupPrivilegeValueA)
			{
				if (!((LPLookupPrivilegeValueA)fpLookupPrivilegeValueA) (NULL, SE_MANAGE_VOLUME_NAME, &luid))
				{
					CloseHandle(cur_token); //I'd have used ON_BLOCK_EXIT, but want to keep dependency count down :)
					return;
				}
			}
			
			memset(&new_tp, 0, sizeof(LTOKEN_PRIVILEGES));
			new_tp.PrivilegeCount = 1;
			new_tp.Privileges[0].Luid = luid;
			new_tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if(fpAdjustTokenPrivileges)
			{
				if (!((LPAdjustTokenPrivileges)fpAdjustTokenPrivileges) (cur_token, FALSE, &new_tp, sizeof(LTOKEN_PRIVILEGES), NULL, NULL))
				{
					CloseHandle (cur_token);
					return;
				}
			}

			if(cur_token)
				CloseHandle(cur_token);
		}
	}

	static int fallocate(int fd, off_t offset, off_t len)
	{
		DWORD zeroLow = 0;
		LONG zeroHigh = 0;
		LLARGE_INTEGER zeroPos;
		LLARGE_INTEGER oldPos;
		LLARGE_INTEGER endPos;
		LLARGE_INTEGER newPos;
		LLARGE_INTEGER minusOne;
		static const DWORD DWORD_MAX=0xFFFFFFFF;
		int setPosRes;

		minusOne.u.HighPart = 0xFFFFFFFF;
		minusOne.u.LowPart = 0xFFFFFFFF;

		memset(&zeroPos, '\0', sizeof zeroPos);

		#ifndef q4_WCE
			HANDLE h = (HANDLE) _get_osfhandle(fd);
		#else
			HANDLE h = (HANDLE)fd;
		#endif //q4_WCE

		if(offset < 0 || len < 0)
		{
			return EINVAL;
		}

		// get original position.
		setPosRes = SetPos(h, zeroPos, &oldPos, FILE_CURRENT);
		if(setPosRes)
		{
			return setPosRes;
		}

		// get current file end.
		setPosRes = SetPos(h, zeroPos, &endPos, FILE_END);
		if(setPosRes)
		{
			return setPosRes;
		}

		// jump to offset.
		LLARGE_INTEGER tmpPos;
		tmpPos.u.LowPart = offset;
		tmpPos.u.HighPart = 0;

		setPosRes = SetPos(h, tmpPos, NULL, FILE_BEGIN);
		if(setPosRes)
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return setPosRes;
		}

		// jump to length.
		tmpPos.u.LowPart = len;
		tmpPos.u.HighPart = 0;
		
		setPosRes = SetPos(h, tmpPos, &newPos, FILE_CURRENT);
		if(setPosRes)
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return setPosRes;
		}

		if(fpSetEndOfFile)
		{
			if(endPos.u.HighPart < newPos.u.HighPart
				|| (endPos.u.HighPart == newPos.u.HighPart && endPos.u.LowPart < newPos.u.LowPart))
			{
				if(!((LPSetEndOfFile)fpSetEndOfFile)(h))
				{
					SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
					return ENOSPC;
				}
			}
		}

		LONGLONG sizeToReserve = newPos.QuadPart - endPos.QuadPart;
		if(fpSetFileValidData)
		{
			if (((LPSetFileValidData)fpSetFileValidData)(h, sizeToReserve)!=0)
			{
				SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on success.
				return 0; //Success!
			}
		}

		if(fpDeviceIoControl)
		{
			//Bummer. Can't expand the file this way - now try sparse files	
			DWORD temp=0;
			//Mark the file as sparse.
   			if (((LPDeviceIoControl)fpDeviceIoControl)(h, FSCTL_SET_SPARSE, NULL, 0, NULL, 0,  &temp, NULL)!=0)
			{				
				LFILE_ZERO_DATA_INFORMATION range;
				range.FileOffset.QuadPart = endPos.QuadPart;
				range.BeyondFinalZero.QuadPart = newPos.QuadPart;
				//Actually set the sparse range.
				if (((LPDeviceIoControl)fpDeviceIoControl)(h, FSCTL_SET_ZERO_DATA, &range, sizeof(range), NULL, 0, &temp, NULL))
				{
					SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on success.
					return 0; //Done
				}					
			}
		}

		setPosRes = SetPos(h, minusOne, &tmpPos, FILE_END);
		if(setPosRes)
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return setPosRes;
		}

		char initializer_buf [1] = {1};
		DWORD written=0;
		if (!WriteFile(h, initializer_buf, 1, &written, NULL))
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return ENOSPC;
		}

		SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on success.
		return 0;
	}

	static int posix_fallocate(int fd, off_t offset, off_t len)
	{
		DWORD zeroLow = 0;
		LONG zeroHigh = 0;
		LLARGE_INTEGER zeroPos;
		LLARGE_INTEGER oldPos;
		LLARGE_INTEGER endPos;
		LLARGE_INTEGER newPos;
		LLARGE_INTEGER minusOne;
		static const DWORD DWORD_MAX=0xFFFFFFFF;
		int setPosRes;

		minusOne.u.HighPart = 0xFFFFFFFF;
		minusOne.u.LowPart = 0xFFFFFFFF;

		memset(&zeroPos, '\0', sizeof zeroPos);

		#ifndef q4_WCE
			HANDLE h = (HANDLE) _get_osfhandle(fd);
		#else
			HANDLE h = (HANDLE)fd;
		#endif //q4_WCE

		if(offset < 0 || len < 0)
		{
			return EINVAL;
		}

		// get original position.
		setPosRes = SetPos(h, zeroPos, &oldPos, FILE_CURRENT);
		if(setPosRes)
		{
			return setPosRes;
		}

		// get current file end.
		setPosRes = SetPos(h, zeroPos, &endPos, FILE_END);
		if(setPosRes)
		{
			return setPosRes;
		}

		// jump to offset.
		LLARGE_INTEGER tmpPos;
		tmpPos.u.LowPart = offset;
		tmpPos.u.HighPart = 0;

		setPosRes = SetPos(h, tmpPos, NULL, FILE_BEGIN);
		if(setPosRes)
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return setPosRes;
		}

		// jump to length.
		tmpPos.u.LowPart = len;
		tmpPos.u.HighPart = 0;
		
		setPosRes = SetPos(h, tmpPos, &newPos, FILE_CURRENT);
		if(setPosRes)
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return setPosRes;
		}

		if(fpSetEndOfFile)
		{
			if(endPos.u.HighPart < newPos.u.HighPart
				|| (endPos.u.HighPart == newPos.u.HighPart && endPos.u.LowPart < newPos.u.LowPart))
			{
				if(!((LPSetEndOfFile)fpSetEndOfFile)(h))
				{
					SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
					return ENOSPC;
				}
			}
		}

		setPosRes = SetPos(h, minusOne, &tmpPos, FILE_END);
		if(setPosRes)
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return setPosRes;
		}

		char initializer_buf [1] = {1};
		DWORD written=0;
		if (!WriteFile(h, initializer_buf, 1, &written, NULL))
		{
			SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on error.
			return ENOSPC;
		}

		SetPos(h, oldPos, NULL, FILE_BEGIN); // restore position on success.
		return 0;
	}

	~Fallocate()
	{
		if(instanceCount > 0)
		{
			instanceCount--;

			if(instanceCount == 0)
			{
				fpOpenProcessToken = NULL;
				fpLookupPrivilegeValueA = NULL;
				fpGetCurrentProcess = NULL;
				fpAdjustTokenPrivileges = NULL;
				fpSetFilePointer = NULL;
				fpSetFilePointerEx = NULL;
				fpSetEndOfFile = NULL;
				fpSetFileValidData = NULL;
				fpDeviceIoControl = NULL;

				if(hKernel32 != 0)
				{
					FreeLibrary(hKernel32);
					hKernel32 = 0;
				}

				if(hAdvapi32 != 0)
				{
					FreeLibrary(hAdvapi32);
					hAdvapi32 = 0;
				}
			}
		}
	}
};

int Fallocate::instanceCount = 0;
HMODULE Fallocate::hAdvapi32 = 0;
HMODULE Fallocate::hKernel32 = 0;
FARPROC Fallocate::fpOpenProcessToken = NULL;
FARPROC Fallocate::fpLookupPrivilegeValueA = NULL;
FARPROC Fallocate::fpGetCurrentProcess = NULL;
FARPROC Fallocate::fpAdjustTokenPrivileges = NULL;
FARPROC Fallocate::fpSetFilePointer = NULL;
FARPROC Fallocate::fpSetFilePointerEx = NULL;
FARPROC Fallocate::fpSetEndOfFile = NULL;
FARPROC Fallocate::fpSetFileValidData = NULL;
FARPROC Fallocate::fpDeviceIoControl = NULL;

static Fallocate _fallocate;

int posix_fallocate(int fd, off_t offset, off_t len)
{
	return Fallocate::posix_fallocate(fd, offset, len);
}


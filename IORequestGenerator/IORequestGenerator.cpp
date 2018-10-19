/*

DISKSPD

Copyright(c) Microsoft Corporation
All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

//FUTURE EXTENSION: make it compile with /W4

// Windows 7
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include "common.h"
#include "IORequestGenerator.h"

#include <stdio.h>
#include <stdlib.h>
#include <Winioctl.h>   //DISK_GEOMETRY
#include <windows.h>
#include <stddef.h>

#include <Wmistr.h>     //WNODE_HEADER

#include <iostream>		//IO stream
#include <fstream>
#include <sstream>
#include <iomanip>

#include <chrono>
#include <thread>
#include <vector>

#include "etw.h"
#include <assert.h>

// Flags for RtlFlushNonVolatileMemory
#ifndef FLUSH_NV_MEMORY_IN_FLAG_NO_DRAIN
#define FLUSH_NV_MEMORY_IN_FLAG_NO_DRAIN    (0x00000001)
#endif

/*****************************************************************************/
// gets size of a dynamic volume, return zero on failure
//
UINT64 GetDynamicPartitionSize(HANDLE hFile)
{
    assert(NULL != hFile && INVALID_HANDLE_VALUE != hFile);

    UINT64 size = 0;
    VOLUME_DISK_EXTENTS diskExt = {0};
    PVOLUME_DISK_EXTENTS pDiskExt = &diskExt;
    DWORD bytesReturned;

    DWORD status = ERROR_SUCCESS;
    BOOL rslt;

    OVERLAPPED ovlp = {0};
    ovlp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ovlp.hEvent == nullptr)
    {
        PrintError("ERROR: Failed to create event (error code: %u)\n", GetLastError());
        return 0;
    }

    rslt = DeviceIoControl(hFile,
                            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                            NULL,
                            0,
                            pDiskExt,
                            sizeof(VOLUME_DISK_EXTENTS),
                            &bytesReturned,
                            &ovlp);
    if (!rslt) {
        status = GetLastError();
        if (status == ERROR_MORE_DATA) {
            status = ERROR_SUCCESS;

            bytesReturned = sizeof(VOLUME_DISK_EXTENTS) + ((pDiskExt->NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT));
            pDiskExt = (PVOLUME_DISK_EXTENTS)LocalAlloc(LPTR, bytesReturned);

            if (pDiskExt)
            {
                rslt = DeviceIoControl(hFile,
                                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                    NULL,
                                    0,
                                    pDiskExt,
                                    bytesReturned,
                                    &bytesReturned,
                                    &ovlp);
                if (!rslt)
                {
                    status = GetLastError();
                    if (status == ERROR_IO_PENDING)
                    {
                        if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
                        {
                            status = GetLastError();
                            PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", status);
                        }
                        else
                        {
                            status = ERROR_SUCCESS;
                            assert(pDiskExt->NumberOfDiskExtents <= 1);
                        }
                    }
                    else
                    {
                        PrintError("ERROR: Could not obtain dynamic volume extents (error code: %u)\n", status);
                    }
                }
            }
            else
            {
                status = GetLastError();
                PrintError("ERROR: Could not allocate memory (error code: %u)\n", status);
            }
        }
        else if (status == ERROR_IO_PENDING)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
            {
                status = GetLastError();
                PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", status);
            }
            else
            {
                status = ERROR_SUCCESS;
                assert(pDiskExt->NumberOfDiskExtents <= 1);
            }
        }
        else
        {
            PrintError("ERROR: Could not obtain dynamic volume extents (error code: %u)\n", status);
        }
    }
    else
    {
        assert(pDiskExt->NumberOfDiskExtents <= 1);
    }

    if (status == ERROR_SUCCESS)
    {
        for (DWORD n = 0; n < pDiskExt->NumberOfDiskExtents; n++) {
            size += pDiskExt->Extents[n].ExtentLength.QuadPart;
        }
    }

    if (pDiskExt && (pDiskExt != &diskExt)) {
        LocalFree(pDiskExt);
    }
    CloseHandle(ovlp.hEvent);

    return size;
}

/*****************************************************************************/
// gets partition size, return zero on failure
//
UINT64 GetPartitionSize(HANDLE hFile)
{
    assert(NULL != hFile && INVALID_HANDLE_VALUE != hFile);

    PARTITION_INFORMATION_EX pinf;
    OVERLAPPED ovlp = {};

    ovlp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ovlp.hEvent == nullptr)
    {
        PrintError("ERROR: Failed to create event (error code: %u)\n", GetLastError());
        return 0;
    }

    DWORD rbcnt = 0;
    DWORD status = ERROR_SUCCESS;
    UINT64 size = 0;

    if (!DeviceIoControl(hFile,
                        IOCTL_DISK_GET_PARTITION_INFO_EX,
                        NULL,
                        0,
                        &pinf,
                        sizeof(pinf),
                        &rbcnt,
                        &ovlp)
        )
    {
        status = GetLastError();
        if (status == ERROR_IO_PENDING)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
            {
                PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", GetLastError());
            }
            else
            {
                size = pinf.PartitionLength.QuadPart;
            }
        }
        else
        {
            size = GetDynamicPartitionSize(hFile);
        }
    }
    else
    {
        size = pinf.PartitionLength.QuadPart;
    }

    CloseHandle(ovlp.hEvent);

    return size;
}

/*****************************************************************************/
// gets physical drive size, return zero on failure
//
UINT64 GetPhysicalDriveSize(HANDLE hFile)
{
    assert(NULL != hFile && INVALID_HANDLE_VALUE != hFile);

    DISK_GEOMETRY_EX geom;
    OVERLAPPED ovlp = {};

    ovlp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ovlp.hEvent == nullptr)
    {
        PrintError("ERROR: Failed to create event (error code: %u)\n", GetLastError());
        return 0;
    }

    DWORD rbcnt = 0;
    DWORD status = ERROR_SUCCESS;
    BOOL rslt;

    rslt = DeviceIoControl(hFile,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL,
        0,
        &geom,
        sizeof(geom),
        &rbcnt,
        &ovlp);

    if (!rslt)
    {
        status = GetLastError();
        if (status == ERROR_IO_PENDING)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
            {
                PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", GetLastError());
            }
            else
            {
                rslt = TRUE;
            }
        }
        else
        {
            PrintError("ERROR: Could not obtain drive geometry (error code: %u)\n", status);
        }
    }

    CloseHandle(ovlp.hEvent);

    if (!rslt)
    {
        return 0;
    }

    return (UINT64)geom.DiskSize.QuadPart;
}

/*****************************************************************************/
// activates specified privilege in process token
//
bool SetPrivilege(LPCSTR pszPrivilege, LPCSTR pszErrorPrefix = "ERROR:")
{
    TOKEN_PRIVILEGES TokenPriv;
    HANDLE hToken = INVALID_HANDLE_VALUE;
    DWORD dwError;
    bool fOk = true;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        PrintError("%s Error opening process token (error code: %u)\n", pszErrorPrefix, GetLastError());
        fOk = false;
        goto cleanup;
    }

    TokenPriv.PrivilegeCount = 1;
    TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(nullptr, pszPrivilege, &TokenPriv.Privileges[0].Luid))
    {
        PrintError("%s Error looking up privilege value %s (error code: %u)\n", pszErrorPrefix, pszPrivilege, GetLastError());
        fOk = false;
        goto cleanup;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPriv, 0, nullptr, nullptr))
    {
        PrintError("%s Error adjusting token privileges for %s (error code: %u)\n", pszErrorPrefix, pszPrivilege, GetLastError());
        fOk = false;
        goto cleanup;
    }

    if (ERROR_SUCCESS != (dwError = GetLastError()))
    {
        PrintError("%s Error adjusting token privileges for %s (error code: %u)\n", pszErrorPrefix, pszPrivilege, dwError);
        fOk = false;
        goto cleanup;
    }

cleanup:
    if (hToken != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hToken);
    }
    
    return fOk;
}

BOOL
DisableLocalCache(
    HANDLE h
)
/*++
Routine Description:

    Disables local caching of I/O to a file by SMB. All reads/writes will flow to the server.

Arguments:

    h - Handle to the file

Return Value:

    Returns ERROR_SUCCESS (0) on success, nonzero error code on failure.

--*/
{
    DWORD BytesReturned = 0;
    OVERLAPPED Overlapped = { 0 };
    DWORD Status = ERROR_SUCCESS;
    BOOL Success = false;

    Overlapped.hEvent = CreateEvent(nullptr, true, false, nullptr);
    if (!Overlapped.hEvent)
    {
        return GetLastError();
    }

#ifndef FSCTL_DISABLE_LOCAL_BUFFERING
#define FSCTL_DISABLE_LOCAL_BUFFERING   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 174, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

    Success = DeviceIoControl(h,
        FSCTL_DISABLE_LOCAL_BUFFERING,
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &Overlapped);

    if (!Success) {
        Status = GetLastError();
    }

    if (!Success && Status == ERROR_IO_PENDING)
    {
        if (!GetOverlappedResult(h, &Overlapped, &BytesReturned, true))
        {
            Status = GetLastError();
        }
        else
        {
            Status = (DWORD) Overlapped.Internal;
        }
    }

    if (Overlapped.hEvent)
    {
        CloseHandle(Overlapped.hEvent);
    }

    return Status;
}

/*****************************************************************************/
// structures and global variables
//
struct ETWEventCounters g_EtwEventCounters;

__declspec(align(4)) static LONG volatile g_lRunningThreadsCount = 0;   //must be aligned on a 32-bit boundary, otherwise InterlockedIncrement
                                                                        //and InterlockedDecrement will fail on 64-bit systems

static BOOL volatile g_bRun;                    //used for letting threads know that they should stop working

typedef NTSTATUS (__stdcall *NtQuerySysInfo)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
static NtQuerySysInfo g_pfnNtQuerySysInfo;

typedef VOID (__stdcall *RtlCopyMemNonTemporal)(VOID UNALIGNED *, VOID UNALIGNED *, SIZE_T);
static RtlCopyMemNonTemporal g_pfnRtlCopyMemoryNonTemporal;

typedef NTSTATUS (__stdcall *RtlFlushNvMemory)(PVOID, PVOID, SIZE_T, ULONG);
static RtlFlushNvMemory g_pfnRtlFlushNonVolatileMemory;

typedef NTSTATUS(__stdcall *RtlGetNvToken)(PVOID, SIZE_T, PVOID *);
static RtlGetNvToken g_pfnRtlGetNonVolatileToken;

typedef NTSTATUS(__stdcall *RtlFreeNvToken)(PVOID);
static RtlFreeNvToken g_pfnRtlFreeNonVolatileToken;

static PRINTF g_pfnPrintOut = nullptr;
static PRINTF g_pfnPrintError = nullptr;
static PRINTF g_pfnPrintVerbose = nullptr;

static BOOL volatile g_bThreadError = FALSE;    //true means that an error has occured in one of the threads
BOOL volatile g_bTracing = TRUE;                //true means that ETW is turned on

// TODO: is this still needed?
__declspec(align(4)) static LONG volatile g_lGeneratorRunning = 0;  //used to detect if GenerateRequests is already running

static BOOL volatile g_bError = FALSE;                              //true means there was fatal error during intialization and threads shouldn't perform their work


std::mutex mReadWriteEvent; // Mutex to protect this vector
std::vector<sDiskioTypeGroup1> vReadIO;
std::vector<sDiskioTypeGroup1> vWriteIO;

extern HANDLE g_hAbortEvent;



/*****************************************************************************/
// wrapper for pfnPrintOut. printf cannot be used directly, because IORequestGenerator.dll
// may be consumed by gui app which doesn't have stdout
static void print(const char *format, ...)
{
    assert(NULL != format);

    if( NULL != g_pfnPrintOut )
    {
        va_list listArg;
        va_start(listArg, format);
        g_pfnPrintOut(format, listArg);
        va_end(listArg);
    }
}

/*****************************************************************************/
// wrapper for pfnPrintError. fprintf(stderr) cannot be used directly, because IORequestGenerator.dll
// may be consumed by gui app which doesn't have stdout
void PrintError(const char *format, ...)
{
    assert(NULL != format);

    if( NULL != g_pfnPrintError )
    {
        va_list listArg;

        va_start(listArg, format);
        g_pfnPrintError(format, listArg);
        va_end(listArg);
    }
}

/*****************************************************************************/
// prints the string only if verbose mode is set to true
//
static void printfv(bool fVerbose, const char *format, ...)
{
    assert(NULL != format);

    if( NULL != g_pfnPrintVerbose && fVerbose )
    {
        va_list argList;
        va_start(argList, format);
        g_pfnPrintVerbose(format, argList);
        va_end(argList);
    }
}

/*****************************************************************************/
// thread for gathering ETW data (etw functions are defined in etw.cpp)
//
DWORD WINAPI etwThreadFunc(LPVOID cookie)
{
    UNREFERENCED_PARAMETER(cookie);

    g_bTracing = TRUE;
	printf("ETW Thread Func -----------------------------\n");
    BOOL result = TraceEvents();

	printf("Stop ETW -----------------------------\n");
    g_bTracing = FALSE;

    return result ? 0 : 1;
}
/*****************************************************************************/
// thread for gathering ETW data (etw functions are defined in etw.cpp)
//
DWORD WINAPI etwDebug(LPVOID cookie)
{
	////UNREFERENCED_PARAMETER(cookie);
	sDebugArgs DebugArgs = *((sDebugArgs*)cookie);
	sDiskioTypeGroup1 DiskioTypeGroup1;
	clock_t begin_time = clock();
	FILE * pFile;
	errno_t err = fopen_s(&pFile, DebugArgs.logfile.c_str(), "w");
	static UINT32 index = 0;
	while (g_bTracing)
	{
		if (vReadIO.size() > 0) {
			std::lock_guard<std::mutex> lg(mReadWriteEvent); 
			DiskioTypeGroup1 = vReadIO[vReadIO.size() - 1];
			fprintf(pFile, "%lu	%f	%lu	%lu	%s	%lu	%lu	\n",
				++index,
				clock() / (double)CLOCKS_PER_SEC,
				DiskioTypeGroup1.HighResResponseTime,
				DiskioTypeGroup1.DiskNumber,
				"Read",
				(DiskioTypeGroup1.ByteOffset) / 512,
				(DiskioTypeGroup1.TransferSize) / 512);
			if (DebugArgs.bVerbose)
			{
				printf("%f	%5lu	%10s	%16lu	%5lu\n",
					clock() / (double)CLOCKS_PER_SEC,
					DiskioTypeGroup1.DiskNumber,
					"Read",
					(DiskioTypeGroup1.ByteOffset) / 512,
					(DiskioTypeGroup1.TransferSize) / 512);
			}
			vReadIO.pop_back();
		}
		if (vWriteIO.size() > 0) {
			std::lock_guard<std::mutex> lg(mReadWriteEvent); 
			DiskioTypeGroup1 = vWriteIO[vWriteIO.size() - 1];
			fprintf(pFile, "%lu	%f	%lu	%lu	%s	%lu	%lu	\n",
				++index,
				clock() / (double)CLOCKS_PER_SEC,
				DiskioTypeGroup1.HighResResponseTime,
				DiskioTypeGroup1.DiskNumber,
				"Write",
				(DiskioTypeGroup1.ByteOffset) / 512,
				(DiskioTypeGroup1.TransferSize) / 512);

			if (DebugArgs.bVerbose)
			{
				printf("%f	%5lu	%10s	%16lu	%5lu\n",
					clock() / (double)CLOCKS_PER_SEC,
					DiskioTypeGroup1.DiskNumber,
					"Write",
					(DiskioTypeGroup1.ByteOffset) / 512,
					(DiskioTypeGroup1.TransferSize) / 512);
			}
			vWriteIO.pop_back();
		}
	}
	fclose(pFile);
	return 1;
}

bool IORequestGenerator::GenerateIORequests(Profile& profile, PRINTF pPrintOut, PRINTF pPrintError, PRINTF pPrintVerbose, struct Synchronization *sync)
{
	g_pfnPrintOut = pPrintOut;
	g_pfnPrintError = pPrintError;
	g_pfnPrintVerbose = pPrintVerbose;

	HANDLE hEtwThread, hDebug;
	memset(&g_EtwEventCounters, 0, sizeof(struct ETWEventCounters));  // reset all etw event counters
	bool fUseETW = profile.GetEtwEnabled();            //true if user wants ETW
	printfv(profile.GetVerbose(), "starting trace session\n");
	//
	// start etw session
	//
	printf("Disk  |  Request  |     Sector   | Length\n");
	TRACEHANDLE hTraceSession = NULL;

	hTraceSession = StartETWSession(profile);
	if (NULL == hTraceSession)
	{
		PrintError("Could not start ETW session\n");
		//_TerminateWorkerThreads(vhThreads);
		return false;
	}
	hEtwThread = CreateThread(NULL, 64 * 1024, etwThreadFunc, NULL, 0, NULL);
	if (NULL == hEtwThread)
	{
		PrintError("Warning: unable to create thread for ETW session\n");
		//_TerminateWorkerThreads(vhThreads);
		return false;
	}
	sDebugArgs DebugArgs = { profile.GetLogFile(),profile.GetVerbose() };
	hDebug = CreateThread(NULL, 0, etwDebug, &DebugArgs, 0, NULL);
	if (NULL == hDebug)
	{
		PrintError("Warning: unable to create thread for ETW session\n");
		//_TerminateWorkerThreads(vhThreads);
		return false;
	}

	

	assert(NULL != sync->hStopEvent);
	UINT32 timeOut = (profile.GetTimeSpan() > 0) ? 1000 * profile.GetTimeSpan() : INFINITE;
	DWORD dwWaitStatus = WaitForSingleObject(sync->hStopEvent, timeOut);
	if (WAIT_OBJECT_0 != dwWaitStatus && WAIT_TIMEOUT != dwWaitStatus)
	{
		printf("Error during WaitForSingleObject\n");
		return FALSE;
	}

	//Stop ETW session
	PEVENT_TRACE_PROPERTIES pETWSession = NULL;

	//printfv(profile.GetVerbose(), "stopping ETW session\n");
	pETWSession = StopETWSession(hTraceSession);
	if (NULL == pETWSession)
	{
		PrintError("Error stopping ETW session\n");
		return false;
	}

	WaitForSingleObject(hEtwThread, INFINITE);
	WaitForSingleObject(hDebug, INFINITE);
	//TerminateThread(hDebug, INFINITE);
	if (NULL != hEtwThread)
	{
		CloseHandle(hEtwThread);
	}
	if (NULL != hDebug)
	{
		CloseHandle(hDebug);
	}

	printf( "Read count %lu\n", g_EtwEventCounters.ullIORead);
	printf("Write count %lu\n", g_EtwEventCounters.ullIOWrite);
	printf("tracing events\n");
	return true;
}

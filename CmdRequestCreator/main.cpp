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

// CmdRequestCreator.cpp : Defines the entry point for the console application.
//

#include "main.h"
#include <windows.h>
#include <stdlib.h>
#include <assert.h>
#include "common.h"
#include "errors.h"
#include "CmdLineParser.h"
#include "IORequestGenerator.h"

/*****************************************************************************/
// global variables
 HANDLE g_hAbortEvent = NULL;     // handle to the 'abort' event
                                        // it allows stopping I/O Request Generator in the middle of its work
                                        // the results of its work will be passed to the Results Parser
static HANDLE g_hEventStarted = NULL;   // event signalled to notify that the actual (measured) test is to be started
static HANDLE g_hEventFinished = NULL;  // event signalled to notify that the actual test has finished

/*****************************************************************************/
// wrapper for printf. printf cannot be used directly, because IORequestGenerator.dll
// may be consumed by gui app which doesn't have stdout
void WINAPI PrintOut(const char *format, va_list args)
{
    vprintf(format, args);
}

/*****************************************************************************/
// wrapper for fprintf. fprintf cannot be used directly, because IORequestGenerator.dll
// may be consumed by gui app which doesn't have stdout
void WINAPI PrintError(const char *format, va_list args)
{
    vfprintf(stderr, format, args);
}

/*****************************************************************************/
BOOL WINAPI ctrlCRoutine(DWORD dwCtrlType)
{
    if( CTRL_C_EVENT == dwCtrlType )
    {
        printf("\n*** Interrupted by Ctrl-C. Stopping I/O Request Generator. ***\n");
        if( !SetEvent(g_hAbortEvent) )
        {
            fprintf(stderr, "Warning: Setting abort event failed (error code: %u)\n", GetLastError());
        }
        SetConsoleCtrlHandler(ctrlCRoutine, FALSE);

        //indicate that the signal has been handled
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/*****************************************************************************/
int __cdecl main(int argc, const char* argv[])
{
	struct Synchronization synch;        //sychronization structure
	synch.ulStructSize = sizeof(synch);
	synch.hStopEvent = NULL;
	synch.hStartEvent = NULL;

	CmdLineParser cmdLineParser;
	Profile profile;
	if (!cmdLineParser.ParseCmdInfo(argc, argv, &profile))
	{
		return ERROR_PARSE_CMD_LINE;
	}
	//
// create abort event if stop event is not explicitly provided by the user (otherwise use the stop event)
//

	if (NULL == synch.hStopEvent)
	{
		synch.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (NULL == synch.hStopEvent)
		{
			fprintf(stderr, "Unable to create an abort event for CTRL+C\n");
			//FUTURE EXTENSION: change error code
			return 1;
		}
	}
	g_hAbortEvent = synch.hStopEvent;   // set abort event to either stop event provided by user or the just created event

    //
    // capture ctrl+c
    //
    if( !SetConsoleCtrlHandler(ctrlCRoutine, TRUE) )
    {
        fprintf(stderr, "Unable to set CTRL+C routine\n");
        //FUTURE EXTENSION: change error code
        return 1;
    }

    //TraceLoggingRegister(g_hEtwProvider);

    IORequestGenerator ioGenerator;
	//Profile profile;
	//profile.SetVerbose(true);
	profile.SetEtwDiskIO(true);
	if (!ioGenerator.GenerateIORequests(profile, (PRINTF)PrintOut, (PRINTF)PrintError, (PRINTF)PrintOut, &synch ))
	{
		fprintf(stderr, "Error generating I/O requests\n");
		return 1;
	}
	//TraceLoggingUnregister(g_hEtwProvider);

    if( g_hEventStarted )
    {
        CloseHandle(g_hEventStarted);
    }
    if( NULL != g_hEventFinished )
    {
        CloseHandle(g_hEventFinished);
    }

    return 0;
}
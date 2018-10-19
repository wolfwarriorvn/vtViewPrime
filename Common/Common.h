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

#pragma once

#include <windows.h>
#include <TraceLoggingProvider.h>
#include <TraceLoggingActivity.h>
#include <evntrace.h>
#include <ctime>
#include <vector>
#include <Winternl.h>   //ntdll.dll
#include <assert.h>


using namespace std;

//TRACELOGGING_DECLARE_PROVIDER(g_hEtwProvider);

// versioning material. for simplicity in consumption, please ensure that the date string
// parses via the System.Datetime constructor as follows (in Powershell):
//
//      [datetime] "string"
//
// this should result in a valid System.Datetime object, rendered like:
//
//      Monday, June 16, 2014 12:00:00 AM

#define DISKSPD_RELEASE_TAG ""
#define DISKSPD_REVISION    "a"

#define DISKSPD_MAJOR       2
#define DISKSPD_MINOR       0
#define DISKSPD_BUILD       21
#define DISKSPD_QFE         0

#define DISKSPD_MAJORMINOR_VER_STR(x,y,z) #x "." #y "." #z
#define DISKSPD_MAJORMINOR_VERSION_STRING(x,y,z) DISKSPD_MAJORMINOR_VER_STR(x,y,z)
#define DISKSPD_MAJORMINOR_VERSION_STR DISKSPD_MAJORMINOR_VERSION_STRING(DISKSPD_MAJOR, DISKSPD_MINOR, DISKSPD_BUILD)

#define DISKSPD_NUMERIC_VERSION_STRING DISKSPD_MAJORMINOR_VERSION_STR DISKSPD_REVISION DISKSPD_RELEASE_TAG
#define DISKSPD_DATE_VERSION_STRING "2018/9/21"

#define DISKSPD_TRACE_INFO      0x00000000
#define DISKSPD_TRACE_RESERVED  0x00000001
#define DISKSPD_TRACE_IO        0x00000100

typedef void (WINAPI *PRINTF)(const char*, va_list);                            //function used for displaying formatted data (printf style)

struct ETWEventCounters
{
    UINT64 ullIORead;                   // Read
    UINT64 ullIOWrite;                  // Write
    UINT64 ullMMTransitionFault;        // Transition fault
    UINT64 ullMMDemandZeroFault;        // Demand Zero fault
    UINT64 ullMMCopyOnWrite;            // Copy on Write
    UINT64 ullMMGuardPageFault;         // Guard Page fault
    UINT64 ullMMHardPageFault;          // Hard page fault
    UINT64 ullNetTcpSend;               // Send
    UINT64 ullNetTcpReceive;            // Receive
    UINT64 ullNetUdpSend;               // Send
    UINT64 ullNetUdpReceive;            // Receive
    UINT64 ullNetConnect;               // Connect
    UINT64 ullNetDisconnect;            // Disconnect
    UINT64 ullNetRetransmit;            // ReTransmit
    UINT64 ullNetAccept;                // Accept
    UINT64 ullNetReconnect;             // ReConnect
    UINT64 ullRegCreate;                // NtCreateKey
    UINT64 ullRegOpen;                  // NtOpenKey
    UINT64 ullRegDelete;                // NtDeleteKey
    UINT64 ullRegQuery;                 // NtQueryKey
    UINT64 ullRegSetValue;              // NtSetValueKey
    UINT64 ullRegDeleteValue;           // NtDeleteValueKey
    UINT64 ullRegQueryValue;            // NtQueryValueKey
    UINT64 ullRegEnumerateKey;          // NtEnumerateKey
    UINT64 ullRegEnumerateValueKey;     // NtEnumerateValueKey
    UINT64 ullRegQueryMultipleValue;    // NtQueryMultipleValueKey
    UINT64 ullRegSetInformation;        // NtSetInformationKey
    UINT64 ullRegFlush;                 // NtFlushKey
    UINT64 ullThreadStart;
    UINT64 ullThreadEnd;
    UINT64 ullProcessStart;
    UINT64 ullProcessEnd;
    UINT64 ullImageLoad;
};

// structure containing informations about ETW session
struct ETWSessionInfo
{
    ULONG ulBufferSize;
    ULONG ulMinimumBuffers;
    ULONG ulMaximumBuffers;
    ULONG ulFreeBuffers;
    ULONG ulBuffersWritten;
    ULONG ulFlushTimer;
    LONG lAgeLimit;
    ULONG ulNumberOfBuffers;
    ULONG ulEventsLost;
    ULONG ulLogBuffersLost;
    ULONG ulRealTimeBuffersLost;
};

// structure containing parameters concerning ETW session provided by user
struct ETWMask
{
    BOOL bProcess;
    BOOL bThread;
    BOOL bImageLoad;
    BOOL bDiskIO;
    BOOL bMemoryPageFaults;
    BOOL bMemoryHardFaults;
    BOOL bNetwork;
    BOOL bRegistry;
    BOOL bUsePagedMemory;
    BOOL bUsePerfTimer;
    BOOL bUseSystemTimer;
    BOOL bUseCyclesCounter;
};

namespace UnitTests
{
    class PerfTimerUnitTests;
    class ProfileUnitTests;
    class TargetUnitTests;
}

class PerfTimer
{
public:

    static UINT64 GetTime();

    static double PerfTimeToMicroseconds(const double);
    static double PerfTimeToMilliseconds(const double);
    static double PerfTimeToSeconds(const double);
    static double PerfTimeToMicroseconds(const UINT64);
    static double PerfTimeToMilliseconds(const UINT64);
    static double PerfTimeToSeconds(const UINT64);

    static UINT64 MicrosecondsToPerfTime(const double);
    static UINT64 MillisecondsToPerfTime(const double);
    static UINT64 SecondsToPerfTime(const double);

private:

    static const UINT64 TIMER_FREQ;
    static UINT64 _GetPerfTimerFreq();

    friend class UnitTests::PerfTimerUnitTests;
};

//
// This code implements Bob Jenkins public domain simple random number generator
// See http://burtleburtle.net/bob/rand/smallprng.html for details
//

class Random
{
public:
    Random(UINT64 ulSeed = 0);

    inline UINT64 Rand64()
    {
        UINT64 e;
        
        e =           _ulState[0] - _rotl64(_ulState[1], 7);
        _ulState[0] = _ulState[1] ^ _rotl64(_ulState[2], 13);
        _ulState[1] = _ulState[2] + _rotl64(_ulState[3], 37);
        _ulState[2] = _ulState[3] + e;
        _ulState[3] = e + _ulState[0];
        
        return _ulState[3];
    }

    inline UINT32 Rand32()
    {
        return (UINT32)Rand64();
    }

    void RandBuffer(BYTE *pBuffer, UINT32 ulLength, bool fPseudoRandomOkay);

private:
    UINT64 _ulState[4];
};

struct PercentileDescriptor
{
    double Percentile;
    string Name;
};

class Util
{
public:
    static string DoubleToStringHelper(const double);
    template<typename T> static T QuotientCeiling(T dividend, T divisor)
    {
        return (dividend + divisor - 1) / divisor;
    }
};

// To keep track of which type of IO was issued
enum class IOOperation
{
    ReadIO = 1,
    WriteIO
};


typedef void (*CALLBACK_TEST_STARTED)();    //callback function to notify that the measured test is about to start
typedef void (*CALLBACK_TEST_FINISHED)();   //callback function to notify that the measured test has just finished




struct Synchronization
{
    ULONG ulStructSize;     //size of the structure that the caller is aware of (to easier achieve backward compatibility in a future)
    HANDLE hStopEvent;      //an event to be signalled if the scenario is to be stop before time ellapses
    HANDLE hStartEvent;     //an event for signalling start
    CALLBACK_TEST_STARTED pfnCallbackTestStarted;   //a function to be called if the measured test is about to start
    CALLBACK_TEST_FINISHED pfnCallbackTestFinished; //a function to be called as soon as the measrued test finishes
};

#define STRUCT_SYNCHRONIZATION_SUPPORTS(pSynch, Field) ( \
    (NULL != (pSynch)) && \
    ((pSynch)->ulStructSize >= offsetof(struct Synchronization, Field) + sizeof((pSynch)->Field)) \
    )

class Profile
{
public:
    Profile() :
        _fVerbose(false),
		_sTimeSpan(0),
        _dwProgress(0),
        _fEtwEnabled(false),
        _fEtwProcess(false),
        _fEtwThread(false),
        _fEtwImageLoad(false),
        _fEtwDiskIO(false),
        _fEtwMemoryPageFaults(false),
        _fEtwMemoryHardFaults(false),
        _fEtwNetwork(false),
        _fEtwRegistry(false),
        _fEtwUsePagedMemory(false),
        _fEtwUsePerfTimer(false),
        _fEtwUseSystemTimer(false),
        _fEtwUseCyclesCounter(false)
    {
    }

	void MarkFilesAsPrecreated(const vector<string> vFiles);


    void SetVerbose(bool b) { _fVerbose = b; }
    bool GetVerbose() const { return _fVerbose; }

    void SetProgress(DWORD dwProgress) { _dwProgress = dwProgress; }
    DWORD GetProgress() const { return _dwProgress; }

    void SetCmdLine(string sCmdLine) { _sCmdLine = sCmdLine; }
    string GetCmdLine() const { return _sCmdLine; };


	void SetLogFile(string log) { _sLogFile = log; }
	string GetLogFile() const { return _sLogFile; }

	void SetTimeSpan(UINT32 time) { _sTimeSpan = time; }
	UINT32 GetTimeSpan() const { return _sTimeSpan; }

    //ETW
    void SetEtwEnabled(bool b)          { _fEtwEnabled = b; }
    void SetEtwProcess(bool b)          { _fEtwProcess = b; }
    void SetEtwThread(bool b)           { _fEtwThread = b; }
    void SetEtwImageLoad(bool b)        { _fEtwImageLoad = b; }
    void SetEtwDiskIO(bool b)           { _fEtwDiskIO = b; }
    void SetEtwMemoryPageFaults(bool b) { _fEtwMemoryPageFaults = b; }
    void SetEtwMemoryHardFaults(bool b) { _fEtwMemoryHardFaults = b; }
    void SetEtwNetwork(bool b)          { _fEtwNetwork = b; }
    void SetEtwRegistry(bool b)         { _fEtwRegistry = b; }
    void SetEtwUsePagedMemory(bool b)   { _fEtwUsePagedMemory = b; }
    void SetEtwUsePerfTimer(bool b)     { _fEtwUsePerfTimer = b; }
    void SetEtwUseSystemTimer(bool b)   { _fEtwUseSystemTimer = b; }
    void SetEtwUseCyclesCounter(bool b) { _fEtwUseCyclesCounter = b; }

    bool GetEtwEnabled() const          { return _fEtwEnabled; }
    bool GetEtwProcess() const          { return _fEtwProcess; }
    bool GetEtwThread() const           { return _fEtwThread; }
    bool GetEtwImageLoad() const        { return _fEtwImageLoad; }
    bool GetEtwDiskIO() const           { return _fEtwDiskIO; }
    bool GetEtwMemoryPageFaults() const { return _fEtwMemoryPageFaults; }
    bool GetEtwMemoryHardFaults() const { return _fEtwMemoryHardFaults; }
    bool GetEtwNetwork() const          { return _fEtwNetwork; }
    bool GetEtwRegistry() const         { return _fEtwRegistry; }
    bool GetEtwUsePagedMemory() const   { return _fEtwUsePagedMemory; }
    bool GetEtwUsePerfTimer() const     { return _fEtwUsePerfTimer; }
    bool GetEtwUseSystemTimer() const   { return _fEtwUseSystemTimer; }
    bool GetEtwUseCyclesCounter() const { return _fEtwUseCyclesCounter; }


private:
    Profile(const Profile& T);
	string _sLogFile;
	UINT32 _sTimeSpan;

    bool _fVerbose;
    DWORD _dwProgress;
    string _sCmdLine;


    //ETW
    bool _fEtwEnabled;
    bool _fEtwProcess;
    bool _fEtwThread;
    bool _fEtwImageLoad;
    bool _fEtwDiskIO;
    bool _fEtwMemoryPageFaults;
    bool _fEtwMemoryHardFaults;
    bool _fEtwNetwork;
    bool _fEtwRegistry;
    bool _fEtwUsePagedMemory;
    bool _fEtwUsePerfTimer;
    bool _fEtwUseSystemTimer;
    bool _fEtwUseCyclesCounter;

    friend class UnitTests::ProfileUnitTests;
};

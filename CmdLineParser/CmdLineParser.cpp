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

#include "CmdLineParser.h"
#include "Common.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

CmdLineParser::CmdLineParser()
{
}

CmdLineParser::~CmdLineParser()
{
}

void CmdLineParser::_UsageInfo(const char *pszFileName) const
{
	printf("\n");
	printf("Usage: %s [options] target\n", pszFileName);
	printf("\n");
	printf("Available options:\n");
	printf("  -h                    display usage information\n");
	printf("  -v                    verbose mode\n");
	printf("  -f                    generate logfile\n");
	printf("  -t                    set time-out interval, in seconds\n");
	printf("\n");
	printf("Examples:\n\n");
	printf("Start Trace Event and save disk I/O event into logfile for 10 second:\n\n");
	printf(" $ %s -f filelog -t 10000 \n\n", pszFileName);
	printf("Start Trace Event forever and only stop when hit 'Ctrl+C':\n\n");
	printf(" $ %s -f filelog \n\n", pszFileName);
}

bool CmdLineParser::ParseCmdInfo(const int argc, const char *argv[], Profile *pProfile)
{
	string test;
	int nParamCnt = argc - 1;
	const char** args = argv + 1;
	if (argc < 2)
	{
		_UsageInfo(argv[0]);
		return false;
	}
	bool fError = false;

	while (nParamCnt)
	{
		const char* arg = *args;
		// check if it is a parameter or already path
		if ('-' != *arg && '/' != *arg)
		{
			--nParamCnt;
			++args;
			continue;
		}

		// skip '-' or '/'
		++arg;

		switch (*arg)
		{
		case 'h':
			_UsageInfo(argv[0]);
			return false;
		case 'v':
			pProfile->SetVerbose(true);
			break;
		case 'f':
			if (*(args + 1) != '\0')
			{
				pProfile->SetLogFile(*(args + 1));
			}
			else fError = true;
			break;
		case 't':
			if (*(args + 1) != '\0')
			{
				int iTimeOut = atoi(*(args + 1));
				if (iTimeOut <= 0)
				{
					fError = true;
					break;
				}
				pProfile->SetTimeSpan(iTimeOut);
				printf("Time-out %u \n", iTimeOut);
			}
			else fError = true;
			break;
		default:
			fprintf(stderr, "ERROR: invalid option: '%s'\n", arg);
			return false;
		}

		if (fError)
		{
			fprintf(stderr, "ERROR: incorrectly provided option: '%s'\n", arg);
			return false;
		}

		--nParamCnt;
		++args;
	}


	//string flag = argv[1];

	//if (0 == flag.compare("-f"))
	//{
	//	pProfile->SetLogFile(argv[2]);
	//}
	//flag = argv[3];
	//if (0 == flag.compare("-t"))
	//{
	//	pProfile->SetTimeSpan(atoi(argv[4]));
	//}
	//else
	//{
	//	_DisplayUsageInfo(argv[0]);
	//	return false;
	//}


	return true;
}


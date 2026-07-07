#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <fstream>
#include <sstream>
#include <random>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

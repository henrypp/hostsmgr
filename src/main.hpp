// hostsmgr
// Copyright (c) 2016-2019 Henry++

#ifndef __MAIN_H__
#define __MAIN_H__

#include <windows.h>
#include <commctrl.h>

#include "routine.hpp"
#include "resource.hpp"
#include "app.hpp"

// libs
//#pragma comment(lib, "iphlpapi.lib")

struct STATIC_DATA
{
	bool is_nobackup = false;
	bool is_noresolver = false;

	WCHAR hosts_file[MAX_PATH] = {0};
	WCHAR eol[3] = {0};

	LPWSTR sources_file = {0};
	LPWSTR whitelist_file = {0};
	LPWSTR userlist_file = {0};
	LPWSTR cache_dir = {0};
	LPWSTR hosts_destination = nullptr;


	HANDLE houtput = nullptr;
	WORD attributes = 0;
};

#endif // __MAIN_H__

// hostsmgr
// Copyright (c) 2016-2020 Henry++

#pragma once

#include <windows.h>
#include <commctrl.h>

#include "routine.hpp"
#include "resource.hpp"
#include "app.hpp"

// libs
//#pragma comment(lib, "iphlpapi.lib")

struct STATIC_DATA
{
	WCHAR hosts_file[MAX_PATH] = {0};
	WCHAR eol[3] = {0};

	LPWSTR sources_file = nullptr;
	LPWSTR whitelist_file = nullptr;
	LPWSTR userlist_file = nullptr;
	LPWSTR cache_dir = nullptr;
	LPWSTR hosts_destination = nullptr;
	LPWSTR hosts_file_temp = nullptr;

	HANDLE houtput = nullptr;

	WORD attributes = 0;

	bool is_nobackup = false;
	bool is_noresolver = false;
	bool is_nocache = false;
};

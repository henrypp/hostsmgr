// hostsmgr
// Copyright (c) 2016-2023 Henry++

#pragma once

#include "routine.h"

#include "resource.h"
#include "app.h"
#include "global.h"

typedef struct _STATIC_DATA
{
	PR_STRING eol;

	PR_STRING sources_file;
	PR_STRING whitelist_file;
	PR_STRING userlist_file;
	PR_STRING cache_dir;
	PR_STRING hosts_destination;
	PR_STRING hosts_file;
	PR_STRING hosts_file_temp;
	PR_STRING hosts_file_backup;

	PR_HASHTABLE sources_table;
	PR_HASHTABLE exclude_table;
	PR_HASHTABLE exclude_table_mask;
	PR_HASHTABLE dnscrypt_list;

	HINTERNET hsession;
	HANDLE hfile; // hosts file

	volatile LONG64 total_size;
	volatile LONG64 total_hosts;
	volatile LONG total_sources;

	WORD con_attr;

	BOOLEAN is_dnscrypt;
	BOOLEAN is_nobackup;
	BOOLEAN is_nocache;
	BOOLEAN is_nointro;
	BOOLEAN is_hostonly;
} STATIC_DATA, *PSTATIC_DATA;

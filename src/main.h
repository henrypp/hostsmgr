// hostsmgr
// Copyright (c) 2016-2021 Henry++

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

	HANDLE hfile; // hosts file
	HINTERNET hsession;

	volatile LONG64 total_size;
	volatile LONG total_hosts;
	volatile LONG total_sources;

	WORD con_attr;

	BOOLEAN is_dnscrypt;
	BOOLEAN is_nobackup;
	BOOLEAN is_nocache;
	BOOLEAN is_nointro;
	BOOLEAN is_hostonly;
} STATIC_DATA, *PSTATIC_DATA;

typedef struct _SOURCE_INFO_DATA
{
	PR_STRING url;
	PR_BYTE bytes;

	HANDLE hfile; // source file handle
	HANDLE hfile_out; // hosts file

	ULONG_PTR source_hash;

	ULONG flags;
} SOURCE_INFO_DATA, *PSOURCE_INFO_DATA;

#define SI_FLAG_SOURCES 0x0001
#define SI_FLAG_USERLIST 0x0002
#define SI_FLAG_WHITELIST 0x0004
#define SI_FLAG_BLACKLIST 0x0008
#define SI_FLAG_ISFILEPATH 0x0010

#define SI_PROCESS_READ_CONFIG 0x0001
#define SI_PROCESS_PREPARE_DNSCRYPT 0x0002
#define SI_PROCESS_START 0x0004

typedef enum _FACILITY_CODE
{
	FACILITY_INIT = 1,
	FACILITY_TITLE,
	FACILITY_SUCCESS,
	FACILITY_WARNING,
	FACILITY_FAILURE,
	FACILITY_HELP,
} FACILITY_CODE;

VOID _app_printstatus (_In_ FACILITY_CODE fac, _In_opt_ ULONG code, _In_opt_ PSOURCE_INFO_DATA source_data, _In_opt_ LPCWSTR text);

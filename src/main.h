// hostsmgr
// Copyright (c) 2016-2024 Henry++

#pragma once

#include "routine.h"
#include "rapp.h"

#include "resource.h"
#include "app.h"

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

typedef enum _FACILITY_CODE
{
	FACILITY_INIT = 1,
	FACILITY_TITLE,
	FACILITY_SUCCESS,
	FACILITY_WARNING,
	FACILITY_ERROR,
	FACILITY_HELP,
} FACILITY_CODE;

typedef struct _SOURCE_INFO_DATA
{
	PR_STRING url;
	PR_STRING path;
	HANDLE hfile;
	ULONG flags;
} SOURCE_INFO_DATA, *PSOURCE_INFO_DATA;

typedef struct _SOURCE_CONTEXT
{
	PSOURCE_INFO_DATA source_data;
	LONG64 start_time;
	LONG item_count;
	ULONG flags;
} SOURCE_CONTEXT, *PSOURCE_CONTEXT;

// src flags
#define SRC_FLAG_IS_FILEPATH 0x0001
#define SRC_FLAG_SOURCE 0x0002
#define SRC_FLAG_WHITELIST 0x0004
#define SRC_FLAG_USERLIST 0x0008
#define SRC_FLAG_BLACKLIST 0x0010

#define SRC_FLAG_READONLY_FLAG (SRC_FLAG_SOURCE | SRC_FLAG_WHITELIST | SRC_FLAG_USERLIST | SRC_FLAG_IS_FILEPATH)

// action flags
#define ACTION_READ_SOURCE 0x0001
#define ACTION_READ_USERCONFIG 0x0002
#define ACTION_READ_HOSTS 0x0004
#define ACTION_PREPARE_DNSCRYPT 0x0008
#define ACTION_IS_WRITE 0x0010
#define ACTION_IS_LOADED 0x0020

#define ACTION_VALID_FLAGS (ACTION_READ_SOURCE | ACTION_READ_USERCONFIG | ACTION_READ_HOSTS | ACTION_PREPARE_DNSCRYPT)

#define ACTION_TYPE_ST (ACTION_READ_SOURCE | ACTION_READ_USERCONFIG)
#define ACTION_TYPE_MT (ACTION_READ_HOSTS | ACTION_PREPARE_DNSCRYPT)

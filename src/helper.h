// hostsmgr
// Copyright (c) 2016-2022 Henry++

#pragma once

typedef enum _FACILITY_CODE
{
	FACILITY_INIT = 1,
	FACILITY_TITLE,
	FACILITY_SUCCESS,
	FACILITY_WARNING,
	FACILITY_FAILURE,
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
#define SRC_FLAG_SOURCE 0x0001
#define SRC_FLAG_WHITELIST 0x0002
#define SRC_FLAG_USERLIST 0x0004
#define SRC_FLAG_BLACKLIST 0x0008
#define SRC_FLAG_IS_FILEPATH 0x0010

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

VOID _app_util_downloadfile (
	_In_ HINTERNET hrequest,
	_In_ HANDLE hfile,
	_In_ PFILETIME timestamp
);

BOOLEAN _app_util_isurl (
	_In_ PR_STRING string
);

VOID _app_print_printresult (
	_In_ PSOURCE_CONTEXT context
);

PR_STRING _app_print_getsourcetext (
	_In_ PSOURCE_INFO_DATA source_data
);

PR_STRING _app_print_gettext (
	_In_opt_ ULONG status,
	_In_opt_ PSOURCE_INFO_DATA source_data,
	_In_opt_ LPCWSTR text
);

VOID _app_print_status (
	_In_ FACILITY_CODE fac,
	_In_opt_ ULONG status,
	_In_opt_ PSOURCE_INFO_DATA source_data,
	_In_opt_ LPCWSTR text
);

BOOLEAN _app_hosts_initialize ();

VOID _app_hosts_destroy ();

VOID _app_hosts_writeheader ();

VOID _app_hosts_writestring (
	_In_ HANDLE hfile,
	_In_ PR_STRING string
);

_Success_ (return != 0)
ULONG_PTR _app_parser_readline (
	_In_ PSOURCE_CONTEXT context,
	_Inout_ PR_STRING line
);

VOID _app_queue_item (
	_In_ PR_WORKQUEUE work_queue,
	_In_ PSOURCE_INFO_DATA source_data,
	_In_ ULONG flags
);

BOOLEAN _app_sources_additem (
	_In_ ULONG_PTR url_hash,
	_In_ PR_STRING url_string,
	_In_ ULONG flags
);

VOID _app_sources_parse (
	_In_ ULONG flags
);

VOID NTAPI _app_sources_parsethread (
	_In_ PVOID arglist,
	_In_ ULONG busy_count
);

VOID _app_sources_processfile (
	_Inout_ PSOURCE_CONTEXT context
);

VOID _app_sources_destroy ();

VOID _app_whitelist_initialize ();

VOID _app_whitelist_additem (
	_In_ ULONG_PTR hash_code,
	_In_ PR_STRING host_string,
	_In_ BOOLEAN is_glob
);

BOOLEAN _app_whitelist_isfound (
	_In_ ULONG_PTR hash_code,
	_In_ PR_STRING host_string
);

BOOLEAN _app_whitelist_isglob (
	_In_ PR_STRING host_string
);

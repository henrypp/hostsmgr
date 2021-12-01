// hostsmgr
// Copyright (c) 2016-2021 Henry++

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

PR_STRING _app_print_getsourcetext (_In_ PSOURCE_INFO_DATA source_data);
PR_STRING _app_print_gettext (_In_opt_ ULONG code, _In_opt_ PSOURCE_INFO_DATA source_data, _In_opt_ LPCWSTR text);
VOID _app_print_status (_In_ FACILITY_CODE fac, _In_opt_ ULONG code, _In_opt_ PSOURCE_INFO_DATA source_data, _In_opt_ LPCWSTR text);

BOOLEAN _app_hosts_initialize ();
VOID _app_hosts_destroy ();
VOID _app_hosts_writeheader ();
VOID _app_hosts_writestring (_In_ HANDLE hfile, _In_ PR_STRING string);

ULONG_PTR _app_parser_readline (_Inout_ PR_STRING line, _In_ ULONG flags);
LONG _app_parser_readfile (_Inout_ PSOURCE_INFO_DATA source_data, _In_opt_ HANDLE hfile_out);

VOID _app_sources_additem (_In_ ULONG_PTR url_hash, _In_ PR_STRING url_string, _In_ ULONG flags);
VOID _app_sources_parse (_In_ ULONG flags);
VOID NTAPI _app_sources_parsethread (_In_ PVOID arglist, _In_ ULONG busy_count);
VOID _app_source_processfile (_Inout_ PSOURCE_INFO_DATA source_data, _In_ LONG64 start_time);
VOID _app_sources_destroy ();

VOID _app_whitelist_additem (_In_ ULONG_PTR hash_code, _In_ PR_STRING host_string, _In_ BOOLEAN is_glob);
VOID _app_whitelist_initialize ();
BOOLEAN _app_whitelist_isfound (_In_ ULONG_PTR hash_code, _In_ PR_STRING host_string);
BOOLEAN _app_whitelist_isglob (_In_ PR_STRING host_string);


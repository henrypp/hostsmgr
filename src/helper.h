// hostsmgr
// Copyright (c) 2016-2021 Henry++

#pragma once

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


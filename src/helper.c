// hostsmgr
// Copyright (c) 2016-2021 Henry++

#include "global.h"

FORCEINLINE VOID _app_print_sourceresult (_In_ PSOURCE_INFO_DATA source_data, _In_ LONG item_count, _In_ LONG64 start_time)
{
	WCHAR buffer[128];
	WCHAR numbers[128];

	_r_format_number (numbers, RTL_NUMBER_OF (numbers), item_count);
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"(%s items in %4.03f sec.)", numbers, _r_sys_finalexecutiontime (start_time));

	_app_print_status (item_count ? FACILITY_SUCCESS : FACILITY_WARNING, 0, source_data, buffer);
}

PR_STRING _app_print_getsourcetext (_In_ PSOURCE_INFO_DATA source_data)
{
	static R_STRINGREF sr = PR_STRINGREF_INIT (L"/");

	R_URLPARTS url_parts;
	PR_STRING string;
	ULONG code;

	string = NULL;

	if (source_data->flags & SI_FLAG_ISFILEPATH)
	{
		string = _r_path_compact (source_data->url->buffer, 32); // compact
	}
	else
	{
		code = _r_inet_queryurlparts (source_data->url, PR_URLPARTS_HOST | PR_URLPARTS_PATH, &url_parts);

		if (code == ERROR_SUCCESS)
		{
			_r_obj_movereference (&url_parts.host, _r_path_compact (url_parts.host->buffer, 20)); // compact
			_r_obj_movereference (&url_parts.path, _r_path_compact (url_parts.path->buffer, 32)); // compact

			_r_str_trimstring (url_parts.path, &sr, 0);

			string = _r_obj_concatstringrefs (3, &url_parts.host->sr, &sr, &url_parts.path->sr);

			_r_inet_destroyurlparts (&url_parts);
		}
	}

	if (!string)
		string = _r_obj_reference (source_data->url);

	return string;
}

PR_STRING _app_print_gettext (_In_ FACILITY_CODE fac, _In_opt_ ULONG code, _In_opt_ PSOURCE_INFO_DATA source_data, _In_opt_ LPCWSTR text)
{
	R_STRINGBUILDER sb;
	PR_STRING string;

	_r_obj_initializestringbuilder (&sb);

	if (source_data)
	{
		string = _app_print_getsourcetext (source_data);

		_r_obj_appendstringbuilder (&sb, L" ");
		_r_obj_appendstringbuilder2 (&sb, string);

		_r_obj_dereference (string);
	}

	if (text)
		_r_obj_appendstringbuilderformat (&sb, L" %s", text);

	if (code)
		_r_obj_appendstringbuilderformat (&sb, L" (error: 0x%08" TEXT (PRIX32) L")", code);

	_r_obj_appendstringbuilder (&sb, L"\r\n");

	string = _r_obj_finalstringbuilder (&sb);

	return string;
}

VOID _app_print_status (_In_ FACILITY_CODE fac, _In_opt_ ULONG code, _In_opt_ PSOURCE_INFO_DATA source_data, _In_opt_ LPCWSTR text)
{
	PR_STRING string;

	switch (fac)
	{
		case FACILITY_INIT:
		{
			_app_print_status (FACILITY_TITLE, 0, NULL, L"Configuration");

			_r_queuedlock_acquireexclusive (&console_lock);

			_r_console_writestringformat (L"Path: %s\r\nResolver: %s\r\nCaching: %s\r\nDnscrypt mode: %s\r\n",
										  _r_obj_getstring (config.hosts_file),
										  config.is_hostonly ? L"<disabled>" : _r_obj_getstring (config.hosts_destination),
										  config.is_nocache ? L"<disabled>" : L"<enabled>",
										  !config.is_dnscrypt ? L"<disabled>" : L"<enabled>"
			);

			_r_queuedlock_releaseexclusive (&console_lock);

			break;
		}

		case FACILITY_TITLE:
		{
			_r_queuedlock_acquireexclusive (&console_lock);

			_r_console_writestringformat (L"\r\n%s:\r\n", text);

			_r_queuedlock_releaseexclusive (&console_lock);

			break;
		}

		case FACILITY_SUCCESS:
		case FACILITY_WARNING:
		case FACILITY_FAILURE:
		{
			_r_queuedlock_acquireexclusive (&console_lock);

			if (fac == FACILITY_SUCCESS)
			{
				_r_console_setcolor (FOREGROUND_GREEN);
				_r_console_writestring (L"[success]");
			}
			else if (fac == FACILITY_WARNING)
			{
				_r_console_setcolor (FOREGROUND_GREEN | FOREGROUND_RED);
				_r_console_writestring (L"[warning]");
			}
			else if (fac == FACILITY_FAILURE)
			{
				_r_console_setcolor (FOREGROUND_RED);
				_r_console_writestring (L"[failure]");
			}

			_r_console_setcolor (config.con_attr);

			string = _app_print_gettext (fac, code, source_data, text);

			_r_console_writestring2 (string);

			_r_queuedlock_releaseexclusive (&console_lock);

			_r_obj_dereference (string);

			break;
		}

		case FACILITY_HELP:
		{
			_r_queuedlock_acquireexclusive (&console_lock);

			_app_print_status (FACILITY_TITLE, 0, NULL, L"Usage");

			_r_console_writestring (L"hostsmgr -ip 127.0.0.1 -os win -path \".\\out_file\"\r\n");

			_app_print_status (FACILITY_TITLE, 0, NULL, L"Command line");

			_r_console_writestring (L"-path       output file location (def. \".\\hosts\")\r\n\
-ip         ip address to be set as resolver (def. 0.0.0.0)\r\n\
-os         new line format; \"win\", \"linux\" or \"mac\" (def. \"win\")\r\n\
-dnscrypt   generate hosts list in dnscrypt mode (opt.)\r\n\
-nobackup   do not create backup for output file (opt.)\r\n\
-nointro    do not write introduction header into file (opt.)\r\n\
-noresolve  do not set resolver, just generate hosts list (opt.)\r\n\
-nocache    do not use cache files, load directly from internet (opt.)\r\n\
\r\n");

			_r_queuedlock_releaseexclusive (&console_lock);

			break;
		}
	}
}

BOOLEAN _app_hosts_initialize ()
{
	config.hfile = CreateFile (config.hosts_file_temp->buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

	if (!_r_fs_isvalidhandle (config.hfile))
	{
		_app_print_status (FACILITY_FAILURE, GetLastError (), NULL, L"Hosts failed");
		return FALSE;
	}

	return TRUE;
}

VOID _app_hosts_destroy ()
{
	SAFE_DELETE_HANDLE (config.hfile);
}

VOID _app_hosts_writeheader ()
{
	R_STRINGBUILDER sb;
	PSOURCE_INFO_DATA source_data;
	SIZE_T enum_key;

	_r_obj_initializestringbuilder (&sb);

	_r_obj_appendstringbuilderformat (&sb,
									  L"# This file is automatically generated by %s.%s#%s# DO NOT MODIFY THIS FILE -- YOUR CHANGES WILL BE ERASED!%s#%s# Content merged from the following sources:%s",
									  _r_app_getname (),
									  config.eol->buffer,
									  config.eol->buffer,
									  config.eol->buffer,
									  config.eol->buffer,
									  config.eol->buffer
	);

	enum_key = 0;

	while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
	{
		if (!(source_data->flags & SI_FLAG_BLACKLIST))
			continue;

		_r_obj_appendstringbuilderformat (&sb,
										  L"# %s%s",
										  source_data->url->buffer,
										  config.eol->buffer
		);
	}

	if (!config.is_hostonly)
	{
		_r_obj_appendstringbuilderformat (&sb,
										  L"%s127.0.0.1 localhost%s::1 localhost%s",
										  config.eol->buffer,
										  config.eol->buffer,
										  config.eol->buffer
		);
	}

	_r_obj_appendstringbuilder2 (&sb, config.eol);

	_r_fs_setpos (config.hfile, 0, FILE_BEGIN);

	_app_hosts_writestring (config.hfile, sb.string);

	_r_fs_setpos (config.hfile, 0, FILE_END);

	_r_obj_deletestringbuilder (&sb);
}

VOID _app_hosts_writestring (_In_ HANDLE hfile, _In_ PR_STRING string)
{
	PR_BYTE bytes;
	ULONG unused;
	NTSTATUS status;

	status = _r_str_unicode2multibyte (&string->sr, &bytes);

	if (NT_SUCCESS (status))
	{
		WriteFile (hfile, bytes->buffer, (ULONG)bytes->length, &unused, NULL);

		_r_obj_dereference (bytes);
	}
}

ULONG_PTR _app_parser_readline (_Inout_ PR_STRING line, _In_ ULONG flags)
{
	static R_STRINGREF blacklist_normal_sr = PR_STRINGREF_INIT (L"#<>!@$%^&(){}\"':;/\\[]=*? ");
	static R_STRINGREF blacklist_dnscrypt_sr = PR_STRINGREF_INIT (L"#<>!@$%^&(){}\"':;/\\ ");
	static R_STRINGREF blacklist_first_char_sr = PR_STRINGREF_INIT (L".");
	static R_STRINGREF trim_sr = PR_STRINGREF_INIT (L"\r\n\t\\/ ");

	PR_STRINGREF blacklist_sr;
	SIZE_T comment_pos;
	SIZE_T space_pos;

	comment_pos = _r_str_findchar (&line->sr, L'#', FALSE);

	if (comment_pos != SIZE_MAX)
		_r_obj_setstringlength (line, comment_pos * sizeof (WCHAR));

	_r_str_replacechar (&line->sr, L'\t', L' ');
	_r_str_trimstring (line, &trim_sr, 0);

	if (_r_obj_isstringempty2 (line))
		return 0;

	if (flags & SI_FLAG_SOURCES)
		return _r_str_crc32 (&line->sr, TRUE);

	space_pos = _r_str_findchar (&line->sr, L' ', FALSE);

	if (space_pos != SIZE_MAX)
	{
		_r_obj_removestring (line, 0, space_pos + 1);
		_r_str_trimstring (line, &trim_sr, 0);

		// check for spaces
		if (_r_str_findchar (&line->sr, L' ', FALSE) != SIZE_MAX)
			return 0;

		if (_r_obj_isstringempty2 (line))
			return 0;
	}

	// check first char
	for (SIZE_T i = 0; i < _r_str_getlength3 (&blacklist_first_char_sr); i++)
	{
		if (line->buffer[0] == blacklist_first_char_sr.buffer[i])
			return 0;
	}

	// check whole line
	if (config.is_dnscrypt)
	{
		blacklist_sr = &blacklist_dnscrypt_sr;
	}
	else
	{
		blacklist_sr = &blacklist_normal_sr;
	}

	for (SIZE_T i = 0; i < _r_str_getlength2 (line); i++)
	{
		for (SIZE_T j = 0; j < _r_str_getlength3 (blacklist_sr); j++)
		{
			if (line->buffer[i] == blacklist_sr->buffer[j])
				return 0;
		}
	}

	_r_str_tolower (&line->sr); // cosmetics

	return _r_str_crc32 (&line->sr, TRUE);
}

LONG _app_parser_readfile (_Inout_ PSOURCE_INFO_DATA source_data, _In_opt_ HANDLE hfile_out)
{
	static R_STRINGREF sr = PR_STRINGREF_INIT (L" ");

	R_BYTEREF line_sr;
	PR_STRING buffer;
	PR_STRING line_string;
	LPSTR tok_buffer;
	LPSTR token;
	ULONG_PTR hash_code;
	LONG item_count;
	NTSTATUS status;

	if (!source_data->bytes)
		source_data->bytes = _r_fs_readfile (source_data->hfile);

	if (!source_data->bytes)
		return 0;

	if (source_data->bytes->buffer[0] == '<')
		return 0;

	tok_buffer = NULL;
	token = strtok_s (source_data->bytes->buffer, "\r\n", &tok_buffer);

	item_count = 0;

	while (token)
	{
		_r_obj_initializebyteref (&line_sr, token);

		status = _r_str_multibyte2unicode (&line_sr, &line_string);

		if (NT_SUCCESS (status))
		{
			hash_code = _app_parser_readline (line_string, source_data->flags);

			if (hash_code)
			{
				if (source_data->flags & SI_FLAG_SOURCES)
				{
					if (!_r_obj_findhashtable (config.sources_table, hash_code))
					{
						_app_sources_additem (hash_code, _r_obj_reference (line_string), SI_FLAG_BLACKLIST);

						item_count += 1;
					}
				}
				else
				{

					if (!_app_whitelist_isfound (hash_code, line_string))
					{
						if (hfile_out)
						{
							if (config.is_hostonly)
							{
								buffer = _r_obj_concatstringrefs (2, &line_string->sr, &config.eol->sr);
							}
							else
							{
								buffer = _r_obj_concatstringrefs (4, &config.hosts_destination->sr, &sr, &line_string->sr, &config.eol->sr);
							}

							_app_hosts_writestring (hfile_out, buffer);

							_r_obj_dereference (buffer);
						}

						item_count += 1;
					}
				}
			}

			_r_obj_dereference (line_string);
		}

		token = strtok_s (NULL, "\r\n", &tok_buffer);
	}

	return item_count;
}

VOID _app_sources_additem (_In_ ULONG_PTR url_hash, _In_ PR_STRING url_string, _In_ ULONG flags)
{
	SOURCE_INFO_DATA source_data = {0};

	source_data.url = url_string;
	source_data.source_hash = url_hash;

	if (!PathIsURL (url_string->buffer))
		flags |= SI_FLAG_ISFILEPATH;

	source_data.flags = flags;

	_r_obj_addhashtableitem (config.sources_table, url_hash, &source_data);
}

VOID _app_sources_parse (_In_ ULONG flags)
{
	R_WORKQUEUE work_queue;
	PSOURCE_INFO_DATA source_data;
	SIZE_T enum_key;

	if (flags & SI_PROCESS_READ_CONFIG)
	{
		_r_workqueue_initialize (&work_queue, 0, 1, 250, NULL);
	}
	else
	{
		_r_workqueue_initialize (&work_queue, 0, 16, 250, NULL);
	}

	if (flags & SI_PROCESS_READ_CONFIG)
	{
		enum_key = 0;

		// parse sources
		while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
		{
			if (source_data->flags & SI_FLAG_SOURCES)
				_r_workqueue_queueitem (&work_queue, &_app_sources_parsethread, source_data);
		}

		enum_key = 0;

		// parse whitelist
		while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
		{
			if (source_data->flags & SI_FLAG_WHITELIST)
				_r_workqueue_queueitem (&work_queue, &_app_sources_parsethread, source_data);
		}

		enum_key = 0;

		// parse userlist
		while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
		{
			if (source_data->flags & SI_FLAG_USERLIST)
				_r_workqueue_queueitem (&work_queue, &_app_sources_parsethread, source_data);
		}
	}
	else if (flags & SI_PROCESS_PREPARE_DNSCRYPT)
	{
		enum_key = 0;

		while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
		{
			if (source_data->flags & SI_FLAG_BLACKLIST)
				_r_workqueue_queueitem (&work_queue, &_app_sources_parsethread, source_data);
		}
	}
	else if (flags & SI_PROCESS_START)
	{
		enum_key = 0;

		while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
		{
			if (source_data->flags & SI_FLAG_BLACKLIST)
				_r_workqueue_queueitem (&work_queue, &_app_sources_parsethread, source_data);
		}
	}

	_r_workqueue_waitforfinish (&work_queue);
	_r_workqueue_destroy (&work_queue);
}

VOID NTAPI _app_sources_parsethread (_In_ PVOID arglist, _In_ ULONG busy_count)
{
	PSOURCE_INFO_DATA source_data;
	FILETIME remote_timestamp = {0};
	FILETIME local_timestamp = {0};
	HINTERNET hconnect;
	HINTERNET hrequest;
	PR_STRING path;
	PR_BYTE bytes;
	LONG64 start_time;
	ULONG disposition_flag;
	ULONG attributes_flag;
	ULONG status;
	ULONG readed;
	ULONG unused;

	start_time = _r_sys_startexecutiontime ();

	source_data = (PSOURCE_INFO_DATA)arglist;

	if (_r_fs_isvalidhandle (source_data->hfile))
	{
		_app_source_processfile (source_data, start_time);
		return;
	}

	if (source_data->flags & SI_FLAG_ISFILEPATH)
	{
		source_data->hfile = CreateFile (source_data->url->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (source_data->hfile))
		{
			_app_print_status (FACILITY_FAILURE, GetLastError (), source_data, NULL);
			return;
		}
	}
	else
	{
		path = _r_format_string (L"%s\\%" TEXT (PR_ULONG_PTR) L".txt", config.cache_dir->buffer, source_data->source_hash);

		if (config.is_nocache)
		{
			disposition_flag = CREATE_ALWAYS;
			attributes_flag = FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE;
		}
		else
		{
			disposition_flag = OPEN_ALWAYS;
			attributes_flag = FILE_ATTRIBUTE_TEMPORARY;
		}

		SetFileAttributes (path->buffer, FILE_ATTRIBUTE_NORMAL);

		source_data->hfile = CreateFile (path->buffer, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, disposition_flag, attributes_flag, NULL);

		if (!_r_fs_isvalidhandle (source_data->hfile))
		{
			_app_print_status (FACILITY_FAILURE, GetLastError (), source_data, NULL);
			_r_obj_dereference (path);

			return;
		}

		if (config.hsession)
		{
			status = _r_inet_openurl (config.hsession, source_data->url, &hconnect, &hrequest, NULL);

			if (status != ERROR_SUCCESS)
			{
				_app_print_status (FACILITY_FAILURE, status, source_data, NULL);
			}
			else
			{
				status = _r_inet_querystatuscode (hrequest);

				if (status == HTTP_STATUS_OK)
				{
					_r_unixtime_to_filetime (_r_inet_querylastmodified (hrequest), &remote_timestamp);

					if (!_r_fs_getsize (source_data->hfile) || (GetFileTime (source_data->hfile, &local_timestamp, NULL, NULL) && CompareFileTime (&local_timestamp, &remote_timestamp) == -1))
					{
						bytes = _r_obj_createbyte_ex (NULL, 65536);

						while (_r_inet_readrequest (hrequest, bytes->buffer, (ULONG)bytes->length, &readed, NULL))
						{
							WriteFile (source_data->hfile, bytes->buffer, readed, &unused, NULL);
						}

						_r_obj_dereference (bytes);

						SetFileTime (source_data->hfile, &remote_timestamp, &remote_timestamp, &remote_timestamp);
					}
				}

				_r_inet_close (hrequest);
				_r_inet_close (hconnect);
			}
		}

		_r_obj_dereference (path);
	}

	_app_source_processfile (source_data, start_time);
}

VOID _app_source_processfile (_Inout_ PSOURCE_INFO_DATA source_data, _In_ LONG64 start_time)
{
	HANDLE hfile_out;
	LONG item_count;

	if (source_data->flags & (SI_FLAG_SOURCES | SI_FLAG_WHITELIST))
	{
		hfile_out = NULL;
	}
	else
	{
		hfile_out = config.hfile;
	}

	item_count = _app_parser_readfile (source_data, hfile_out);

	if (hfile_out)
	{
		if (item_count)
		{
			InterlockedAdd (&config.total_hosts, item_count);
			InterlockedIncrement (&config.total_sources);
		}

		InterlockedAdd64 (&config.total_size, _r_fs_getsize (source_data->hfile));
	}

	_app_print_sourceresult (source_data, item_count, start_time);
}

VOID _app_sources_destroy ()
{
	PSOURCE_INFO_DATA source_data;
	SIZE_T enum_key;

	enum_key = 0;

	while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
	{
		SAFE_DELETE_HANDLE (source_data->hfile);
		SAFE_DELETE_REFERENCE (source_data->bytes);
	}
}

VOID _app_whitelist_additem (_In_ ULONG_PTR hash_code, _In_ PR_STRING host_string, _In_ BOOLEAN is_glob)
{
	if (is_glob)
	{
		_r_queuedlock_acquireexclusive (&exclude_mask_lock);

		_r_obj_addhashtablepointer (config.exclude_table_mask, hash_code, _r_obj_reference (host_string)); // mask

		_r_queuedlock_releaseexclusive (&exclude_mask_lock);

	}
	else
	{
		_r_queuedlock_acquireexclusive (&exclude_lock);

		_r_obj_addhashtableitem (config.exclude_table, hash_code, NULL);

		_r_queuedlock_releaseexclusive (&exclude_lock);
	}
}

VOID _app_whitelist_initialize ()
{
	// predefined whitelisted hosts
	static R_STRINGREF exclude_hosts[] = {
		PR_STRINGREF_INIT (L"local"),
		PR_STRINGREF_INIT (L"localhost"),
		PR_STRINGREF_INIT (L"localhost.localdomain"),
		PR_STRINGREF_INIT (L"broadcasthost"),
		PR_STRINGREF_INIT (L"notice"),
		PR_STRINGREF_INIT (L"ip6-loopback"),
		PR_STRINGREF_INIT (L"ip6-localhost"),
		PR_STRINGREF_INIT (L"ip6-localnet"),
		PR_STRINGREF_INIT (L"ip6-mcastprefix"),
		PR_STRINGREF_INIT (L"ip6-allnodes"),
		PR_STRINGREF_INIT (L"ip6-allrouters"),
		PR_STRINGREF_INIT (L"ip6-allhosts"),
		PR_STRINGREF_INIT (L"0.0.0.0"),
	};

	_r_queuedlock_acquireexclusive (&exclude_lock);

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (exclude_hosts); i++)
	{
		_r_obj_addhashtableitem (config.exclude_table, _r_str_crc32 (&exclude_hosts[i], TRUE), NULL);
	}

	_r_queuedlock_releaseexclusive (&exclude_lock);
}

BOOLEAN _app_whitelist_isfound (_In_ ULONG_PTR hash_code, _In_ PR_STRING host_string)
{
	PR_STRING string;
	SIZE_T enum_key;
	BOOLEAN is_glob;
	BOOLEAN is_found;

	is_glob = _app_whitelist_isglob (host_string);

	//if (is_glob)
	//{
	//	_r_queuedlock_acquireshared (&exclude_mask_lock);
	//
	//	is_found = (_r_obj_findhashtable (config.exclude_table_mask, hash_code) != NULL);
	//
	//	_r_queuedlock_releaseshared (&exclude_mask_lock);
	//}
	//else
	//{
	//	_r_queuedlock_acquireshared (&exclude_lock);
	//
	//	is_found = (_r_obj_findhashtable (config.exclude_table, hash_code) != NULL);
	//
	//	_r_queuedlock_releaseshared (&exclude_lock);
	//}

	if (!is_glob)
	{
		_r_queuedlock_acquireshared (&exclude_lock);

		is_found = (_r_obj_findhashtable (config.exclude_table, hash_code) != NULL);

		_r_queuedlock_releaseshared (&exclude_lock);
	}
	else
	{
		is_found = FALSE;
	}

	if (!is_found)
	{
		if (!_r_obj_ishashtableempty (config.exclude_table_mask))
		{
			enum_key = 0;

			_r_queuedlock_acquireshared (&exclude_mask_lock);

			while (_r_obj_enumhashtablepointer (config.exclude_table_mask, &string, NULL, &enum_key))
			{
				if (!string)
					continue;

				if (_r_str_match (host_string->buffer, string->buffer, TRUE))
				{
					is_found = TRUE;
					break;
				}
			}

			_r_queuedlock_releaseshared (&exclude_mask_lock);
		}

	}

	// remember entries to avoid duplicates
	if (!is_found)
		_app_whitelist_additem (hash_code, host_string, is_glob);

	return is_found;
}

BOOLEAN _app_whitelist_isglob (_In_ PR_STRING host_string)
{
	static R_STRINGREF sr = PR_STRINGREF_INIT (L"?*"); // glob chars

	BOOLEAN is_glob;

	is_glob = (_r_str_findchar (&host_string->sr, L'*', FALSE) != SIZE_MAX);

	return is_glob;
}

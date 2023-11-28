// hostsmgr
// Copyright (c) 2016-2023 Henry++

#include "global.h"

VOID _app_util_downloadfile (
	_In_ HINTERNET hrequest,
	_In_ HANDLE hfile,
	_In_ PFILETIME timestamp
)
{
	IO_STATUS_BLOCK isb;
	PR_BYTE bytes;
	ULONG readed;
	NTSTATUS status;

	_r_fs_clearfile (hfile);

	bytes = _r_obj_createbyte_ex (NULL, PR_SIZE_BUFFER);

	while (_r_inet_readrequest (hrequest, bytes->buffer, PR_SIZE_BUFFER, &readed, NULL))
	{
		status = NtWriteFile (hfile, NULL, NULL, NULL, &isb, bytes->buffer, readed, NULL, NULL);

		if (!NT_SUCCESS (status) || isb.Information == 0)
			break;
	}

	_r_fs_settimestamp (hfile, timestamp, timestamp, timestamp);

	_r_obj_dereference (bytes);
}

BOOLEAN _app_util_isurl (
	_In_ PR_STRING string
)
{
	// predefined whitelisted hosts
	static R_STRINGREF protocols_prep[] = {
		PR_STRINGREF_INIT (L"http"), // http/https
		PR_STRINGREF_INIT (L"ftp"), // ftp/ftps
		//PR_STRINGREF_INIT (L"ssh"), // ssh
		//PR_STRINGREF_INIT (L"git"), // git
		//PR_STRINGREF_INIT (L"ldap"), // ldap/ldaps
	};

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (protocols_prep); i++)
	{
		if (_r_str_isstartswith (&string->sr, &protocols_prep[i], TRUE))
			return TRUE;
	}

	return FALSE;
}

VOID _app_print_printresult (
	_In_ PSOURCE_CONTEXT context
)
{
	WCHAR buffer[128];
	WCHAR hosts_format[64];

	_r_format_number (hosts_format, RTL_NUMBER_OF (hosts_format), context->item_count);

	_r_str_printf (
		buffer,
		RTL_NUMBER_OF (buffer),
		L"- %s items in %.03f sec.",
		hosts_format,
		_r_perf_getexecutionfinal (context->start_time)
	);

	_app_print_status (context->item_count ? FACILITY_SUCCESS : FACILITY_WARNING, 0, context->source_data, buffer);
}

PR_STRING _app_print_getsourcetext (
	_In_ PSOURCE_INFO_DATA source_data
)
{
	static R_STRINGREF sr = PR_STRINGREF_INIT (L"/");

	R_URLPARTS url_parts;
	PR_STRING string = NULL;
	SIZE_T pos;
	ULONG status;

	if (source_data->flags & SRC_FLAG_IS_FILEPATH)
	{
		string = _r_path_getbasenamestring (&source_data->url->sr);
	}
	else
	{
		status = _r_inet_queryurlparts (source_data->url, PR_URLPARTS_HOST | PR_URLPARTS_PATH, &url_parts);

		if (status == ERROR_SUCCESS)
		{
			pos = _r_str_findchar (&url_parts.path->sr, L'?', FALSE);

			if (pos != SIZE_MAX)
				_r_obj_setstringlength (url_parts.path, pos * sizeof (WCHAR));

			// compact
			_r_obj_movereference (&url_parts.host, _r_path_compact (url_parts.host, 20));

			_r_obj_movereference (&url_parts.path, _r_path_compact (url_parts.path, 42));

			_r_str_trimstring (url_parts.host, &sr, 0);
			_r_str_trimstring (url_parts.path, &sr, 0);

			string = _r_obj_concatstringrefs (
				3,
				&url_parts.host->sr,
				&sr,
				&url_parts.path->sr
			);

			_r_inet_destroyurlparts (&url_parts);
		}
	}

	if (!string)
		string = _r_obj_reference (source_data->url);

	return string;
}

PR_STRING _app_print_gettext (
	_In_opt_ ULONG status,
	_In_opt_ PSOURCE_INFO_DATA source_data,
	_In_opt_ LPCWSTR text
)
{
	R_STRINGBUILDER sb;
	PR_STRING string;

	_r_obj_initializestringbuilder (&sb, 256);

	if (source_data)
	{
		string = _app_print_getsourcetext (source_data);

		_r_obj_appendstringbuilder (&sb, L" ");
		_r_obj_appendstringbuilder2 (&sb, string);

		_r_obj_dereference (string);
	}

	if (text)
		_r_obj_appendstringbuilderformat (&sb, L" %s", text);

	if (status)
		_r_obj_appendstringbuilderformat (&sb, L" (error: 0x%08" TEXT (PRIX32) L")", status);

	_r_obj_appendstringbuilder (&sb, L"\r\n");

	string = _r_obj_finalstringbuilder (&sb);

	return string;
}

VOID _app_print_status (
	_In_ FACILITY_CODE fac,
	_In_opt_ LONG status,
	_In_opt_ PSOURCE_INFO_DATA source_data,
	_In_opt_ LPCWSTR text
)
{
	PR_STRING string;

	switch (fac)
	{
		case FACILITY_INIT:
		{
			_app_print_status (FACILITY_TITLE, 0, NULL, L"Configuration");

			_r_console_writestringformat (
				L"Path: %s\r\nResolver: %s\r\nCaching: %s\r\nDnscrypt mode: %s\r\n",
				_r_obj_getstring (config.hosts_file),
				config.is_hostonly ? L"<disabled>" : _r_obj_getstring (config.hosts_destination),
				config.is_nocache ? L"<disabled>" : L"<enabled>",
				!config.is_dnscrypt ? L"<disabled>" : L"<enabled>"
			);

			break;
		}

		case FACILITY_TITLE:
		{
			_r_console_writestringformat (L"\r\n%s:\r\n", text);

			break;
		}

		case FACILITY_SUCCESS:
		case FACILITY_WARNING:
		case FACILITY_ERROR:
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
			else if (fac == FACILITY_ERROR)
			{
				_r_console_setcolor (FOREGROUND_RED);
				_r_console_writestring (L"[failure]");
			}

			_r_console_setcolor (config.con_attr);

			string = _app_print_gettext (status, source_data, text);

			_r_console_writestring2 (string);

			_r_queuedlock_releaseexclusive (&console_lock);

			_r_obj_dereference (string);

			break;
		}

		case FACILITY_HELP:
		{
			_app_print_status (FACILITY_TITLE, 0, NULL, L"Usage");

			_r_console_writestring (L"hostsmgr -ip 127.0.0.1 -os win -path \".\\out_file\"\r\n");

			_app_print_status (FACILITY_TITLE, 0, NULL, L"Command line");

			_r_console_writestring (
				L"-path       output file location (def. \".\\hosts\")\r\n" \
				L"-ip         ip address to be set as resolver (def. 0.0.0.0)\r\n" \
				L"-os         new line format; \"win\", \"linux\" or \"mac\" (def. \"win\")\r\n" \
				L"-dnscrypt   generate hosts list in dnscrypt mode (opt.)\r\n" \
				L"-nobackup   do not create backup for output file (opt.)\r\n" \
				L"-nointro    do not write introduction header into file (opt.)\r\n" \
				L"-noresolve  do not set resolver, just generate hosts list (opt.)\r\n" \
				L"-nocache    do not use cache files, load directly from internet (opt.)\r\n"
			);

			break;
		}
	}
}

BOOLEAN _app_hosts_initialize ()
{
	NTSTATUS status;

	status = _r_fs_createfile (
		config.hosts_file_temp->buffer,
		FILE_OVERWRITE_IF,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FALSE,
		NULL,
		&config.hfile
	);

	if (!NT_SUCCESS (status))
	{
		_app_print_status (FACILITY_ERROR, status, NULL, L"Hosts failed");

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
	PSOURCE_INFO_DATA source_data = NULL;
	R_STRINGBUILDER sb;
	SIZE_T enum_key;
	LPCWSTR title;

	_r_obj_initializestringbuilder (&sb, 256);

	title = L"# This file is automatically generated by %s.%s" \
		L"#%s" \
		L"# DO NOT MODIFY THIS FILE -- YOUR CHANGES WILL BE ERASED!%s" \
		L"#%s" \
		L"# Content merged from the following sources:%s";

	_r_obj_appendstringbuilderformat (
		&sb,
		title,
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
		if (!(source_data->flags & SRC_FLAG_BLACKLIST))
			continue;

		_r_obj_appendstringbuilder (&sb, L"# ");
		_r_obj_appendstringbuilder2 (&sb, source_data->url);
		_r_obj_appendstringbuilder2 (&sb, config.eol);
	}

	if (!config.is_hostonly)
	{
		_r_obj_appendstringbuilder2 (&sb, config.eol);
		_r_obj_appendstringbuilder (&sb, L"127.0.0.1 localhost");

		_r_obj_appendstringbuilder2 (&sb, config.eol);
		_r_obj_appendstringbuilder (&sb, L"::1 localhost");

		_r_obj_appendstringbuilder2 (&sb, config.eol);
	}

	_r_obj_appendstringbuilder2 (&sb, config.eol);

	_app_hosts_writestring (config.hfile, sb.string);

	_r_obj_deletestringbuilder (&sb);
}

VOID _app_hosts_writestring (
	_In_ HANDLE hfile,
	_In_ PR_STRING string
)
{
	IO_STATUS_BLOCK isb;
	PR_BYTE bytes;
	NTSTATUS status;

	status = _r_str_unicode2multibyte (&string->sr, &bytes);

	if (NT_SUCCESS (status))
	{
		status = NtWriteFile (hfile, NULL, NULL, NULL, &isb, bytes->buffer, (ULONG)bytes->length, NULL, NULL);

		_r_obj_dereference (bytes);
	}
}

_Success_ (return != 0)
ULONG_PTR _app_parser_readline (
	_In_ PSOURCE_CONTEXT context,
	_Inout_ PR_STRING line
)
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

	if (context->flags & ACTION_READ_SOURCE)
		return _r_str_gethash2 (line, TRUE);

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

	return _r_str_gethash2 (line, TRUE);
}

VOID _app_queue_item (
	_In_ PR_WORKQUEUE work_queue,
	_In_ PSOURCE_INFO_DATA source_data,
	_In_ ULONG flags
)
{
	PSOURCE_CONTEXT context;

	context = _r_freelist_allocateitem (&context_list);

	context->start_time = _r_perf_getexecutionstart ();
	context->source_data = source_data;
	context->flags = flags;

	_r_workqueue_queueitem (work_queue, &_app_sources_parsethread, context);
}
BOOLEAN _app_sources_additem (
	_In_ ULONG_PTR url_hash,
	_In_ PR_STRING url_string,
	_In_ ULONG flags
)
{
	SOURCE_INFO_DATA source_data = {0};
	PR_STRING path;
	HANDLE hfile;
	ULONG access_flag;
	ULONG attributes_flag;
	ULONG disposition_flag;
	ULONG create_flag = 0;
	NTSTATUS status;

	if ((flags & SRC_FLAG_IS_FILEPATH) || !_app_util_isurl (url_string))
	{
		path = _r_obj_reference (url_string);

		flags |= SRC_FLAG_IS_FILEPATH;
	}
	else
	{
		path = _r_format_string (L"%s\\%" TEXT (PR_ULONG_PTR) L".txt", config.cache_dir->buffer, url_hash);
	}

	if (flags & SRC_FLAG_READONLY_FLAG)
	{
		access_flag = GENERIC_READ;
		attributes_flag = FILE_ATTRIBUTE_NORMAL;
		disposition_flag = FILE_OPEN_IF;
	}
	else
	{
		access_flag = GENERIC_READ | GENERIC_WRITE;
		attributes_flag = FILE_ATTRIBUTE_TEMPORARY;

		if (config.is_nocache)
		{
			create_flag = FILE_DELETE_ON_CLOSE;
			disposition_flag = FILE_OVERWRITE_IF;
		}
		else
		{
			disposition_flag = FILE_OPEN_IF;
		}

		if (_r_fs_exists (path->buffer))
			_r_fs_setattributes (path->buffer, NULL, FILE_ATTRIBUTE_NORMAL);
	}

	status = _r_fs_createfile (
		path->buffer,
		disposition_flag,
		access_flag,
		FILE_SHARE_READ,
		attributes_flag,
		create_flag,
		FALSE,
		NULL,
		&hfile
	);

	if (!NT_SUCCESS (status))
	{
		_app_print_status (FACILITY_ERROR, status, NULL, path->buffer);
		_r_obj_dereference (path);

		return FALSE;
	}

	source_data.flags = flags;
	source_data.hfile = hfile;
	source_data.path = path;
	source_data.url = _r_obj_reference (url_string);

	_r_obj_addhashtableitem (config.sources_table, url_hash, &source_data);

	return TRUE;
}

VOID _app_sources_parse (
	_In_ ULONG flags
)
{
	PSOURCE_INFO_DATA source_data = NULL;
	R_ENVIRONMENT environment;
	R_WORKQUEUE work_queue;
	SIZE_T enum_key;

	if (!(flags & ACTION_VALID_FLAGS))
	{
		_app_print_status (FACILITY_ERROR, ERROR_INVALID_FLAGS, NULL, NULL);

		return;
	}

	_r_sys_setenvironment (&environment, THREAD_PRIORITY_LOWEST, IoPriorityLow, MEMORY_PRIORITY_NORMAL);

	if (flags & ACTION_TYPE_ST)
	{
		_r_workqueue_initialize (&work_queue, 1, &environment, L"QueueST");
	}
	else if (flags & ACTION_TYPE_MT)
	{
		_r_workqueue_initialize (&work_queue, 12, &environment, L"QueueMT");
	}
	else
	{
		// fix warning!
		return;
	}

	if (flags & ACTION_TYPE_ST)
	{
		// parse sources
		if (flags & ACTION_READ_SOURCE)
		{
			enum_key = 0;

			while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
			{
				if (source_data->flags & SRC_FLAG_SOURCE)
					_app_queue_item (&work_queue, source_data, flags);
			}
		}

		// parse userconfig
		if (flags & ACTION_READ_USERCONFIG)
		{
			enum_key = 0;

			// parse whitelist
			while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
			{
				if (source_data->flags & SRC_FLAG_WHITELIST)
					_app_queue_item (&work_queue, source_data, flags);
			}

			enum_key = 0;

			// parse userlist
			while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
			{
				if (source_data->flags & SRC_FLAG_USERLIST)
					_app_queue_item (&work_queue, source_data, flags | ACTION_IS_WRITE);
			}
		}
	}
	else if (flags & ACTION_TYPE_MT)
	{
		if (flags & ACTION_PREPARE_DNSCRYPT)
		{
			_app_print_status (FACILITY_TITLE, 0, NULL, L"Prepare dnscrypt configuration");

			flags |= ACTION_PREPARE_DNSCRYPT;
		}
		else if (flags & ACTION_READ_HOSTS)
		{
			_app_print_status (FACILITY_TITLE, 0, NULL, L"Reading sources");

			flags |= ACTION_IS_WRITE;
		}

		enum_key = 0;

		while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
		{
			if (source_data->flags & SRC_FLAG_BLACKLIST)
				_app_queue_item (&work_queue, source_data, flags);
		}
	}

	_r_workqueue_waitforfinish (&work_queue);
	_r_workqueue_destroy (&work_queue);
}

VOID NTAPI _app_sources_parsethread (
	_In_ PVOID arglist,
	_In_ ULONG busy_count
)
{
	PSOURCE_CONTEXT context;
	FILETIME remote_timestamp;
	FILETIME local_timestamp;
	PR_STRING proxy_string = NULL;
	HINTERNET hconnect;
	HINTERNET hrequest;
	LONG64 remote_size;
	LONG64 local_size;
	LONG64 lastmod;

	context = (PSOURCE_CONTEXT)arglist;

	if (context->source_data->flags & SRC_FLAG_IS_FILEPATH)
		context->flags |= ACTION_IS_LOADED;

	if (context->flags & ACTION_IS_LOADED)
	{
		_app_sources_processfile (context);
	}
	else
	{
		if (config.hsession)
		{
			proxy_string = _r_app_getproxyconfiguration ();

			if (!_r_inet_openurl (config.hsession, context->source_data->url, proxy_string, &hconnect, &hrequest, NULL))
			{
				_app_print_status (FACILITY_ERROR, PebLastError (), context->source_data, L"[winhttp]");
			}
			else
			{
				// query content length
				_r_fs_getsize2 (context->source_data->hfile, NULL, &local_size);

				remote_size = _r_inet_querycontentlength (hrequest);

				// query content lastmod
				lastmod = _r_inet_querylastmodified (hrequest);

				_r_unixtime_to_filetime (lastmod, &remote_timestamp);

				_r_fs_gettimestamp (context->source_data->hfile, NULL, NULL, &local_timestamp);

				if (!local_size || local_size != remote_size || CompareFileTime (&local_timestamp, &remote_timestamp) == -1)
					_app_util_downloadfile (hrequest, context->source_data->hfile, &remote_timestamp);

				_r_inet_close (hrequest);
				_r_inet_close (hconnect);
			}
		}

		context->flags |= ACTION_IS_LOADED;

		_app_sources_processfile (context);
	}

	if (proxy_string)
		_r_obj_dereference (proxy_string);

	_r_freelist_deleteitem (&context_list, context);
}

VOID _app_sources_processfile (
	_Inout_ PSOURCE_CONTEXT context
)
{
	static R_STRINGREF sr = PR_STRINGREF_INIT (L" ");

	R_BYTEREF line_sr;
	PR_BYTE bytes;
	PR_STRING buffer;
	PR_STRING string = NULL;
	PR_STRING line_string;
	LPSTR tok_buffer = NULL;
	LPSTR token;
	SIZE_T enum_key;
	ULONG_PTR hash_code;
	ULONG checksum;
	BOOLEAN is_found;
	NTSTATUS status;

	context->item_count = 0;

	status = _r_fs_readfile (context->source_data->hfile, &bytes);

	if (!NT_SUCCESS (status))
		return;

	if (bytes->buffer[0] == '<')
	{
		_r_obj_dereference (bytes);

		return;
	}

	token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

	while (token)
	{
		_r_obj_initializebyteref (&line_sr, token);

		status = _r_str_multibyte2unicode (&line_sr, &line_string);

		if (NT_SUCCESS (status))
		{
			hash_code = _app_parser_readline (context, line_string);

			if (hash_code)
			{
				if (context->flags & ACTION_READ_SOURCE)
				{
					if (!_r_obj_findhashtable (config.sources_table, hash_code))
					{
						_app_sources_additem (hash_code, line_string, SRC_FLAG_BLACKLIST);

						context->item_count += 1;
					}
				}
				else if (context->flags & (ACTION_READ_USERCONFIG | ACTION_READ_HOSTS))
				{
					if (!_app_whitelist_isfound (hash_code, line_string))
					{
						if (context->flags & ACTION_IS_WRITE)
						{
							if (config.is_hostonly)
							{
								buffer = _r_obj_concatstringrefs (
									2,
									&line_string->sr,
									&config.eol->sr
								);
							}
							else
							{
								buffer = _r_obj_concatstringrefs (
									4,
									&config.hosts_destination->sr,
									&sr,
									&line_string->sr,
									&config.eol->sr
								);
							}

							_app_hosts_writestring (config.hfile, buffer);

							_r_obj_dereference (buffer);
						}

						context->item_count += 1;
					}
				}
				else if (context->flags & ACTION_PREPARE_DNSCRYPT)
				{
					is_found = FALSE;

					enum_key = 0;

					checksum = _r_str_gethash2 (line_string, TRUE);

					_r_queuedlock_acquireshared (&dnscrypt_lock);

					while (_r_obj_enumhashtablepointer (config.dnscrypt_list, &string, NULL, &enum_key))
					{
						if (_r_str_findchar (&string->sr, L'*', FALSE) != SIZE_MAX)
						{
							if (_r_str_match (line_string->buffer, string->buffer, TRUE))
								is_found = TRUE;
						}
						else
						{
							if (_r_obj_findhashtable (config.dnscrypt_list, checksum))
								is_found = TRUE;
						}
					}

					_r_queuedlock_releaseshared (&dnscrypt_lock);

					if (is_found)
					{
						_r_queuedlock_acquireexclusive (&exclude_lock);
						_r_obj_addhashtableitem (config.exclude_table, checksum, NULL);
						_r_queuedlock_releaseexclusive (&exclude_lock);

						context->item_count += 1;
					}

					_r_queuedlock_acquireexclusive (&dnscrypt_lock);
					_r_obj_addhashtablepointer (config.dnscrypt_list, checksum, _r_obj_reference (line_string));
					_r_queuedlock_releaseexclusive (&dnscrypt_lock);
				}
			}

			_r_obj_dereference (line_string);
		}

		token = strtok_s (NULL, "\r\n", &tok_buffer);
	}

	if (context->flags & ACTION_IS_WRITE)
	{
		if (context->item_count)
		{
			InterlockedAdd64 (&config.total_hosts, context->item_count);
			InterlockedIncrement (&config.total_sources);
		}

		InterlockedAdd64 (&config.total_size, bytes->length);
	}

	_app_print_printresult (context);

	_r_obj_dereference (bytes);
}

VOID _app_sources_destroy ()
{
	PSOURCE_INFO_DATA source_data = NULL;
	SIZE_T enum_key;

	enum_key = 0;

	while (_r_obj_enumhashtable (config.sources_table, &source_data, NULL, &enum_key))
	{
		SAFE_DELETE_HANDLE (source_data->hfile);

		SAFE_DELETE_REFERENCE (source_data->url);
		SAFE_DELETE_REFERENCE (source_data->path);
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
		_r_obj_addhashtableitem (config.exclude_table, _r_str_gethash3 (&exclude_hosts[i], FALSE), NULL);
	}

	_r_queuedlock_releaseexclusive (&exclude_lock);
}

VOID _app_whitelist_additem (
	_In_ ULONG_PTR hash_code,
	_In_ PR_STRING host_string,
	_In_ BOOLEAN is_glob
)
{
	if (is_glob)
	{
		_r_queuedlock_acquireexclusive (&exclude_mask_lock);
		_r_obj_addhashtablepointer (config.exclude_table_mask, hash_code, _r_obj_reference (host_string));
		_r_queuedlock_releaseexclusive (&exclude_mask_lock);

	}
	else
	{
		_r_queuedlock_acquireexclusive (&exclude_lock);
		_r_obj_addhashtableitem (config.exclude_table, hash_code, NULL);
		_r_queuedlock_releaseexclusive (&exclude_lock);
	}
}

BOOLEAN _app_whitelist_isfound (
	_In_ ULONG_PTR hash_code,
	_In_ PR_STRING host_string
)
{
	PR_STRING string = NULL;
	SIZE_T enum_key;
	BOOLEAN is_glob;
	BOOLEAN is_found = FALSE;

	is_glob = _app_whitelist_isglob (host_string);

	//if (is_glob)
	//{
	//	_r_queuedlock_acquireshared (&exclude_mask_lock);
	//	is_found = (_r_obj_findhashtable (config.exclude_table_mask, hash_code) != NULL);
	//	_r_queuedlock_releaseshared (&exclude_mask_lock);
	//}
	//else
	//{
	//	_r_queuedlock_acquireshared (&exclude_lock);
	//	is_found = (_r_obj_findhashtable (config.exclude_table, hash_code) != NULL);
	//	_r_queuedlock_releaseshared (&exclude_lock);
	//}

	if (!is_glob)
	{
		_r_queuedlock_acquireshared (&exclude_lock);
		is_found = (_r_obj_findhashtable (config.exclude_table, hash_code) != NULL);
		_r_queuedlock_releaseshared (&exclude_lock);
	}

	if (!is_found)
	{
		if (!_r_obj_isempty (config.exclude_table_mask))
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

BOOLEAN _app_whitelist_isglob (
	_In_ PR_STRING host_string
)
{
	BOOLEAN is_glob;

	is_glob = (_r_str_findchar (&host_string->sr, L'*', FALSE) != SIZE_MAX);

	return is_glob;
}

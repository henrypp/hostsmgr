// hostsmgr
// Copyright (c) 2016-2021 Henry++

#include <io.h>
#include <fcntl.h>

#include "routine.h"

#include "main.h"
#include "rapp.h"

#include "resource.h"

STATIC_DATA config = {0};

R_QUEUED_LOCK exclude_lock = PR_QUEUED_LOCK_INIT;

PR_HASHTABLE exclude_list = NULL;
PR_LIST exclude_list_mask = NULL;

VOID _app_printconsole (_In_ _Printf_format_string_ LPCWSTR format, ...)
{
	va_list arg_ptr;
	PR_STRING string;
	HANDLE hstdout;

	if (!format)
		return;

	hstdout = GetStdHandle (STD_OUTPUT_HANDLE);

	if (!_r_fs_isvalidhandle (hstdout))
		return;

	va_start (arg_ptr, format);
	string = _r_format_string_v (format, arg_ptr);
	va_end (arg_ptr);

	if (!string)
		return;

	WriteConsole (hstdout, string->buffer, (ULONG)_r_obj_getstringlength (string), NULL, NULL);
}

VOID _app_printstatus (_In_ FACILITY_CODE fac, _In_opt_ ULONG code, _In_opt_ LPCWSTR name, _In_opt_ LPCWSTR description)
{
	switch (fac)
	{
		case FACILITY_SUCCESS:
		{
			if (name)
			{
				if (description)
				{
					_app_printconsole (L"%s (%s)\r\n", name, description);
				}
				else
				{
					_app_printconsole (L"%s\r\n", name);
				}
			}

			break;
		}

		case FACILITY_FAILURE:
		{
			if (name)
			{
				if (description)
				{
					if (code)
					{
						_app_printconsole (L"%s (%s / 0x%08" TEXT (PRIX32) L")\r\n", name, description, code);
					}
					else
					{
						_app_printconsole (L"%s (%s)\r\n", name, description);
					}
				}
				else
				{
					if (code)
					{
						_app_printconsole (L"%s (0x%08" TEXT (PRIX32) L")\r\n", name, code);
					}
					else
					{
						_app_printconsole (L"%s\r\n", name);
					}
				}
			}

			break;
		}

		case FACILITY_HELP:
		{
			_app_printconsole (L"Usage:\r\n\
hostsmgr -ip 127.0.0.1 -os win -path [out file]\r\n\
\r\n\
Command line:\r\n\
-path       output file location (def. \".\\hosts\")\r\n\
-ip         ip address to be set as resolver (def. 0.0.0.0)\r\n\
-os         new line format; \"win\", \"linux\" or \"mac\" (def. \"win\")\r\n\
-nobackup   do not create backup for output file (opt.)\r\n\
-noresolve  do not set resolver, just generate hosts list (opt.)\r\n\
-nocache    do not use cache files, load directly from internet (opt.)\r\n\
\r\n");

			break;
		}
	}
}

VOID _app_writestringtofile (_In_ HANDLE hfile, _In_ PR_STRING string)
{
	PR_BYTE bytes;
	ULONG written;

	bytes = _r_str_unicode2multibyte (&string->sr);

	if (bytes)
	{
		WriteFile (hfile, bytes->buffer, (ULONG)bytes->length, &written, NULL);

		_r_obj_dereference (bytes);
	}
}

ULONG_PTR _app_parseline (_Inout_ PR_STRING line)
{
	static R_STRINGREF trim_sr = PR_STRINGREF_INIT (L"\r\n\t\\/ ");
	static R_STRINGREF blacklist_sr = PR_STRINGREF_INIT (L"#<>!@$%^&(){}\"':;/ ");
	static R_STRINGREF blacklist_first_char_sr = PR_STRINGREF_INIT (L".");

	SIZE_T comment_pos;
	SIZE_T space_pos;

	_r_str_trimstring (line, &trim_sr, 0);

	comment_pos = _r_str_findchar (&line->sr, L'#', FALSE);

	if (comment_pos != SIZE_MAX)
		_r_obj_setstringlength (line, comment_pos * sizeof (WCHAR));

	_r_str_replacechar (&line->sr, L'\t', L' ');
	_r_str_trimstring (line, &trim_sr, 0);

	if (_r_obj_isstringempty (line))
		return 0;

	space_pos = _r_str_findchar (&line->sr, L' ', FALSE);

	if (space_pos != SIZE_MAX)
	{
		_r_obj_removestring (line, 0, space_pos + 1);
		_r_str_trimstring (line, &trim_sr, 0);

		// check for spaces
		if (_r_str_findchar (&line->sr, L' ', FALSE) != SIZE_MAX)
			return 0;
	}
	else
	{
		_r_str_trimstring (line, &trim_sr, 0);
	}

	if (_r_obj_isstringempty (line))
		return 0;

	// check first char
	for (SIZE_T i = 0; i < _r_obj_getstringreflength (&blacklist_first_char_sr); i++)
	{
		if (line->buffer[0] == blacklist_first_char_sr.buffer[i])
			return 0;
	}

	// check whole line
	for (SIZE_T i = 0; i < _r_obj_getstringlength (line); i++)
	{
		for (SIZE_T j = 0; j < _r_obj_getstringreflength (&blacklist_sr); j++)
		{
			if (line->buffer[i] == blacklist_sr.buffer[j])
				return 0;
		}
	}

	return _r_obj_getstringrefhash (&line->sr, TRUE);
}

BOOLEAN _app_ishostfoundsafe (_In_ ULONG_PTR hash_code, _In_ PR_STRING host_string)
{
	PR_STRING string;
	BOOLEAN is_found;

	_r_queuedlock_acquireshared (&exclude_lock);

	is_found = (_r_obj_findhashtable (exclude_list, hash_code) != NULL);

	_r_queuedlock_releaseshared (&exclude_lock);

	// remember entries to avoid duplicates
	if (!is_found)
	{
		_r_queuedlock_acquireexclusive (&exclude_lock);

		_r_obj_addhashtableitem (exclude_list, hash_code, NULL);

		_r_queuedlock_releaseexclusive (&exclude_lock);
	}

	if (is_found)
		return is_found;

	_r_queuedlock_acquireshared (&exclude_lock);

	if (!_r_obj_islistempty (exclude_list_mask))
	{
		for (SIZE_T i = 0; i < _r_obj_getlistsize (exclude_list_mask); i++)
		{
			string = _r_obj_getlistitem (exclude_list_mask, i);

			if (string)
			{
				if (_r_str_match (host_string->buffer, string->buffer, TRUE))
				{
					is_found = TRUE;
					break;
				}
			}
		}
	}

	_r_queuedlock_releaseshared (&exclude_lock);

	return is_found;
}

LONG _app_parsefile (_In_ HANDLE hfile_in, _In_opt_ HANDLE hfile_out)
{
	PR_BYTE bytes;
	PR_STRING buffer;
	PR_STRING host_string;
	ULONG_PTR host_hash;
	LONG hosts_count;

	bytes = _r_fs_readfile (hfile_in);

	if (!bytes)
		return 0;

	hosts_count = 0;

	if (bytes->buffer[0] != '<')
	{
		R_BYTEREF line_sr;
		LPSTR tok_buffer;
		LPSTR token;

		tok_buffer = NULL;
		token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

		while (token)
		{
			_r_obj_initializebyteref (&line_sr, token);

			host_string = _r_str_multibyte2unicode (&line_sr);

			if (host_string)
			{
				host_hash = _app_parseline (host_string);

				if (host_hash)
				{
					if (!_app_ishostfoundsafe (host_hash, host_string))
					{
						if (hfile_out)
						{
							if (config.is_hostonly)
							{
								buffer = _r_obj_concatstrings (2, host_string->buffer, config.eol);
							}
							else
							{
								buffer = _r_obj_concatstrings (4, config.hosts_destination->buffer, L" ", host_string->buffer, config.eol);
							}

							_app_writestringtofile (hfile_out, buffer);
							_r_obj_dereference (buffer);

							hosts_count += 1;
						}
						else
						{
							// remember entries to prevent duplicates
							if (_r_str_findchar (&host_string->sr, L'*', FALSE) != SIZE_MAX)
							{
								_r_queuedlock_acquireexclusive (&exclude_lock);

								_r_obj_addlistitem (exclude_list_mask, _r_obj_reference (host_string)); // mask

								_r_queuedlock_releaseexclusive (&exclude_lock);
							}

							hosts_count += 1;
						}
					}
				}

				_r_obj_dereference (host_string);
			}

			token = strtok_s (NULL, "\r\n", &tok_buffer);
		}
	}

	_r_obj_dereference (bytes);

	return hosts_count;
}

PR_HASHTABLE _app_getsourcestable (_In_ HANDLE hfile)
{
	R_BYTEREF line_sr;
	PR_HASHTABLE result;
	PR_STRING url_string;
	PR_BYTE bytes;
	ULONG_PTR hash_code;
	SIZE_T comment_pos;
	LPSTR tok_buffer;
	LPSTR token;

	bytes = _r_fs_readfile (hfile);

	if (!bytes)
		return NULL;

	result = _r_obj_createhashtable_ex (sizeof (SOURCE_INFO_DATA), 64, NULL);

	tok_buffer = NULL;
	token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

	while (token)
	{
		_r_obj_initializebyteref (&line_sr, token);

		url_string = _r_str_multibyte2unicode (&line_sr);

		if (url_string)
		{
			comment_pos = _r_str_findchar (&url_string->sr, L'#', FALSE);

			if (comment_pos != SIZE_MAX)
			{
				_r_obj_setstringlength (url_string, comment_pos * sizeof (WCHAR));
				_r_str_trimstring2 (url_string, L"\r\n\t\\/ ", 0);
			}

			hash_code = _r_obj_getstringrefhash (&url_string->sr, TRUE);

			if (hash_code && !_r_obj_findhashtable (result, hash_code))
			{
				SOURCE_INFO_DATA si_data = {0};

				si_data.source = url_string;
				si_data.source_hash = hash_code;

				_r_obj_addhashtableitem (result, hash_code, &si_data);
			}
			else
			{
				_r_obj_dereference (url_string);
			}
		}

		token = strtok_s (NULL, "\r\n", &tok_buffer);
	}

	_r_obj_dereference (bytes);

	if (!result->count)
	{
		_r_obj_dereference (result);

		return NULL;
	}

	return result;
}

VOID NTAPI _app_downloadandparsethread (_In_ PVOID arglist, _In_ ULONG busy_count)
{
	PSOURCE_INFO_DATA si_data;
	WCHAR path[MAX_PATH];
	WCHAR buffer[128] = {0};
	HANDLE hfile;
	LONG count;

	si_data = (PSOURCE_INFO_DATA)arglist;

	if (!PathIsURL (si_data->source->buffer))
	{
		hfile = CreateFile (si_data->source->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printstatus (FACILITY_FAILURE, GetLastError (), si_data->source->buffer, L"open failure");
		}
		else
		{
			count = _app_parsefile (hfile, si_data->hfile);

			if (count)
			{
				InterlockedAdd (&config.total_hosts, count);
				InterlockedAdd64 (&config.total_size, _r_fs_getsize (hfile));
				InterlockedIncrement (&config.total_sources);
			}

			_r_format_number (buffer, RTL_NUMBER_OF (buffer), count);
			_r_str_append (buffer, RTL_NUMBER_OF (buffer), L" hosts");

			_app_printstatus (count ? FACILITY_SUCCESS : FACILITY_FAILURE, 0, si_data->source->buffer, buffer);

			CloseHandle (hfile);
		}
	}
	else
	{
		if (config.is_nocache)
		{
			_r_str_printf (path, RTL_NUMBER_OF (path), L"%s\\%" TEXT (PR_ULONG_PTR) L".txt", _r_sys_gettempdirectory ()->buffer, si_data->source_hash);
		}
		else
		{
			_r_str_printf (path, RTL_NUMBER_OF (path), L"%s\\%" TEXT (PR_ULONG_PTR) L".txt", _r_obj_getstringorempty (config.cache_dir), si_data->source_hash);
		}

		SetFileAttributes (path, FILE_ATTRIBUTE_NORMAL);
		hfile = CreateFile (path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, config.is_nocache ? CREATE_ALWAYS : OPEN_ALWAYS, config.is_nocache ? FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE : FILE_ATTRIBUTE_TEMPORARY, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printstatus (FACILITY_FAILURE, GetLastError (), si_data->source->buffer, L"open failure");
		}
		else
		{
			HINTERNET hconnect;
			HINTERNET hrequest;

			if (_r_inet_openurl (si_data->hsession, si_data->source, &hconnect, &hrequest, NULL) == ERROR_SUCCESS)
			{
				ULONG status = 0;
				ULONG size = sizeof (status);

				if (WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status, &size, NULL))
				{
					if (status == HTTP_STATUS_OK)
					{
						FILETIME remote_timestamp = {0};
						FILETIME local_timestamp = {0};

						SYSTEMTIME lastmod = {0};
						size = sizeof (lastmod);

						if (WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_LAST_MODIFIED | WINHTTP_QUERY_FLAG_SYSTEMTIME, NULL, &lastmod, &size, NULL))
						{
							SystemTimeToFileTime (&lastmod, &remote_timestamp);
						}

						if (!_r_fs_getsize (hfile) || (GetFileTime (hfile, &local_timestamp, NULL, NULL) && CompareFileTime (&local_timestamp, &remote_timestamp) == -1))
						{
							PR_BYTE bytes;
							ULONG readed;
							ULONG written;

							bytes = _r_obj_createbyte_ex (NULL, 65536);

							if (bytes)
							{
								while (_r_inet_readrequest (hrequest, bytes->buffer, (ULONG)bytes->length, &readed, NULL))
								{
									WriteFile (hfile, bytes->buffer, readed, &written, NULL);
								}

								_r_obj_dereference (bytes);
							}

							SetFileTime (hfile, &remote_timestamp, &remote_timestamp, &remote_timestamp);
						}
					}
				}

				_r_inet_close (hrequest);
				_r_inet_close (hconnect);
			}

			count = _app_parsefile (hfile, si_data->hfile);

			if (count)
			{
				InterlockedAdd (&config.total_hosts, count);
				InterlockedAdd64 (&config.total_size, _r_fs_getsize (hfile));
				InterlockedIncrement (&config.total_sources);
			}

			_r_format_number (buffer, RTL_NUMBER_OF (buffer), count);
			_r_str_append (buffer, RTL_NUMBER_OF (buffer), L" hosts");

			_app_printstatus (count ? FACILITY_SUCCESS : FACILITY_FAILURE, 0, si_data->source->buffer, buffer);

			CloseHandle (hfile);
		}
	}
}

VOID _app_startupdate ()
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

	WCHAR buffer[128];

	PR_HASHTABLE sources_table;
	PSOURCE_INFO_DATA si_data;
	SIZE_T enum_key;

	HANDLE hfile;
	HANDLE hosts_file;
	LONG hosts_count;

	LONG64 start_time;
	HINTERNET hsession;
	R_WORKQUEUE work_queue;

	// parse sources list
	hfile = CreateFile (config.sources_file->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!_r_fs_isvalidhandle (hfile))
	{
		_app_printstatus (FACILITY_FAILURE, GetLastError (), L"Parsing sources", L"open failure");
		return;
	}

	sources_table = _app_getsourcestable (hfile);

	CloseHandle (hfile);

	if (!sources_table)
		return;

	_r_format_number (buffer, RTL_NUMBER_OF (buffer), _r_obj_gethashtablesize (sources_table));
	_r_str_append (buffer, RTL_NUMBER_OF (buffer), L" lists loaded");

	_app_printstatus (FACILITY_SUCCESS, 0, L"Parsing sources", buffer);

	hosts_file = CreateFile (config.hosts_file_temp->buffer, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

	if (!_r_fs_isvalidhandle (hosts_file))
	{
		_app_printstatus (FACILITY_FAILURE, GetLastError (), L"Parsing sources", L"file open failure");
		return;
	}

	// write header
	{
		R_STRINGBUILDER header;

		_r_obj_initializestringbuilder (&header);

		_r_obj_appendstringbuilderformat (&header,
										  L"# This file is automatically generated by %s.%s#%s# DO NOT MODIFY THIS FILE -- YOUR CHANGES WILL BE ERASED!%s#%s# Content merged from the following sources:%s",
										  APP_NAME,
										  config.eol,
										  config.eol,
										  config.eol,
										  config.eol,
										  config.eol
		);

		enum_key = 0;

		while (_r_obj_enumhashtable (sources_table, &si_data, NULL, &enum_key))
		{
			_r_obj_appendstringbuilderformat (&header,
											  L"# %s%s",
											  si_data->source->buffer,
											  config.eol
			);
		}

		if (!config.is_hostonly)
		{
			_r_obj_appendstringbuilderformat (&header,
											  L"%s127.0.0.1 localhost%s::1 localhost%s%s",
											  config.eol,
											  config.eol,
											  config.eol,
											  config.eol
			);
		}

		_app_writestringtofile (hosts_file, header.string);

		_r_obj_deletestringbuilder (&header);
	}

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (exclude_hosts); i++)
	{
		_r_obj_addhashtableitem (exclude_list, _r_obj_getstringrefhash (&exclude_hosts[i], TRUE), NULL);
	}

	// parse whitelist
	{
		hfile = CreateFile (config.whitelist_file->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printstatus (FACILITY_FAILURE, GetLastError (), L"Parsing whitelist", L"open failure");
		}
		else
		{
			hosts_count = _app_parsefile (hfile, NULL);

			_r_format_number (buffer, RTL_NUMBER_OF (buffer), hosts_count + _r_obj_getlistsize (exclude_list_mask));
			_r_str_append (buffer, RTL_NUMBER_OF (buffer), L" hosts");

			_app_printstatus (FACILITY_SUCCESS, 0, L"Parsing whitelist", buffer);

			CloseHandle (hfile);
		}
	}

	// parse userlist
	{
		hfile = CreateFile (config.userlist_file->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printstatus (FACILITY_FAILURE, GetLastError (), L"Parsing userlist", L"open failure");
		}
		else
		{
			hosts_count = _app_parsefile (hfile, hosts_file);

			_r_format_number (buffer, RTL_NUMBER_OF (buffer), hosts_count);
			_r_str_append (buffer, RTL_NUMBER_OF (buffer), L" hosts");

			_app_printstatus (FACILITY_SUCCESS, 0, L"Parsing userlist", buffer);

			if (hosts_count)
			{
				InterlockedAdd (&config.total_hosts, hosts_count);
				InterlockedAdd64 (&config.total_size, _r_fs_getsize (hfile));
				InterlockedIncrement (&config.total_sources);
			}

			CloseHandle (hfile);
		}
	}

	if (!config.is_nocache && !_r_obj_isstringempty (config.cache_dir))
	{
		_r_fs_mkdir (config.cache_dir->buffer);
	}

	start_time = _r_sys_getexecutiontime ();
	hsession = _r_inet_createsession (_r_app_getuseragent ());

	if (!hsession)
	{
		_app_printstatus (FACILITY_FAILURE, GetLastError (), NULL, L"winhttp failure");
	}
	else
	{
		_app_printconsole (L"\r\n");

		enum_key = 0;

		_r_workqueue_initialize (&work_queue, 0, 35, 1000, NULL);

		while (_r_obj_enumhashtable (sources_table, &si_data, NULL, &enum_key))
		{
			si_data->hfile = hosts_file;
			si_data->hsession = hsession;

			_r_workqueue_queueitem (&work_queue, &_app_downloadandparsethread, si_data);
		}

		_r_workqueue_waitforfinish (&work_queue);
		_r_workqueue_destroy (&work_queue);

		CloseHandle (hosts_file); // required!

		SetFileAttributes (config.hosts_file->buffer, FILE_ATTRIBUTE_NORMAL);

		if (!config.is_nobackup)
			_r_fs_movefile (config.hosts_file->buffer, config.hosts_file_backup->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

		_r_fs_movefile (config.hosts_file_temp->buffer, config.hosts_file->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

		WCHAR hosts_format[128];
		WCHAR size_format[128];

		_r_format_number (hosts_format, RTL_NUMBER_OF (hosts_format), config.total_hosts);
		_r_format_bytesize64 (size_format, RTL_NUMBER_OF (size_format), config.total_size);

		_app_printconsole (L"\r\nFinished %" TEXT (PR_LONG) L" sources with %s hosts and %s in %.03f seconds...\r\n", config.total_sources, hosts_format, size_format, _r_sys_finalexecutiontime (start_time));

		_r_inet_close (hsession);
	}

	_r_obj_dereference (sources_table);
}

VOID _app_parsearguments (_In_reads_ (argc) LPCWSTR argv[], _In_ INT argc)
{
	R_STRINGREF key_name;
	R_STRINGREF key_value;

	for (INT i = 0; i < argc; i++)
	{
		_r_obj_initializestringrefconst (&key_name, argv[i]);

		if ((key_name.length <= 2 * sizeof (WCHAR)))
			continue;

		if (*key_name.buffer == L'/' || *key_name.buffer == L'-')
			_r_str_skiplength (&key_name, sizeof (WCHAR));

		if (argc > (i + 1))
		{
			_r_obj_initializestringrefconst (&key_value, argv[i + 1]);
		}
		else
		{
			_r_obj_initializestringrefempty (&key_value);
		}

		if (_r_str_isequal2 (&key_name, L"ip", TRUE))
		{
			if (!key_value.length)
				continue;

			_r_obj_movereference (&config.hosts_destination, _r_obj_createstring3 (&key_value));
		}
		else if (_r_str_isequal2 (&key_name, L"nobackup", TRUE))
		{
			config.is_nobackup = TRUE;
		}
		else if (_r_str_isequal2 (&key_name, L"noresolve", TRUE))
		{
			config.is_hostonly = TRUE;
		}
		else if (_r_str_isequal2 (&key_name, L"nocache", TRUE))
		{
			config.is_nocache = TRUE;
		}
		else if (_r_str_isequal2 (&key_name, L"path", TRUE))
		{
			if (!key_value.length)
				continue;

			_r_obj_movereference (&config.hosts_file, _r_str_expandenvironmentstring (&key_value));
		}
		else if (_r_str_isequal2 (&key_name, L"os", TRUE))
		{
			if (!key_value.length)
				continue;

			WCHAR ch = _r_str_lower (key_value.buffer[0]);

			if (ch == L'w') // windows
			{
				config.eol[0] = L'\r';
				config.eol[1] = L'\n';
				config.eol[2] = UNICODE_NULL;
			}
			else if (ch == L'l') // linux
			{
				config.eol[0] = L'\n';
				config.eol[1] = UNICODE_NULL;
			}
			else if (ch == L'm') // mac
			{
				config.eol[0] = L'\r';
				config.eol[1] = UNICODE_NULL;
			}
		}
		else if (_r_str_isstartswith2 (&key_name, L"help", TRUE))
		{
			_app_printstatus (FACILITY_HELP, 0, NULL, NULL);
			return;
		}
	}
}

VOID _app_setdefaults ()
{
	exclude_list = _r_obj_createhashtable_ex (sizeof (BOOLEAN), 16, NULL);
	exclude_list_mask = _r_obj_createlist_ex (16, &_r_obj_dereference);

	if (!config.is_hostonly && _r_obj_isstringempty (config.hosts_destination))
		_r_obj_movereference (&config.hosts_destination, _r_obj_createstring (L"0.0.0.0"));

	if (_r_obj_isstringempty (config.hosts_destination))
		config.is_hostonly = TRUE;

	_r_obj_movereference (&config.sources_file, _r_obj_concatstrings (2, _r_app_getdirectory ()->buffer, L"\\hosts_sources.dat"));
	_r_obj_movereference (&config.userlist_file, _r_obj_concatstrings (2, _r_app_getdirectory ()->buffer, L"\\hosts_userlist.dat"));
	_r_obj_movereference (&config.whitelist_file, _r_obj_concatstrings (2, _r_app_getdirectory ()->buffer, L"\\hosts_whitelist.dat"));
	_r_obj_movereference (&config.cache_dir, _r_obj_concatstrings (2, _r_app_getprofiledirectory ()->buffer, L"\\cache"));

	// set hosts path
	if (_r_obj_isstringempty (config.hosts_file))
		_r_obj_movereference (&config.hosts_file, _r_path_search (L".\\hosts"));

	_r_obj_movereference (&config.hosts_file_temp, _r_obj_concatstrings (2, _r_obj_getstring (config.hosts_file), L".tmp"));
	_r_obj_movereference (&config.hosts_file_backup, _r_obj_concatstrings (2, _r_obj_getstring (config.hosts_file), L".bak"));

	// set end-of-line type
	if (_r_str_isempty (config.eol))
	{
		config.eol[0] = L'\r';
		config.eol[1] = L'\n';
		config.eol[2] = UNICODE_NULL;
	}
}

INT _cdecl wmain (INT argc, LPCWSTR argv[])
{
	INT mode;

	mode = _setmode (_fileno (stdin), _O_U16TEXT);
	mode = _setmode (_fileno (stdout), _O_U16TEXT);
	mode = _setmode (_fileno (stderr), _O_U16TEXT);

	SetConsoleTitle (_r_app_getname ());

	if (_r_app_initialize ())
	{
		_app_printconsole (L"%s %s\r\n%s\r\n\r\n", _r_app_getname (), _r_app_getversion (), _r_app_getcopyright ());

		if (argc <= 1)
		{
			_app_printstatus (FACILITY_HELP, 0, NULL, NULL);
		}
		else
		{
			_app_parsearguments (argv, argc);

			_app_setdefaults ();

			_app_printconsole (L"Path: %s\r\nSources: %s\r\nUserlist: %s\r\nWhitelist: %s\r\nResolver: %s\r\n\r\n",
							   _r_obj_getstring (config.hosts_file),
							   _r_obj_getstring (config.sources_file),
							   _r_obj_getstring (config.userlist_file),
							   _r_obj_getstring (config.whitelist_file),
							   config.is_hostonly ? L"<disabled>" : _r_obj_getstring (config.hosts_destination)
			);

			_app_startupdate ();
		}
	}

	return ERROR_SUCCESS;
}

// hostsmgr
// Copyright (c) 2016-2021 Henry++

#include <io.h>
#include <fcntl.h>

#include "routine.h"

#include "main.h"
#include "rapp.h"

#include "resource.h"

STATIC_DATA config;

R_SPINLOCK exclude_lock;
R_SPINLOCK parsing_lock;

PR_HASHTABLE exclude_list = NULL;
PR_LIST exclude_list_mask = NULL;

FORCEINLINE LONG64 PerformanceCounter ()
{
	LARGE_INTEGER li = {0};
	QueryPerformanceCounter (&li);

	return li.QuadPart;
}

FORCEINLINE LONG64 PerformanceFrequency ()
{
	LARGE_INTEGER li = {0};
	QueryPerformanceFrequency (&li);

	return li.QuadPart;
}

VOID _app_printconsole (LPCWSTR format, ...)
{
	va_list arg_ptr;
	PR_STRING string;
	HANDLE hstdout;

	hstdout = GetStdHandle (STD_OUTPUT_HANDLE);

	if (!format || !_r_fs_isvalidhandle (hstdout))
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
			if (!_r_str_isempty (name))
			{
				if (!_r_str_isempty (description))
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
			if (!_r_str_isempty (name))
			{
				if (!_r_str_isempty (description))
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

	bytes = _r_str_unicode2multibyteex (string->buffer, string->length);

	if (bytes)
	{
		WriteFile (hfile, bytes->buffer, (ULONG)bytes->length, &written, NULL);

		_r_obj_dereference (bytes);
	}
}

SIZE_T _app_parseline (_Inout_ PR_STRING line)
{
	SIZE_T comment_start_pos;
	SIZE_T space_pos;

	_r_obj_trimstring (line, L"\r\n\t\\/ ");

	comment_start_pos = _r_str_findchar (line->buffer, L'#');

	if (comment_start_pos == 0)
		return 0;

	if (comment_start_pos != SIZE_MAX)
		_r_obj_setstringsize (line, comment_start_pos * sizeof (WCHAR));

	_r_str_replacechar (line->buffer, L'\t', L' ');
	_r_obj_trimstring (line, L"\r\n\\/ ");

	if (_r_obj_isstringempty (line))
		return 0;

	space_pos = _r_str_findchar (line->buffer, L' ');

	if (space_pos != SIZE_MAX)
	{
		_r_obj_removestring (line, 0, space_pos + 1);
		_r_obj_trimstring (line, L"\r\n\\/ ");

		// check for spaces
		if (_r_str_findchar (line->buffer, L' ') != SIZE_MAX)
			return 0;
	}
	else
	{
		_r_obj_trimstring (line, L"\r\n\\/ ");
	}

	if (line->buffer[0] == UNICODE_NULL || line->buffer[0] == L'#' || line->buffer[0] == L'<')
		return 0;

	if (!_r_obj_isstringempty (line))
		return _r_str_hash (line->buffer);

	return 0;
}

BOOLEAN _app_ishostfoundsafe (_In_ SIZE_T hash_code, _In_ PR_STRING host_string)
{
	PR_STRING string;
	BOOLEAN is_found;

	if (!hash_code)
		return TRUE;

	_r_spinlock_acquireshared (&exclude_lock);

	is_found = (_r_obj_findhashtable (exclude_list, hash_code) != NULL);

	_r_spinlock_releaseshared (&exclude_lock);

	// remember entries to avoid duplicates
	if (!is_found)
	{
		_r_spinlock_acquireexclusive (&exclude_lock);

		_r_obj_addhashtableitem (exclude_list, hash_code, NULL);

		_r_spinlock_releaseexclusive (&exclude_lock);
	}

	if (is_found)
		return is_found;

	_r_spinlock_acquireshared (&exclude_lock);

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

	_r_spinlock_releaseshared (&exclude_lock);

	return is_found;
}

LONG _app_parsefile (_In_ HANDLE hfile_in, _In_opt_ HANDLE hfile_out)
{
	PR_BYTE bytes;
	PR_STRING buffer;
	PR_STRING host_string;
	SIZE_T host_hash;
	SIZE_T length;
	LONG hosts_count;

	if (!(length = (SIZE_T)_r_fs_getsize (hfile_in)))
		return 0;

	bytes = _r_fs_readfile (hfile_in, (ULONG)length);

	if (!bytes)
		return 0;

	hosts_count = 0;

	if (bytes->buffer[0] != '<')
	{
		LPSTR tok_buffer = NULL;
		LPSTR token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

		while (token)
		{
			_r_str_trim_a (token, "\r\n\t\\/ ");
			host_string = _r_str_multibyte2unicode (token);

			if (host_string)
			{
				host_hash = _app_parseline (host_string);

				if (!_app_ishostfoundsafe (host_hash, host_string))
				{
					if (hfile_out)
					{
						if (config.is_noresolver)
						{
							buffer = _r_format_string (L"%s%s", host_string->buffer, config.eol);
						}
						else
						{
							buffer = _r_format_string (L"%s %s%s", config.hosts_destination->buffer, host_string->buffer, config.eol);
						}

						if (buffer)
						{
							_app_writestringtofile (hfile_out, buffer);
							_r_obj_dereference (buffer);

							hosts_count += 1;
						}
					}
					else
					{
						// remember entries to prevent duplicates
						if (_r_str_findchar (host_string->buffer, L'*') != SIZE_MAX)
						{
							_r_spinlock_acquireexclusive (&exclude_lock);

							_r_obj_addlistitem (exclude_list_mask, _r_obj_reference (host_string)); // mask

							_r_spinlock_releaseexclusive (&exclude_lock);
						}

						hosts_count += 1;
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
	PR_HASHTABLE result;
	PR_STRING url_string;
	PR_BYTE bytes;
	SIZE_T hash_code;
	SIZE_T comment_pos;
	SIZE_T length;

	result = _r_obj_createhashtableex (sizeof (SOURCE_INFO_DATA), 64, NULL);

	length = (SIZE_T)_r_fs_getsize (hfile);

	if (length)
	{
		bytes = _r_fs_readfile (hfile, (ULONG)length);

		if (bytes)
		{
			LPSTR tok_buffer = NULL;
			LPSTR token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

			while (token)
			{
				_r_str_trim_a (token, "\r\n\t\\/ ");

				url_string = _r_str_multibyte2unicode (token);

				if (url_string)
				{
					comment_pos = _r_str_findchar (url_string->buffer, L'#');

					if (comment_pos != SIZE_MAX)
					{
						_r_obj_setstringsize (url_string, comment_pos * sizeof (WCHAR));
						_r_obj_trimstring (url_string, L"\r\n\t\\/ ");
					}

					hash_code = _r_str_hash (url_string->buffer);

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
		}
	}

	if (!result->count)
	{
		_r_obj_dereference (result);

		return NULL;
	}

	return result;
}

THREAD_API _app_downloadandparsethread (PVOID lparam)
{
	PSOURCE_INFO_DATA si_data;
	WCHAR path[MAX_PATH];
	WCHAR buffer[128];
	HANDLE hfile;
	LONG count;

	InterlockedIncrement (&config.threads_count);

	_r_spinlock_acquireshared (&parsing_lock);

	si_data = (PSOURCE_INFO_DATA)lparam;

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
			PR_STRING temp_path = _r_str_expandenvironmentstring (L"%temp%");

			_r_str_printf (path, RTL_NUMBER_OF (path), L"%s\\%" TEXT (PR_SIZE_T) L".txt", _r_obj_getstringorempty (temp_path), si_data->source_hash);

			if (temp_path)
				_r_obj_dereference (temp_path);
		}
		else
		{
			_r_str_printf (path, RTL_NUMBER_OF (path), L"%s\\%" TEXT (PR_SIZE_T) L".txt", _r_obj_getstringorempty (config.cache_dir), si_data->source_hash);
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

			if (_r_inet_openurl (si_data->hsession, si_data->source->buffer, &hconnect, &hrequest, NULL) == ERROR_SUCCESS)
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
							SystemTimeToFileTime (&lastmod, &remote_timestamp);

						if (!_r_fs_getsize (hfile) || (GetFileTime (hfile, &local_timestamp, NULL, NULL) && CompareFileTime (&local_timestamp, &remote_timestamp) == -1))
						{
							ULONG readed;
							ULONG written;
							PR_BYTE bytes;

							bytes = _r_obj_createbyteex (NULL, 65536);

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

	SetEvent (config.hevent_stop_thread);

	_r_spinlock_releaseshared (&parsing_lock);

	InterlockedDecrement (&config.threads_count);

	return ERROR_SUCCESS;
}

VOID _app_startupdate ()
{
	PR_HASHTABLE sources_table;
	PSOURCE_INFO_DATA si_data;
	SIZE_T enum_key;

	WCHAR buffer[128];

	HANDLE hfile;
	HANDLE hosts_file;
	LPCWSTR path;
	LONG hosts_count;

	// predefined whitelisted hosts
	LPCWSTR exclude_hosts[] = {
		L"local",
		L"localhost",
		L"localhost.localdomain",
		L"broadcasthost",
		L"notice",
		L"ip6-loopback",
		L"ip6-localhost",
		L"ip6-localnet",
		L"ip6-mcastprefix",
		L"ip6-allnodes",
		L"ip6-allrouters",
		L"ip6-allhosts",
		L"0.0.0.0",
	};

	// parse sources list
	path = config.sources_file->buffer;
	hfile = CreateFile (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

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

	path = _r_obj_getstring (config.hosts_file_temp);
	hosts_file = CreateFile (path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

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

		_r_obj_appendstringbuilderformat (&header,
										  L"%s127.0.0.1 localhost%s::1 localhost%s%s",
										  config.eol,
										  config.eol,
										  config.eol,
										  config.eol
		);

		_app_writestringtofile (hosts_file, header.string);

		_r_obj_deletestringbuilder (&header);
	}

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (exclude_hosts); i++)
		_r_obj_addhashtableitem (exclude_list, _r_str_hash (exclude_hosts[i]), NULL);

	// parse whitelist
	{
		path = _r_obj_getstring (config.whitelist_file);
		hfile = CreateFile (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

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
		path = _r_obj_getstring (config.userlist_file);
		hfile = CreateFile (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

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
		_r_fs_mkdir (config.cache_dir->buffer);

	LONG64 start_time = PerformanceCounter ();

	HINTERNET hsession = _r_inet_createsession (_r_app_getuseragent ());

	if (!hsession)
	{
		_app_printstatus (FACILITY_FAILURE, GetLastError (), NULL, L"winhttp failure");
	}
	else
	{
		_app_printconsole (L"\r\n");

		enum_key = 0;

		while (_r_obj_enumhashtable (sources_table, &si_data, NULL, &enum_key))
		{
			si_data->hfile = hosts_file;
			si_data->hsession = hsession;

			while (TRUE)
			{
				if (!_r_spinlock_islocked (&parsing_lock) || (config.threads_count < config.processor_count))
					break;

				WaitForSingleObjectEx (config.hevent_stop_thread, 100, FALSE);
			}

			_r_sys_createthread2 (&_app_downloadandparsethread, si_data);
		}

		// wait for finish
		while (TRUE)
		{
			ULONG code = WaitForSingleObjectEx (config.hevent_stop_thread, 100, FALSE);

			// specify right codes
			if (code != WAIT_OBJECT_0 && code != WAIT_TIMEOUT)
				break;

			if (!_r_spinlock_islocked (&parsing_lock))
				break;
		}

		CloseHandle (hosts_file); // required!

		SetFileAttributes (config.hosts_file->buffer, FILE_ATTRIBUTE_NORMAL);

		if (!config.is_nobackup)
			_r_fs_movefile (config.hosts_file->buffer, config.hosts_file_backup->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

		_r_fs_movefile (config.hosts_file_temp->buffer, config.hosts_file->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

		WCHAR hosts_format[128];
		WCHAR size_format[128];

		_r_format_number (hosts_format, RTL_NUMBER_OF (hosts_format), config.total_hosts);
		_r_format_bytesize64 (size_format, RTL_NUMBER_OF (size_format), config.total_size);

		_app_printconsole (L"\r\nFinished %" TEXT (PR_LONG) L" sources with %s hosts and %s in %.03f seconds...\r\n", config.total_sources, hosts_format, size_format, ((PerformanceCounter () - start_time) * 1000.0) / PerformanceFrequency () / 1000.0);

		_r_inet_close (hsession);
	}

	_r_obj_dereference (sources_table);
}

VOID _app_parsearguments (INT argc, LPCWSTR argv[])
{
	for (INT i = 0; i < argc; i++)
	{
		if (argv[i][0] == L'/' || argv[i][0] == L'-')
		{
			LPCWSTR name = argv[i] + 1;
			LPCWSTR value = argv[i + 1];

			if (_r_str_compare (name, L"ip") == 0)
			{
				_r_obj_movereference (&config.hosts_destination, _r_obj_createstring (value));
			}
			else if (_r_str_compare (name, L"nobackup") == 0)
			{
				config.is_nobackup = TRUE;
			}
			else if (_r_str_compare (name, L"noresolve") == 0)
			{
				config.is_noresolver = TRUE;
			}
			else if (_r_str_compare (name, L"nocache") == 0)
			{
				config.is_nocache = TRUE;
			}
			else if (_r_str_compare (name, L"path") == 0)
			{
				_r_obj_movereference (&config.hosts_file, _r_str_expandenvironmentstring (value));
			}
			else if (_r_str_compare (name, L"thread") == 0)
			{
				config.processor_count = _r_str_tolong (value);
			}
			else if (_r_str_compare (name, L"os") == 0)
			{
				WCHAR ch = _r_str_lower (value[0]);

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
			else if (name[0] == L'h' || _r_str_compare (name, L"help") == 0)
			{
				_app_printstatus (FACILITY_HELP, 0, NULL, NULL);
				return;
			}
		}
	}
}

VOID _app_setdefaults ()
{
	if (!config.processor_count)
		config.processor_count = _r_sys_getprocessorscount ();

	config.processor_count = _r_calc_clamp32 (config.processor_count, 1, _r_sys_getprocessorscount ());

	config.hevent_stop_thread = CreateEvent (NULL, FALSE, FALSE, NULL);

	exclude_list = _r_obj_createhashtableex (sizeof (BOOLEAN), 16, NULL);
	exclude_list_mask = _r_obj_createlistex (16, &_r_obj_dereference);

	_r_spinlock_initialize (&exclude_lock);
	_r_spinlock_initialize (&parsing_lock);

	if (!config.is_noresolver && _r_obj_isstringempty (config.hosts_destination))
		_r_obj_movereference (&config.hosts_destination, _r_obj_createstring (L"0.0.0.0"));

	if (_r_obj_isstringempty (config.hosts_destination))
		config.is_noresolver = TRUE;

	_r_obj_movereference (&config.sources_file, _r_format_string (L"%s\\hosts_sources.dat", _r_app_getdirectory ()));
	_r_obj_movereference (&config.userlist_file, _r_format_string (L"%s\\hosts_userlist.dat", _r_app_getdirectory ()));
	_r_obj_movereference (&config.whitelist_file, _r_format_string (L"%s\\hosts_whitelist.dat", _r_app_getdirectory ()));
	_r_obj_movereference (&config.cache_dir, _r_format_string (L"%s\\cache", _r_app_getprofiledirectory ()));

	// set hosts path
	if (_r_obj_isstringempty (config.hosts_file))
		_r_obj_movereference (&config.hosts_file, _r_str_expandenvironmentstring (L".\\hosts"));

	_r_obj_movereference (&config.hosts_file_temp, _r_format_string (L"%s.tmp", _r_obj_getstring (config.hosts_file)));
	_r_obj_movereference (&config.hosts_file_backup, _r_format_string (L"%s.bak", _r_obj_getstring (config.hosts_file)));

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
	_setmode (_fileno (stdin), _O_U16TEXT);
	_setmode (_fileno (stdout), _O_U16TEXT);
	_setmode (_fileno (stderr), _O_U16TEXT);

	RtlSecureZeroMemory (&config, sizeof (config));

	SetConsoleTitle (APP_NAME);

	if (_r_app_initialize ())
	{
		_app_printconsole (L"%s %s\r\n%s\r\n\r\n", APP_NAME, APP_VERSION, APP_COPYRIGHT);

		if (argc <= 1)
		{
			_app_printstatus (FACILITY_HELP, 0, NULL, NULL);
		}
		else
		{
			_app_parsearguments (argc, argv);

			_app_setdefaults ();

			_app_printconsole (L"Path: %s\r\nSources: %s\r\nUserlist: %s\r\nWhitelist: %s\r\nDestination: %s\r\nCPU cores used: %" PR_LONG L"\r\n\r\n",
							   _r_obj_getstring (config.hosts_file),
							   _r_obj_getstring (config.sources_file),
							   _r_obj_getstring (config.userlist_file),
							   _r_obj_getstring (config.whitelist_file),
							   config.is_noresolver ? L"<disabled>" : _r_obj_getstring (config.hosts_destination),
							   config.processor_count
			);

			_app_startupdate ();
		}
	}

	return ERROR_SUCCESS;
}

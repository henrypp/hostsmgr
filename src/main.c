// hostsmgr
// Copyright (c) 2016-2021 Henry++

#include <io.h>
#include <conio.h>
#include <fcntl.h>

#include "routine.h"

#include "main.h"
#include "rapp.h"

#include "resource.h"

STATIC_DATA config;

typedef enum _FACILITY
{
	Init,
	Success,
	Failure,
	Help,
} FACILITY;

VOID _app_printdata (FACILITY fac, ULONG code, LPCWSTR description, LPCWSTR format, ...)
{
	va_list arg_ptr;
	PR_STRING string = NULL;

	if (format)
	{
		va_start (arg_ptr, format);
		string = _r_format_string_v (format, arg_ptr);
		va_end (arg_ptr);
	}

	switch (fac)
	{
		case Init:
		{
			if (!_r_obj_isstringempty (string) && !_r_str_isempty (description))
			{
				wprintf (L"%s: %s", string->buffer, description);
			}
			else if (!_r_obj_isstringempty (string))
			{
				wprintf (L"%s", string->buffer);
			}

			break;
		}

		case Success:
		{
			if (!_r_obj_isstringempty (string))
			{
				wprintf (L" (%s)\r\n", string->buffer);
			}

			break;
		}

		case Failure:
		{
			if (!_r_obj_isstringempty (string) && !_r_str_isempty (description))
			{
				wprintf (L" (%s / %s / 0x%08" TEXT (PRIX32) L")\r\n", _r_obj_getstringorempty (string), description, code);
			}
			else if (!_r_obj_isstringempty (string))
			{
				if (code)
				{
					wprintf (L" (%s / 0x%08" TEXT (PRIX32) L")\r\n", _r_obj_getstringorempty (string), code);
				}
				else
				{
					wprintf (L" (%s)\r\n", _r_obj_getstringorempty (string));
				}
			}

			break;
		}

		case Help:
		{
			wprintf (L"Usage:\r\n\
hostsmgr -ip 127.0.0.1 -os win -path [out file]\r\n\
\r\n\
Command line:\r\n\
-ip         ip address to be set as resolver (def. 0.0.0.0)\r\n\
-os         new line format; \"win\", \"linux\" & \"mac\" (def. \"win\")\r\n\
-path       output file location (def. \".\\hosts\")\r\n\
-nobackup   do not create backup for output file (opt.)\r\n\
-noresolve  do not set resolver, just generate ip list (opt.)\r\n\
-nocache    do not use cache files, load from inet (opt.)\r\n\
\r\n");

			break;
		}
	}

	if (string)
		_r_obj_dereference (string);
}

VOID _app_writeunicodeasansi (HANDLE hfile, LPCWSTR text)
{
	PR_BYTE bytes;
	ULONG written;

	if (_r_str_isempty (text))
		return;

	bytes = _r_str_unicode2multibyte (text);

	if (bytes)
	{
		WriteFile (hfile, bytes->buffer, (ULONG)bytes->length, &written, NULL);

		_r_obj_dereference (bytes);
	}
}

SIZE_T _app_parseline (PR_STRING line)
{
	SIZE_T length;
	SIZE_T comment_start_pos;
	SIZE_T space_pos;

	_r_obj_trimstring (line, L"\r\n\t\\/ ");

	length = _r_obj_getstringlength (line);
	comment_start_pos = _r_str_findchar (line->buffer, length, L'#');

	if (comment_start_pos == 0)
		return 0;

	if (comment_start_pos != SIZE_MAX)
		_r_obj_setstringsize (line, comment_start_pos * sizeof (WCHAR));

	_r_str_replacechar (line->buffer, _r_obj_getstringlength (line), L'\t', L' ');
	_r_obj_trimstring (line, L"\r\n\\/ ");

	if (_r_obj_isstringempty (line))
		return 0;

	length = _r_obj_getstringlength (line);
	space_pos = _r_str_findchar (line->buffer, length, L' ');

	if (space_pos != SIZE_MAX)
	{
		_r_obj_removestring (line, 0, space_pos + 1);
		_r_obj_trimstring (line, L"\r\n\\/ ");

		length = _r_obj_getstringlength (line);

		// check for spaces
		if (_r_str_findchar (line->buffer, length, L' ') != SIZE_MAX)
			return 0;
	}
	else
	{
		_r_obj_trimstring (line, L"\r\n\\/ ");
	}

	if (!_r_obj_isstringempty (line))
		return _r_obj_getstringhash (line);

	return 0;
}

SIZE_T _app_parsefile (HANDLE hfile, HANDLE hwritefile, PR_HASHTABLE exclude_list, PR_LIST exclude_list_mask)
{
	PR_BYTE bytes;
	SIZE_T length = (SIZE_T)_r_fs_getsize (hfile);
	SIZE_T hosts_count = 0;

	if (!length)
		return 0;

	bytes = _r_fs_readfile (hfile, (ULONG)length);

	if (bytes)
	{
		if (bytes->buffer && bytes->buffer[0] != '<')
		{
			LPSTR tok_buffer = NULL;
			LPSTR token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

			while (token)
			{
				_r_str_trim_a (token, "\r\n\t\\/ ");
				PR_STRING host_string = _r_str_multibyte2unicode (token);

				if (host_string)
				{
					SIZE_T host_hash = _app_parseline (host_string);

					if (host_hash && host_string->buffer[0] != UNICODE_NULL && host_string->buffer[0] != L'#' && !_r_obj_findhashtable (exclude_list, host_hash))
					{
						if (_r_fs_isvalidhandle (hwritefile))
						{
							BOOLEAN is_whitelisted = FALSE;

							// remember entries to prevent duplicates
							_r_obj_addhashtableitem2 (exclude_list, host_hash, NULL);

							for (SIZE_T i = 0; i < _r_obj_getlistsize (exclude_list_mask); i++)
							{
								PR_STRING string = _r_obj_getlistitem (exclude_list_mask, i);

								if (_r_str_match (host_string->buffer, _r_obj_getstring (string), TRUE))
								{
									is_whitelisted = TRUE;
									break;
								}
							}

							if (!is_whitelisted)
							{
								PR_STRING buffer;

								if (config.is_noresolver || _r_obj_isstringempty (config.hosts_destination))
								{
									buffer = _r_format_string (L"%s%s", host_string->buffer, config.eol);
								}
								else
								{
									buffer = _r_format_string (L"%s %s%s", _r_obj_getstringorempty (config.hosts_destination), host_string->buffer, config.eol);
								}

								if (buffer)
								{
									_app_writeunicodeasansi (hwritefile, buffer->buffer);
									_r_obj_dereference (buffer);

									hosts_count += 1;
								}
							}
						}
						else
						{
							// remember entries to prevent duplicates
							if (_r_str_findchar (host_string->buffer, _r_obj_getstringlength (host_string), L'*') != SIZE_MAX)
							{
								_r_obj_addlistitem (exclude_list_mask, _r_obj_reference (host_string)); // mask
							}
							else
							{
								_r_obj_addhashtableitem2 (exclude_list, host_hash, NULL);
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
	}

	return hosts_count;
}

VOID _app_parsesource (HINTERNET hsession, HANDLE hosts_file, LPCWSTR source, PR_HASHTABLE exclude_list, PR_LIST exclude_list_mask, PSIZE_T ptotal_hosts, PSIZE_T ptotal_sources)
{
	HANDLE hfile;
	SIZE_T count;
	SIZE_T source_hash;
	WCHAR number_string[128];

	if (!PathIsURL (source))
	{
		hfile = CreateFile (source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printdata (Failure, GetLastError (), source, L"open failure");
		}
		else
		{
			count = _app_parsefile (hfile, hosts_file, exclude_list, exclude_list_mask);

			if (ptotal_hosts)
				*ptotal_hosts += count;

			if (ptotal_sources)
				*ptotal_sources += 1;

			_r_format_number (number_string, RTL_NUMBER_OF (number_string), count);
			_app_printdata (Success, 0, NULL, L"%s hosts", number_string);

			CloseHandle (hfile);
		}
	}
	else
	{
		source_hash = _r_str_hash (source, _r_str_length (source));

		WCHAR path[MAX_PATH];

		if (config.is_nocache)
		{
			PR_STRING temp_path = _r_str_expandenvironmentstring (L"%temp%");

			_r_str_printf (path, RTL_NUMBER_OF (path), L"%s\\%" TEXT (PR_SIZE_T) L".txt", _r_obj_getstringorempty (temp_path), source_hash);

			if (temp_path)
				_r_obj_dereference (temp_path);
		}
		else
		{
			_r_str_printf (path, RTL_NUMBER_OF (path), L"%s\\%" TEXT (PR_SIZE_T) L".txt", _r_obj_getstringorempty (config.cache_dir), source_hash);
		}

		SetFileAttributes (path, FILE_ATTRIBUTE_NORMAL);
		hfile = CreateFile (path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, config.is_nocache ? CREATE_ALWAYS : OPEN_ALWAYS, config.is_nocache ? FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE : FILE_ATTRIBUTE_TEMPORARY, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printdata (Failure, GetLastError (), path, L"open failure");
		}
		else
		{
			HINTERNET hconnect;
			HINTERNET hrequest;

			if (_r_inet_openurl (hsession, source, &hconnect, &hrequest, NULL) == ERROR_SUCCESS)
			{
				ULONG status;
				ULONG size = sizeof (status);

				if (WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status, &size, NULL))
				{
					if (status >= HTTP_STATUS_OK && status <= HTTP_STATUS_PARTIAL_CONTENT)
					{
						FILETIME remote_timestamp = {0};
						FILETIME local_timestamp = {0};

						SYSTEMTIME lastmod = {0};
						size = sizeof (lastmod);

						if (WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_LAST_MODIFIED | WINHTTP_QUERY_FLAG_SYSTEMTIME, NULL, &lastmod, &size, NULL))
							SystemTimeToFileTime (&lastmod, &remote_timestamp);

						if (!_r_fs_getsize (hfile) || (GetFileTime (hfile, NULL, NULL, &local_timestamp) && CompareFileTime (&local_timestamp, &remote_timestamp) == -1))
						{
							ULONG readed;
							ULONG written;
							ULONG length;
							PR_BYTE bytes;

							length = 32768;
							bytes = _r_obj_createbyteex (NULL, length);

							if (bytes)
							{
								while (_r_inet_readrequest (hrequest, bytes->buffer, length - 1, &readed, NULL))
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

			count = _app_parsefile (hfile, hosts_file, exclude_list, exclude_list_mask);

			if (count)
			{
				if (ptotal_hosts)
					*ptotal_hosts += count;

				if (ptotal_sources)
					*ptotal_sources += 1;
			}

			_r_format_number (number_string, RTL_NUMBER_OF (number_string), count);

			_app_printdata (count ? Success : Failure, 0, NULL, L"%s hosts", number_string);

			CloseHandle (hfile);

			if (!config.is_nocache)
				SetFileAttributes (path, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_TEMPORARY);
		}
	}
}

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

VOID _app_startupdate ()
{
	PR_HASHTABLE exclude_list = NULL;
	PR_LIST exclude_list_mask = NULL;

	HANDLE hfile;
	HANDLE hsources_file;
	HANDLE hosts_file;
	LPCWSTR path;
	SIZE_T count;

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

	exclude_list = _r_obj_createhashtableex (sizeof (void*), 0x1000, NULL);

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (exclude_hosts); i++)
		_r_obj_addhashtableitem2 (exclude_list, _r_str_hash (exclude_hosts[i], _r_str_length (exclude_hosts[i])), NULL);

	PR_LIST sources_arr = _r_obj_createlistex (0x50, &_r_obj_dereference);

	_app_printdata (Init, 0, L"sources list", L"Parsing");

	// parse sources list
	path = _r_obj_getstring (config.sources_file);
	hsources_file = CreateFile (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!_r_fs_isvalidhandle (hsources_file))
	{
		_app_printdata (Failure, GetLastError (), path, L"open failure");
		return;
	}
	else
	{
		SIZE_T length = (SIZE_T)_r_fs_getsize (hsources_file);

		if (length)
		{
			PR_BYTE bytes = _r_fs_readfile (hsources_file, (ULONG)length);

			if (bytes)
			{
				LPSTR tok_buffer;
				LPSTR token = strtok_s (bytes->buffer, "\r\n", &tok_buffer);

				while (token)
				{
					_r_str_trim_a (token, "\r\n\t\\/ ");

					PR_STRING url_string = _r_str_multibyte2unicode (token);

					if (url_string)
					{
						SIZE_T pos = _r_str_findchar (url_string->buffer, _r_obj_getstringlength (url_string), L'#');

						if (pos != SIZE_MAX)
						{
							_r_obj_setstringsize (url_string, pos * sizeof (WCHAR));
							_r_obj_trimstring (url_string, L"\r\n\t\\/ ");
						}

						if (!_r_obj_isstringempty (url_string))
						{
							_r_obj_addlistitem (sources_arr, url_string);
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

		WCHAR number_string[128];
		_r_format_number (number_string, RTL_NUMBER_OF (number_string), _r_obj_getlistsize (sources_arr));

		_app_printdata (Success, 0, NULL, L"%s lists loaded", number_string);

		CloseHandle (hsources_file);
	}

	SIZE_T total_hosts = 0;
	SIZE_T total_sources = 0;

	path = _r_obj_getstring (config.hosts_file_temp);
	hosts_file = CreateFile (path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

	if (!_r_fs_isvalidhandle (hosts_file))
	{
		_app_printdata (Failure, GetLastError (), path, L"create failure");
		return;
	}

	// write header
	{
		WCHAR header[1024];

		_r_str_printf (header,
					   RTL_NUMBER_OF (header),
					   L"# This file is automatically generated by %s.%s#%s# DO NOT MODIFY THIS FILE -- YOUR CHANGES WILL BE ERASED!%s#%s# Content merged from the following sources:%s",
					   APP_NAME,
					   config.eol,
					   config.eol,
					   config.eol,
					   config.eol,
					   config.eol
		);

		for (SIZE_T i = 0; i < _r_obj_getlistsize (sources_arr); i++)
		{
			PR_STRING ptr_item = _r_obj_getlistitem (sources_arr, i);

			if (_r_obj_isstringempty (ptr_item))
				continue;

			_r_str_appendformat (header,
								 RTL_NUMBER_OF (header),
								 L"# %s%s",
								 ptr_item->buffer,
								 config.eol
			);
		}

		_r_str_appendformat (header,
							 RTL_NUMBER_OF (header),
							 L"%s127.0.0.1 localhost%s::1 localhost%s%s",
							 config.eol,
							 config.eol,
							 config.eol,
							 config.eol
		);

		_app_writeunicodeasansi (hosts_file, header);
	}

	// parse whitelist
	{
		_app_printdata (Init, 0, L"whitelist", L"Parsing");

		path = _r_obj_getstring (config.whitelist_file);
		hfile = CreateFile (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printdata (Failure, GetLastError (), path, L"open failure");
		}
		else
		{
			exclude_list_mask = _r_obj_createlistex (0x100, &_r_obj_dereference);

			count = _app_parsefile (hfile, NULL, exclude_list, exclude_list_mask);

			WCHAR hosts_string[128];
			WCHAR masksFormat[128];

			_r_format_number (hosts_string, RTL_NUMBER_OF (hosts_string), count);
			_r_format_number (masksFormat, RTL_NUMBER_OF (masksFormat), _r_obj_getlistsize (exclude_list_mask));

			_app_printdata (Success, 0, NULL, L"%s hosts, %s masks", hosts_string, masksFormat);

			CloseHandle (hfile);
		}
	}

	// parse userlist
	{
		_app_printdata (Init, 0, L"userlist", L"Parsing");

		path = _r_obj_getstring (config.userlist_file);
		hfile = CreateFile (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			_app_printdata (Failure, GetLastError (), path, L"open failure");
		}
		else
		{
			count = _app_parsefile (hfile, hosts_file, exclude_list, exclude_list_mask);

			WCHAR hosts_string[128];

			_r_format_number (hosts_string, RTL_NUMBER_OF (hosts_string), count);

			_app_printdata (Success, 0, NULL, L"%s hosts", hosts_string);

			total_hosts += count;
			total_sources += 1;

			CloseHandle (hfile);
		}
	}

	if (!config.is_nocache && !_r_obj_isstringempty (config.cache_dir))
		_r_fs_mkdir (config.cache_dir->buffer);

	LONG64 start_time = PerformanceCounter ();

	HINTERNET hsession = _r_inet_createsession (_r_app_getuseragent ());

	if (!hsession)
	{
		_app_printdata (Failure, GetLastError (), NULL, L"winhttp failure");
	}
	else
	{
		wprintf (L"\r\n");


		for (SIZE_T i = 0; i < _r_obj_getlistsize (sources_arr); i++)
		{
			PR_STRING source_string = _r_obj_getlistitem (sources_arr, i);

			if (_r_obj_isstringempty (source_string))
				continue;

			_app_printdata (Init, 0, NULL, source_string->buffer);

			_app_parsesource (hsession, hosts_file, source_string->buffer, exclude_list, exclude_list_mask, &total_hosts, &total_sources);
		}

		CloseHandle (hosts_file);

		SetFileAttributes (config.hosts_file->buffer, FILE_ATTRIBUTE_NORMAL);

		if (!config.is_nobackup)
			_r_fs_move (config.hosts_file->buffer, config.hosts_file_backup->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

		_r_fs_move (config.hosts_file_temp->buffer, config.hosts_file->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

		WCHAR hosts_string[128];
		_r_format_number (hosts_string, RTL_NUMBER_OF (hosts_string), total_hosts);

		wprintf (L"\r\nFinished %" TEXT (PR_SIZE_T) L" sources with %s hosts in %.03f  seconds...\r\n", total_sources, hosts_string, ((PerformanceCounter () - start_time) * 1000.0) / PerformanceFrequency () / 1000.0);

		_r_inet_close (hsession);
	}

	if (exclude_list_mask)
		_r_obj_dereference (exclude_list_mask);

	if (sources_arr)
		_r_obj_dereference (sources_arr);
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
				_app_printdata (Help, 0, NULL, NULL);
				return;
			}
		}
	}
}

VOID _app_setdefaults ()
{
	if (!config.is_noresolver && _r_obj_isstringempty (config.hosts_destination))
		_r_obj_movereference (&config.hosts_destination, _r_obj_createstring (L"0.0.0.0"));

	_r_obj_movereference (&config.sources_file, _r_format_string (L"%s\\sources.txt", _r_app_getdirectory ()));
	_r_obj_movereference (&config.userlist_file, _r_format_string (L"%s\\userlist.txt", _r_app_getdirectory ()));
	_r_obj_movereference (&config.whitelist_file, _r_format_string (L"%s\\whitelist.txt", _r_app_getdirectory ()));
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
		wprintf (L"%s %s\r\n%s\r\n\r\n", APP_NAME, APP_VERSION, APP_COPYRIGHT);

		if (argc <= 1)
		{
			_app_printdata (Help, 0, NULL, NULL);

			wprintf (L"Press any key to continue...");

			while (!_getwch ());
		}
		else
		{
			_app_parsearguments (argc, argv);

			_app_setdefaults ();

			wprintf (L"Path: %s\r\nSources: %s\r\nUserlist: %s\r\nWhitelist: %s\r\nDestination: %s\r\n\r\n",
					 _r_obj_getstring (config.hosts_file),
					 _r_obj_getstring (config.sources_file),
					 _r_obj_getstring (config.userlist_file),
					 _r_obj_getstring (config.whitelist_file),
					 config.is_noresolver || _r_obj_isstringempty (config.hosts_destination) ? L"<disabled>" : _r_obj_getstring (config.hosts_destination)
			);

			_app_startupdate ();
		}
	}

	return ERROR_SUCCESS;
}

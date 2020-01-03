// hostsmgr
// Copyright (c) 2016-2020 Henry++

#include <winsock2.h>
#include <windows.h>

#include "main.hpp"
#include "rapp.hpp"
#include "routine.hpp"

#include "resource.hpp"

rapp app;
STATIC_DATA config;

typedef std::unordered_map<size_t, bool> ARRAY_HASHES_LIST;
typedef std::vector<rstring> ARRAY_MASK_LIST;

#define PATH_COMPACT 36

#define CONSOLE_COLOR_YELLOW (FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY)
#define CONSOLE_COLOR_RED (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define CONSOLE_COLOR_GREEN (FOREGROUND_GREEN | FOREGROUND_INTENSITY)

enum class Facility
{
	Init,
	Success,
	Error,
	Help,
};

void _app_printdata (Facility fc, LPCWSTR text, LPCWSTR description, DWORD code)
{
	switch (fc)
	{
		case Facility::Init:
		{
			if (!_r_str_isempty (text) && !_r_str_isempty (description))
				wprintf (L"%s: %s", text, description);

			else if (!_r_str_isempty (text))
				wprintf (text);

			break;
		}

		case Facility::Success:
		{
			SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_GREEN);
			wprintf (L" (%s)\r\n", text);
			SetConsoleTextAttribute (config.houtput, config.attributes);

			break;
		}

		case Facility::Error:
		{
			SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_RED);

			if (!_r_str_isempty (text) && !_r_str_isempty (description))
				wprintf (L" (%s / %s / 0x%08" PRIX32 L")\r\n", text, description, code);
			else if (!_r_str_isempty (text))
			{
				if (code)
					wprintf (L" (%s / 0x%08" PRIX32 L")\r\n", text, code);
				else
					wprintf (L" (%s)\r\n", text);
			}

			SetConsoleTextAttribute (config.houtput, config.attributes);

			break;
		}

		case Facility::Help:
		{
			wprintf (L"Usage: hostsmgr -ip 0.0.0.0 -os win -path [out file]\r\n\r\n");

			SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_YELLOW);
			wprintf (L"Command line:\r\n");
			SetConsoleTextAttribute (config.houtput, config.attributes);

			wprintf (L"/ip         ip address to be set as resolver (def. 0.0.0.0)\r\n");
			wprintf (L"/os         new line format; \"win\", \"linux\" & \"mac\" (def. \"win\")\r\n");
			wprintf (L"/path       output file location (def. \".\\hosts\")\r\n");
			wprintf (L"/nobackup   do not create backup for output file (opt.)\r\n");
			wprintf (L"/noresolve  do not set resolver, just generate ip list (opt.)\r\n");
			wprintf (L"/nocache    do not use cache files, load from inet (opt.)\r\n");

			wprintf (L"\r\n");

			break;
		}
	}
}

void _app_writeunicodeasansi (HANDLE hfile, LPCWSTR text)
{
	if (_r_str_isempty (text))
		return;

	INT length;
	LPSTR line = _r_str_utf16_to_utf8 (text, &length);

	if (line)
	{
		DWORD written = 0;
		WriteFile (hfile, line, length, &written, nullptr);

		SAFE_DELETE_ARRAY (line);
	}
}

size_t _app_parseline (LPWSTR line)
{
	_r_str_trim (line, L"\r\n\t\\/ ");

	size_t length = _r_str_length (line);
	const size_t comment_start_pos = _r_str_find (line, length, L'#');

	if (comment_start_pos == 0)
		return 0;

	if (comment_start_pos != INVALID_SIZE_T)
		line[comment_start_pos] = UNICODE_NULL;

	_r_str_replace (line, L'\t', L' ');
	_r_str_trim (line, L"\r\n\\/ ");

	if (_r_str_isempty (line))
		return 0;

	length = _r_str_length (line);
	size_t space_pos = _r_str_find (line, length, L' ');

	if (space_pos != INVALID_SIZE_T)
	{
		length -= space_pos;

		wmemmove (line, &line[space_pos], length);
		line[length] = UNICODE_NULL;

		_r_str_trim (line, L"\r\n\\/ ");

		// check for spaces
		if (_r_str_find (line, length, L' ') != INVALID_SIZE_T)
			return 0;
	}
	else
	{
		_r_str_trim (line, L"\r\n\\/ ");
	}

	if (!_r_str_isempty (line))
		return _r_str_hash (line);

	return 0;
}

size_t _app_parsefile (HANDLE hfile, HANDLE hwritefile, ARRAY_HASHES_LIST& pwhitelist_hashes, ARRAY_MASK_LIST& pwhitelist_masks)
{
	const size_t length = (size_t)_r_fs_size (hfile);

	if (!length)
		return 0;

	LPSTR buffera = new CHAR[length + 1];
	size_t hosts_count = 0;

	if (_r_fs_readfile (hfile, buffera, length))
	{
		buffera[length] = ANSI_NULL;

		if (buffera[0] != '<')
		{
			LPSTR tok_buffer = nullptr;
			LPSTR token = strtok_s (buffera, "\r\n", &tok_buffer);

			while (token)
			{
				StrTrimA (token, "\r\n\t\\/ ");
				LPWSTR host_name = _r_str_utf8_to_utf16 (token, nullptr);

				if (host_name)
				{
					const size_t host_hash = _app_parseline (host_name);

					if (host_hash && host_name[0] != UNICODE_NULL && host_name[0] != L'#' && pwhitelist_hashes.find (host_hash) == pwhitelist_hashes.end ())
					{
						if (hwritefile && hwritefile != INVALID_HANDLE_VALUE)
						{
							bool is_whitelisted = false;

							// remember entries to prevent duplicates
							pwhitelist_hashes[host_hash] = true;

							for (size_t i = 0; i < pwhitelist_masks.size (); i++)
							{
								if (_r_str_match (host_name, pwhitelist_masks.at (i)))
								{
									is_whitelisted = true;
									break;
								}
							}

							if (!is_whitelisted)
							{
								rstring buffer;

								if (config.is_noresolver || _r_str_isempty (config.hosts_destination))
									buffer.Format (L"%s%s", host_name, config.eol);

								else
									buffer.Format (L"%s %s%s", config.hosts_destination, host_name, config.eol);

								_app_writeunicodeasansi (hwritefile, buffer);

								hosts_count += 1;
							}
						}
						else
						{
							// remember entries to prevent duplicates
							if (_r_str_find (host_name, _r_str_length (host_name), L'*') != INVALID_SIZE_T)
								pwhitelist_masks.push_back (host_name); // mask
							else
								pwhitelist_hashes[host_hash] = true; // full name

							hosts_count += 1;
						}
					}
				}

				SAFE_DELETE_ARRAY (host_name);

				token = strtok_s (nullptr, "\r\n", &tok_buffer);
			}
		}
	}

	SAFE_DELETE_ARRAY (buffera);

	return hosts_count;
}

inline LONG64 PerformanceCounter () noexcept
{
	LARGE_INTEGER li = {0};
	QueryPerformanceCounter (&li);

	return li.QuadPart;
}

inline LONG64 PerformanceFrequency () noexcept
{
	LARGE_INTEGER li = {0};
	QueryPerformanceFrequency (&li);

	return li.QuadPart;
}

void _app_startupdate ()
{
	ARRAY_HASHES_LIST exclude_list;
	ARRAY_MASK_LIST exclude_list_mask;

	// predefined whitelisted hosts
	{
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

		for (size_t i = 0; i < _countof (exclude_hosts); i++)
			exclude_list[_r_str_hash (exclude_hosts[i])] = true;
	}

	std::vector<rstring> sources_arr;

	_app_printdata (Facility::Init, L"Parsing", L"sources list", 0);

	// parse sources list
	HANDLE hsources_file = CreateFile (config.sources_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hsources_file == INVALID_HANDLE_VALUE)
	{
		_app_printdata (Facility::Error, L"open failure", _r_path_getfilename (config.sources_file), GetLastError ());
		return;
	}
	else
	{
		const size_t length = (size_t)_r_fs_size (hsources_file);

		if (length)
		{
			LPSTR buffera = new CHAR[length + 1];

			if (_r_fs_readfile (hsources_file, buffera, length))
			{
				buffera[length] = ANSI_NULL;

				LPSTR tok_buffer = nullptr;
				LPSTR token = strtok_s (buffera, "\r\n", &tok_buffer);

				while (token)
				{
					StrTrimA (token, "\r\n\t\\/ ");

					INT length;
					LPWSTR url = _r_str_utf8_to_utf16 (token, &length);

					if (url)
					{
						size_t pos = _r_str_find (url, length, L'#');

						if (pos != INVALID_SIZE_T)
						{
							url[pos] = UNICODE_NULL;
							_r_str_trim (url, L"\r\n\t\\/ ");
						}

						if (!_r_str_isempty (url))
							sources_arr.push_back (url);

						SAFE_DELETE_ARRAY (url);
					}

					token = strtok_s (nullptr, "\r\n", &tok_buffer);
				}
			}

			SAFE_DELETE_ARRAY (buffera);
		}

		_app_printdata (Facility::Success, _r_fmt (L"%s lists loaded", _r_fmt_number (sources_arr.size ())), nullptr, 0);

		SAFE_DELETE_HANDLE (hsources_file);
	}

	size_t total_hosts = 0;
	size_t total_sources = 0;

	HANDLE hosts_file = CreateFile (config.hosts_file_temp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);

	if (hosts_file == INVALID_HANDLE_VALUE)
	{
		_app_printdata (Facility::Error, L"create failure", _r_path_getfilename (config.hosts_file_temp), GetLastError ());
		return;
	}

	// write header
	{
		rstring header, list;

		for (size_t i = 0; i < sources_arr.size (); i++)
		{
			rstring& rlink = sources_arr.at (i);

			if (!rlink.IsEmpty ())
				list.AppendFormat (L"# %s%s", rlink.GetString (), config.eol);
		}

		header.Format (L"# This file is automatically generated by %s.%s#%s# DO NOT MODIFY THIS FILE -- YOUR CHANGES WILL BE ERASED!%s#%s# Content merged from the following sources:%s%s%s127.0.0.1 localhost%s::1 localhost%s%s", APP_NAME, config.eol, config.eol, config.eol, config.eol, config.eol, list.GetString (), config.eol, config.eol, config.eol, config.eol);

		_app_writeunicodeasansi (hosts_file, header);
	}

	// parse whitelist
	{
		_app_printdata (Facility::Init, L"Parsing", L"whitelist", 0);

		HANDLE hfile = CreateFile (config.whitelist_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hfile == INVALID_HANDLE_VALUE)
		{
			_app_printdata (Facility::Error, L"open failure", _r_path_getfilename (config.whitelist_file), GetLastError ());
		}
		else
		{
			const size_t count = _app_parsefile (hfile, nullptr, exclude_list, exclude_list_mask);

			_app_printdata (Facility::Success, _r_fmt (L"%s hosts, %s masks", _r_fmt_number (count), _r_fmt_number (exclude_list_mask.size ())), nullptr, 0);

			SAFE_DELETE_HANDLE (hfile);
		}
	}

	// parse userlist
	{
		_app_printdata (Facility::Init, L"Parsing", L"userlist", 0);

		HANDLE hfile = CreateFile (config.userlist_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hfile == INVALID_HANDLE_VALUE)
		{
			_app_printdata (Facility::Error, L"open failure", _r_path_getfilename (config.userlist_file), GetLastError ());
		}
		else
		{
			const size_t count = _app_parsefile (hfile, hosts_file, exclude_list, exclude_list_mask);

			_app_printdata (Facility::Success, _r_fmt (L"%s hosts", _r_fmt_number (count)), nullptr, 0);

			total_hosts += count;
			total_sources += 1;

			SAFE_DELETE_HANDLE (hfile);
		}
	}

	if (!config.is_nocache)
		_r_fs_mkdir (config.cache_dir);

	LONG64 start_time = PerformanceCounter ();

	const DWORD length = _R_BUFFER_NET_LENGTH;
	LPSTR buffera = new CHAR[length];

	rstring proxy_config = app.GetProxyConfiguration ();
	HINTERNET hsession = _r_inet_createsession (app.GetUserAgent (), proxy_config);

	if (!hsession)
		_app_printdata (Facility::Error, L"winhttp failure", nullptr, GetLastError ());

	wprintf (L"\r\n");

	for (size_t i = 0; i < sources_arr.size (); i++)
	{
		rstring& rlink = sources_arr.at (i);

		_app_printdata (Facility::Init, rlink, nullptr, 0);

		if (!PathIsURL (rlink))
		{
			HANDLE hfile = CreateFile (rlink, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

			if (hfile == INVALID_HANDLE_VALUE)
			{
				_app_printdata (Facility::Error, L"open failure", nullptr, GetLastError ());
			}
			else
			{
				const size_t count = _app_parsefile (hfile, hosts_file, exclude_list, exclude_list_mask);

				total_hosts += count;
				total_sources += 1;

				_app_printdata (Facility::Success, _r_fmt (L"%s hosts", _r_fmt_number (count)), nullptr, 0);

				SAFE_DELETE_HANDLE (hfile);
			}
		}
		else
		{
			WCHAR path[MAX_PATH] = {0};

			if (config.is_nocache)
				_r_str_printf (path, _countof (path), L"%s\\%" PR_SIZE_T L".txt", _r_path_expand (L"%temp%\\"), _r_str_hash (rlink));
			else
				_r_str_printf (path, _countof (path), L"%s\\%" PR_SIZE_T L".txt", config.cache_dir, _r_str_hash (rlink));

			SetFileAttributes (path, FILE_ATTRIBUTE_NORMAL);
			HANDLE hfile = CreateFile (path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, config.is_nocache ? CREATE_ALWAYS : OPEN_ALWAYS, config.is_nocache ? FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE : FILE_ATTRIBUTE_TEMPORARY, nullptr);

			if (hfile == INVALID_HANDLE_VALUE)
			{
				_app_printdata (Facility::Error, L"open failure", _r_path_getfilename (path), GetLastError ());
			}
			else
			{
				HINTERNET hconnect = nullptr;
				HINTERNET hrequest = nullptr;

				if (_r_inet_openurl (hsession, rlink, proxy_config, &hconnect, &hrequest, nullptr) == ERROR_SUCCESS)
				{
					DWORD status = 0;
					DWORD size = sizeof (status);

					WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &size, nullptr);

					if (status >= HTTP_STATUS_OK && status <= HTTP_STATUS_PARTIAL_CONTENT)
					{
						FILETIME remote_timestamp = {0};
						FILETIME local_timestamp = {0};

						SYSTEMTIME lastmod = {0};
						size = sizeof (lastmod);

						if (WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_LAST_MODIFIED | WINHTTP_QUERY_FLAG_SYSTEMTIME, nullptr, &lastmod, &size, nullptr))
							SystemTimeToFileTime (&lastmod, &remote_timestamp);

						if (!_r_fs_size (hfile) || (GetFileTime (hfile, nullptr, nullptr, &local_timestamp) && CompareFileTime (&local_timestamp, &remote_timestamp) == -1))
						{
							DWORD readed = 0, written = 0;

							while (_r_inet_readrequest (hrequest, buffera, length - 1, &readed, nullptr))
							{
								if (!readed)
									break;

								WriteFile (hfile, buffera, readed, &written, nullptr);
							}

							SetFileTime (hfile, &remote_timestamp, &remote_timestamp, &remote_timestamp);
						}
					}

					_r_inet_close (hrequest);
					_r_inet_close (hconnect);
				}

				const size_t count = _app_parsefile (hfile, hosts_file, exclude_list, exclude_list_mask);

				if (count)
				{
					total_hosts += count;
					total_sources += 1;
				}

				_app_printdata (count ? Facility::Success : Facility::Error, _r_fmt (L"%s hosts", _r_fmt_number (count)), nullptr, 0);

				SAFE_DELETE_HANDLE (hfile);

				if (!config.is_nocache)
					SetFileAttributes (path, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_TEMPORARY);
			}
		}
	}

	_r_inet_close (hsession);

	SAFE_DELETE_ARRAY (buffera);
	SAFE_DELETE_HANDLE (hosts_file);

	SetFileAttributes (config.hosts_file, FILE_ATTRIBUTE_NORMAL);

	if (!config.is_nobackup)
		_r_fs_move (config.hosts_file, _r_fmt (L"%s.bak", config.hosts_file), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

	_r_fs_move (config.hosts_file_temp, config.hosts_file, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

	wprintf (L"\r\nFinished ");

	SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_YELLOW);
	wprintf (L"%" PR_SIZE_T, total_sources);
	SetConsoleTextAttribute (config.houtput, config.attributes);

	wprintf (L" sources with ");

	SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_YELLOW);
	wprintf (L"%s", _r_fmt_number (total_hosts).GetString ());
	SetConsoleTextAttribute (config.houtput, config.attributes);

	wprintf (L" hosts in ");

	SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_YELLOW);
	wprintf (L"%.03f", ((PerformanceCounter () - start_time) * 1000.0) / PerformanceFrequency () / 1000.0);
	SetConsoleTextAttribute (config.houtput, config.attributes);

	wprintf (L" seconds...\r\n");
}

bool _app_parsearguments (INT argc, LPCWSTR argv[])
{
	for (INT i = 0; i < argc; i++)
	{
		if (argv[i][0] == L'/' || argv[i][0] == L'-')
		{
			const rstring name = argv[i] + 1;
			const rstring value = argv[i + 1];

			if (_r_str_compare (name, L"ip") == 0)
			{
				_r_str_alloc (&config.hosts_destination, INVALID_SIZE_T, value);
			}
			else if (_r_str_compare (name, L"nobackup") == 0)
			{
				config.is_nobackup = true;
			}
			else if (_r_str_compare (name, L"noresolve") == 0)
			{
				config.is_noresolver = true;
			}
			else if (_r_str_compare (name, L"nocache") == 0)
			{
				config.is_nocache = true;
			}
			else if (_r_str_compare (name, L"path") == 0)
			{
				_r_str_copy (config.hosts_file, _countof (config.hosts_file), _r_path_expand (value));

				if (_r_fs_exists (config.hosts_file) && (GetFileAttributes (config.hosts_file) & FILE_ATTRIBUTE_DIRECTORY) != 0)
					_r_str_cat (config.hosts_file, _countof (config.hosts_file), L"\\hosts");
			}
			else if (_r_str_compare (name, L"os") == 0)
			{
				const WCHAR ch = value.At (0);

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
			else if (name.At (0) == L'h' || _r_str_compare (name, L"help") == 0)
			{
				_app_printdata (Facility::Help, nullptr, 0, 0);
				return false;
			}
		}
	}

	return true;
}

void _app_setdefaults ()
{
	if (!config.is_noresolver && _r_str_isempty (config.hosts_destination))
		_r_str_alloc (&config.hosts_destination, INVALID_SIZE_T, L"0.0.0.0");

	_r_str_alloc (&config.sources_file, INVALID_SIZE_T, _r_path_expand (L".\\sources.txt"));
	_r_str_alloc (&config.userlist_file, INVALID_SIZE_T, _r_path_expand (L".\\userlist.txt"));
	_r_str_alloc (&config.whitelist_file, INVALID_SIZE_T, _r_path_expand (L".\\whitelist.txt"));

	_r_str_alloc (&config.cache_dir, INVALID_SIZE_T, _r_fmt (L"%s\\cache", app.GetProfileDirectory ()));

	// set hosts path
	if (_r_str_isempty (config.hosts_file))
		_r_str_copy (config.hosts_file, _countof (config.hosts_file), _r_path_expand (L".\\hosts"));

	_r_str_alloc (&config.hosts_file_temp, INVALID_SIZE_T, _r_fmt (L"%s.tmp", config.hosts_file));

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
	if (app.Initialize (APP_NAME, APP_NAME_SHORT, APP_VERSION, APP_COPYRIGHT))
	{
		SetConsoleTitle (APP_NAME);

		config.houtput = GetStdHandle (STD_OUTPUT_HANDLE);

		CONSOLE_SCREEN_BUFFER_INFO Info = {0};
		GetConsoleScreenBufferInfo (config.houtput, &Info);

		config.attributes = Info.wAttributes;

		SetConsoleTextAttribute (config.houtput, CONSOLE_COLOR_YELLOW);
		wprintf (L"%s %s\r\n%s\r\n\r\n", APP_NAME, APP_VERSION, APP_COPYRIGHT);
		SetConsoleTextAttribute (config.houtput, config.attributes);

		if (argc <= 1)
		{
			_app_printdata (Facility::Help, nullptr, nullptr, 0);
			wprintf (L"Press any key to continue...");

			while (!_getwch ());
		}
		else
		{
			if (_app_parsearguments (argc, argv))
			{
				_app_setdefaults ();

				wprintf (
					L"Path: %s\r\nSources: %s\r\nUserlist: %s\r\nWhitelist: %s\r\nDestination: %s\r\n\r\n",
					_r_path_compact (config.hosts_file, PATH_COMPACT).GetString (),
					_r_path_compact (config.sources_file, PATH_COMPACT).GetString (),
					_r_path_compact (config.userlist_file, PATH_COMPACT).GetString (),
					_r_path_compact (config.whitelist_file, PATH_COMPACT).GetString (),
					config.is_noresolver || _r_str_isempty (config.hosts_destination) ? L"<disabled>" : config.hosts_destination
				);

				_app_startupdate ();
			}
		}
	}

	return ERROR_SUCCESS;
}

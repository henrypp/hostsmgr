// hostsmgr
// Copyright (c) 2016-2019 Henry++

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windns.h>
#include <windows.h>
#include <iphlpapi.h>
#include <subauth.h>

#include "main.hpp"
#include "rapp.hpp"
#include "routine.hpp"

#include "resource.hpp"

rapp app (APP_NAME, APP_NAME_SHORT, APP_VERSION, APP_COPYRIGHT);

typedef std::unordered_map<size_t, bool> ARRAY_HASHES_LIST;

bool is_nobackup = false;

std::vector<rstring> sources_arr;

WCHAR hosts_file[MAX_PATH] = {0};
WCHAR sources_file[MAX_PATH] = {0};
WCHAR whitelist_file[MAX_PATH] = {0};
WCHAR userlist_file[MAX_PATH] = {0};
WCHAR cache_dir[MAX_PATH] = {0};

WCHAR hosts_destination[MAX_PATH] = {0};
WCHAR eol[3] = {0};

void _app_printerror (LPCWSTR text, DWORD code)
{
	wprintf (L"ERROR: %s [err: 0x%06X]\r\n\r\n", text, code);
}

void _app_printhelp ()
{
	wprintf (L"Command line:\r\n/ip - ip address to be set as resolve for all domains (default: 0.0.0.0)\r\n/path - \"hosts\" file location; env. variables and relative paths are supported (default: current directory)\r\n/os - new line format; \"win\" for Windows (crlf), \"linux\" - for Linux (lf), \"mac\" for Mac OS (cr)\r\n/nobackup - do not create backup copy for \"hosts\" file\r\n");
}

void _app_writeunicodeasansi (HANDLE hfile, LPCWSTR ustring, DWORD length)
{
	if (!ustring || !length)
		return;

	LPSTR buffer = new CHAR[length + 1];

	if (buffer)
	{
		WideCharToMultiByte (CP_ACP, 0, ustring, (INT)length, buffer, (INT)length, nullptr, nullptr);

		DWORD written = 0;
		WriteFile (hfile, buffer, length, &written, nullptr);

		SAFE_DELETE_ARRAY (buffer);
	}
}

bool _app_ruleishost (LPCWSTR rule)
{
	if (!rule || !rule[0])
		return false;

	NET_ADDRESS_INFO ni;
	SecureZeroMemory (&ni, sizeof (ni));

	USHORT port = 0;
	BYTE prefix_length = 0;

	static const DWORD types = NET_STRING_NAMED_ADDRESS | NET_STRING_NAMED_SERVICE;
	const DWORD errcode = ParseNetworkString (rule, types, &ni, &port, &prefix_length);

	return (errcode == ERROR_SUCCESS);
}

size_t _app_parseline (rstring& line)
{
	line.Trim (L"\r\n\t\\/ ");

	const size_t comment_start_pos = line.Find (L'#');
	const size_t comment_end_pos = line.ReverseFind (L'#');

	if (comment_start_pos == 0 || comment_end_pos == 0)
		return 0;

	size_t hash = 0;

	if (comment_end_pos != rstring::npos)
		line.Mid (0, comment_end_pos);

	line.Replace (L"\t", L" ").Trim (L"\r\n\\/ ");

	if (!line.IsEmpty ())
	{
		const size_t space_pos = line.Find (L' ');
		const rstring host = space_pos == rstring::npos ? line : line.Midded (line.ReverseFind (L' ') + 1);

		if (!_app_ruleishost (host))
			return 0;

		line = host;
		hash = host.Hash ();
	}

	return hash;
}

bool _app_parsefile (HANDLE hreadfile, HANDLE hwritefile, ARRAY_HASHES_LIST& pwhitelist_hashes)
{
	const size_t length = (size_t)_r_fs_size (hreadfile);

	if (!length)
		return false;

	LPSTR buffera = new CHAR[length + 1];

	if (buffera)
	{
		if (_r_fs_readfile (hreadfile, buffera, length))
		{
			rstring content = buffera;
			SAFE_DELETE_ARRAY (buffera);

			if (content.At (0) == L'<')
				return false;

			const rstring::rvector vcarr = content.AsVector (L"\r\n");

			for (size_t i = 0; i < vcarr.size (); i++)
			{
				rstring line = vcarr.at (i);

				const size_t hash = _app_parseline (line);

				if (!hash || line.IsEmpty () || line.At (0) == L'#' || pwhitelist_hashes.find (hash) != pwhitelist_hashes.end ())
					continue;

				// remember entries to prevent duplicates
				pwhitelist_hashes[hash] = true;

				if (hwritefile && hwritefile != INVALID_HANDLE_VALUE)
				{
					rstring buffer;
					buffer.Format (L"%s %s%s", hosts_destination, line.GetString (), eol);

					_app_writeunicodeasansi (hwritefile, buffer, (DWORD)buffer.GetLength ());
				}
			}
		}
		else
		{
			SAFE_DELETE_ARRAY (buffera);
		}
	}

	return true;
}

void _app_startupdate ()
{
	const HINTERNET hsession = _r_inet_createsession (app.GetUserAgent (), app.ConfigGet (L"Proxy", nullptr));

	if (hsession)
	{
		ARRAY_HASHES_LIST exclude_list;

		// predefined whitelisted hosts
		{
			static LPCWSTR exclude_hosts[] = {
				L"local",
				L"localhost",
				L"localhost.localdomain",
				L"broadcasthost",
				L"notice",
				L"ip6-loopback",
				L"ip6-localnet",
				L"ip6-mcastprefix",
				L"ip6-allnodes",
				L"ip6-allrouters",
				L"ip6-allhosts",
			};

			for (size_t i = 0; i < _countof (exclude_hosts); i++)
				exclude_list[_r_str_hash (exclude_hosts[i])] = true;
		}

		const HANDLE hhosts = CreateFile (_r_fmt (L"%s.tmp", hosts_file), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hhosts == INVALID_HANDLE_VALUE)
		{
			_app_printerror (_r_path_compact (hosts_file, 64), GetLastError ());
		}
		else
		{
			// write header
			{
				rstring header, list;

				for (size_t i = 0; i < sources_arr.size (); i++)
				{
					if (!sources_arr.at (i).IsEmpty ())
					{
						list.Append (L"# ");
						list.Append (sources_arr.at (i));
						list.Append (eol);
					}
				}

				header.Format (L"# This file is automatically generated by %s.%s#%s# DO NOT MODIFY THIS FILE -- YOUR CHANGES WILL BE ERASED!%s#%s# Content merged from the following sources:%s%s%s127.0.0.1 localhost%s::1 localhost%s%s", APP_NAME, eol, eol, eol, eol, eol, list.GetString (), eol, eol, eol, eol);

				_app_writeunicodeasansi (hhosts, header, (DWORD)header.GetLength ());
			}

			// parse whitelist
			if (_r_fs_exists (whitelist_file))
			{
				const HANDLE hfile = CreateFile (whitelist_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

				if (hfile == INVALID_HANDLE_VALUE)
				{
					_app_printerror (_r_path_compact (whitelist_file, 64), GetLastError ());
				}
				else
				{
					_app_parsefile (hfile, nullptr, exclude_list);
					CloseHandle (hfile);
				}
			}

			// parse userlist
			if (_r_fs_exists (userlist_file))
			{
				const HANDLE hfile = CreateFile (userlist_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

				if (hfile == INVALID_HANDLE_VALUE)
				{
					_app_printerror (_r_path_compact (userlist_file, 64), GetLastError ());
				}
				else
				{
					_app_parsefile (hfile, hhosts, exclude_list);
					CloseHandle (hfile);
				}
			}

			_r_fs_mkdir (cache_dir);

			for (size_t i = 0; i < sources_arr.size (); i++)
			{
				WCHAR result[64] = {0};
				wprintf (L"%zu/%zu - %s...", i + 1, sources_arr.size (), sources_arr.at (i).GetString ());

				HINTERNET hconnect = nullptr;
				HINTERNET hrequest = nullptr;

				if (!_r_inet_openurl (hsession, sources_arr.at (i), _r_inet_getproxyconfiguration (app.ConfigGet (L"Proxy", nullptr)), &hconnect, &hrequest, nullptr))
				{
					sources_arr.at (i).Clear ();
					StringCchPrintf (result, _countof (result), L"bad url (0x%.8lx.)", GetLastError ());
				}
				else
				{
					SYSTEMTIME lastmod = {0};

					FILETIME remote_timestamp = {0};
					FILETIME local_timestamp = {0};

					DWORD size = sizeof (lastmod);

					WinHttpQueryHeaders (hrequest, WINHTTP_QUERY_LAST_MODIFIED | WINHTTP_QUERY_FLAG_SYSTEMTIME, nullptr, &lastmod, &size, nullptr);
					SystemTimeToFileTime (&lastmod, &remote_timestamp);

					WCHAR path[MAX_PATH] = {0};
					StringCchPrintf (path, _countof (path), L"%s\\%zu.txt", cache_dir, sources_arr.at (i).Hash ());

					SetFileAttributes (path, FILE_ATTRIBUTE_NORMAL);
					const HANDLE hcache = CreateFile (path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_READONLY, nullptr);

					if (hcache != INVALID_HANDLE_VALUE)
					{
						GetFileTime (hcache, nullptr, nullptr, &local_timestamp);

						if (!_r_fs_size (hcache) || CompareFileTime (&local_timestamp, &remote_timestamp) == -1)
						{
							const size_t length = (_R_BUFFER_LENGTH * 4);
							LPSTR buffera = new CHAR[length];

							if (buffera)
							{
								DWORD readed = 0, written = 0;

								while (true)
								{
									if (!_r_inet_readrequest (hrequest, buffera, length - 1, &readed, nullptr))
										break;

									WriteFile (hcache, buffera, readed, &written, nullptr);
								}

								SetFileTime (hcache, &remote_timestamp, &remote_timestamp, &remote_timestamp);

								StringCchCopy (result, _countof (result), L"OKAY!");

								SAFE_DELETE_ARRAY (buffera);
							}
						}
						else
						{
							StringCchCopy (result, _countof (result), L"OKAY!");
						}

						_app_parsefile (hcache, hhosts, exclude_list);

						CloseHandle (hcache);
					}

					_r_inet_close (hrequest);
					_r_inet_close (hconnect);
				}

				wprintf (L"%s\r\n", result);
			}

			_r_inet_close (hsession);

			CloseHandle (hhosts);

			SetFileAttributes (hosts_file, FILE_ATTRIBUTE_NORMAL);

			if (!is_nobackup)
				_r_fs_move (hosts_file, _r_fmt (L"%s.bak", hosts_file));

			_r_fs_move (_r_fmt (L"%s.tmp", hosts_file), hosts_file);
		}

		exclude_list.clear ();
	}
}

bool _app_parsearguments (INT argc, LPCWSTR argv[])
{
	for (int i = 0; i < argc; i++)
	{
		if (argv[i][0] == L'/' || argv[i][0] == L'-')
		{
			const rstring name = rstring (argv[i]).Midded (1);
			const rstring value = argv[i + 1];

			if (name.CompareNoCase (L"ip") == 0)
			{
				StringCchCopy (hosts_destination, _countof (hosts_destination), value);
			}
			else if (name.CompareNoCase (L"nobackup") == 0)
			{
				is_nobackup = true;
			}
			else if (name.CompareNoCase (L"path") == 0)
			{
				StringCchCopy (hosts_file, _countof (hosts_file), _r_path_expand (value));

				if (_r_fs_exists (hosts_file) && (GetFileAttributes (hosts_file) & FILE_ATTRIBUTE_DIRECTORY) != 0)
					StringCchCat (hosts_file, _countof (hosts_file), L"\\hosts");
			}
			else if (name.CompareNoCase (L"os") == 0)
			{
				const WCHAR ch = value.At (0);

				if (ch == L'w') // windows
				{
					eol[0] = L'\r';
					eol[1] = L'\n';
					eol[2] = 0;
				}
				else if (ch == L'l') // linux
				{
					eol[0] = L'\n';
					eol[1] = 0;
				}
				else if (ch == L'm') // mac
				{
					eol[0] = L'\r';
					eol[1] = 0;
				}
			}
			else if (name.At (0) == L'h' || name.CompareNoCase (L"help") == 0)
			{
				_app_printhelp ();
				return false;
			}
		}
	}

	return true;
}

bool _app_setdefaults ()
{
	if (!hosts_destination[0])
		StringCchCopy (hosts_destination, _countof (hosts_destination), L"0.0.0.0");

	StringCchCopy (sources_file, _countof (sources_file), _r_path_expand (L"sources.txt"));
	StringCchCopy (userlist_file, _countof (userlist_file), _r_path_expand (L"userlist.txt"));
	StringCchCopy (whitelist_file, _countof (whitelist_file), _r_path_expand (L"whitelist.txt"));

	StringCchPrintf (cache_dir, _countof (cache_dir), L"%s\\cache", app.GetProfileDirectory ());

	// set hosts path
	if (!hosts_file[0])
		StringCchCopy (hosts_file, _countof (hosts_file), _r_path_expand (L".\\hosts").GetString ());

	// set end-of-line type
	if (!eol[0])
	{
		eol[0] = L'\r';
		eol[1] = L'\n';
		eol[2] = 0;
	}

	const HANDLE hfile = CreateFile (sources_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		_app_printerror (sources_file, GetLastError ());
		return false;
	}
	else
	{
		const size_t length = (size_t)_r_fs_size (hfile);

		if (length)
		{
			LPSTR buffer = new CHAR[length + 1];

			if (buffer)
			{
				if (_r_fs_readfile (hfile, buffer, length))
				{
					rstring::rvector arr = rstring (buffer).AsVector (L"\r\n");

					for (size_t i = 0; i < arr.size (); i++)
					{
						const rstring url = arr[i].Trim (L"\r\n ");

						if (url.IsEmpty () || url.At (0) == L'#')
							continue;

						sources_arr.push_back (url);
					}
				}

				SAFE_DELETE_ARRAY (buffer);
			}
		}

		CloseHandle (hfile);
	}

	return true;
}

INT __cdecl wmain (INT argc, LPCWSTR argv[])
{
	SetConsoleTitle (APP_NAME);

	wprintf (L"%s %s\r\n%s\r\n\r\n", APP_NAME, APP_VERSION, APP_COPYRIGHT);

	if (argc <= 1)
	{
		_app_printhelp ();
	}
	else
	{
		if (_app_parsearguments (argc, argv))
		{
			_app_setdefaults ();

			wprintf (L"Path: %s\r\nSources: %s\r\nUserlist: %s\r\nWhitelist: %s\r\nDestination: %s\r\n\r\n", hosts_file, sources_file, userlist_file, whitelist_file, hosts_destination);

			_app_startupdate ();
		}
	}

	return ERROR_SUCCESS;
}

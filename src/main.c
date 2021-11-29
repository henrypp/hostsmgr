// hostsmgr
// Copyright (c) 2016-2021 Henry++

#include "global.h"

VOID _app_startupdate ()
{
	WCHAR hosts_format[128];
	WCHAR size_format[128];
	LONG64 start_time;

	if (!_app_hosts_initialize ())
		return;

	start_time = _r_sys_startexecutiontime ();

	// initialize internet session
	config.hsession = _r_inet_createsession (_r_app_getuseragent ());

	if (!config.hsession)
		_app_print_status (FACILITY_WARNING, GetLastError (), NULL, L"Inet failure");

	_app_print_status (FACILITY_TITLE, 0, NULL, L"Reading configuration");

	// initialize whitelist
	_app_whitelist_initialize ();

	// add sources list
	_app_sources_additem (_r_str_crc32 (&config.sources_file->sr, TRUE), config.sources_file, SI_FLAG_SOURCES);

	// add whitelist source
	_app_sources_additem (_r_str_crc32 (&config.whitelist_file->sr, TRUE), config.whitelist_file, SI_FLAG_WHITELIST);

	// add userlist source
	_app_sources_additem (_r_str_crc32 (&config.userlist_file->sr, TRUE), config.userlist_file, SI_FLAG_USERLIST);

	// parse sources
	_app_sources_parse (SI_PROCESS_READ_CONFIG);

	// write header
	if (!config.is_nointro)
		_app_hosts_writeheader ();

	if (config.is_dnscrypt)
	{
		_app_print_status (FACILITY_TITLE, 0, NULL, L"Calculate dnscrypt whitelist");

		_app_sources_parse (SI_PROCESS_PREPARE_DNSCRYPT);
	}

	// process sources
	_app_print_status (FACILITY_TITLE, 0, NULL, L"Reading sources");

	_app_sources_parse (SI_PROCESS_START);

	_app_hosts_destroy (); // required!

	SetFileAttributes (config.hosts_file->buffer, FILE_ATTRIBUTE_NORMAL);

	if (!config.is_nobackup)
		_r_fs_movefile (config.hosts_file->buffer, config.hosts_file_backup->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

	_r_fs_movefile (config.hosts_file_temp->buffer, config.hosts_file->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

	_r_format_number (hosts_format, RTL_NUMBER_OF (hosts_format), config.total_hosts);
	_r_format_bytesize64 (size_format, RTL_NUMBER_OF (size_format), config.total_size);

	_r_console_writestringformat (L"\r\nFinished %" TEXT (PR_LONG) L" sources with %s items from %s in %.04f seconds...\r\n", config.total_sources, hosts_format, size_format, _r_sys_finalexecutiontime (start_time));

	_app_hosts_destroy ();
	_app_sources_destroy ();

	if (config.hsession)
	{
		_r_inet_close (config.hsession);
		config.hsession = NULL;
	}
}

VOID _app_parsearguments (_In_reads_ (argc) LPCWSTR argv[], _In_ INT argc)
{
	R_STRINGREF key_name;
	R_STRINGREF key_value;

	for (INT i = 0; i < argc; i++)
	{
		_r_obj_initializestringrefconst (&key_name, argv[i]);

		if (_r_str_getlength3 (&key_name) <= 2)
			continue;

		if (*key_name.buffer == L'/' || *key_name.buffer == L'-')
			_r_obj_skipstringlength (&key_name, sizeof (WCHAR));

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
		else if (_r_str_isequal2 (&key_name, L"dnscrypt", TRUE))
		{
			config.is_dnscrypt = TRUE;
		}
		else if (_r_str_isequal2 (&key_name, L"nobackup", TRUE))
		{
			config.is_nobackup = TRUE;
		}
		else if (_r_str_isequal2 (&key_name, L"noresolve", TRUE))
		{
			config.is_hostonly = TRUE;
		}
		else if (_r_str_isequal2 (&key_name, L"nointro", TRUE))
		{
			config.is_nointro = TRUE;
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
			WCHAR chr;

			if (!key_value.length)
				continue;

			chr = _r_str_lower (key_value.buffer[0]);

			if (chr == L'w') // windows
			{
				config.eol = _r_obj_createstring (L"\r\n");
			}
			else if (chr == L'l') // linux
			{
				config.eol = _r_obj_createstring (L"\n");
			}
			else if (chr == L'm') // mac
			{
				config.eol = _r_obj_createstring (L"\r");
			}
		}
		else if (_r_str_isstartswith2 (&key_name, L"help", TRUE))
		{
			_app_print_status (FACILITY_HELP, 0, NULL, NULL);
			return;
		}
	}
}

VOID _app_setdefaults ()
{
	config.sources_table = _r_obj_createhashtable_ex (sizeof (SOURCE_INFO_DATA), 64, NULL);
	config.exclude_table = _r_obj_createhashtable_ex (sizeof (BOOLEAN), 1024, NULL);
	config.exclude_table_mask = _r_obj_createhashtablepointer (1024);

	if (config.is_dnscrypt)
		config.is_hostonly = TRUE;

	if (_r_obj_isstringempty (config.hosts_destination))
		_r_obj_movereference (&config.hosts_destination, _r_obj_createstring (L"0.0.0.0"));

	// configure paths
	_r_obj_movereference (&config.sources_file, _r_obj_concatstrings (2, _r_app_getdirectory ()->buffer, L"\\hosts_sources.dat"));
	_r_obj_movereference (&config.userlist_file, _r_obj_concatstrings (2, _r_app_getdirectory ()->buffer, L"\\hosts_userlist.dat"));
	_r_obj_movereference (&config.whitelist_file, _r_obj_concatstrings (2, _r_app_getdirectory ()->buffer, L"\\hosts_whitelist.dat"));
	_r_obj_movereference (&config.cache_dir, _r_obj_concatstrings (2, _r_app_getprofiledirectory ()->buffer, L"\\cache"));

	_r_fs_mkdir (config.cache_dir->buffer);

	// set hosts path
	if (_r_obj_isstringempty (config.hosts_file))
		_r_obj_movereference (&config.hosts_file, _r_path_search (L".\\hosts"));

	_r_obj_movereference (&config.hosts_file_temp, _r_obj_concatstrings (2, _r_obj_getstring (config.hosts_file), L".tmp"));
	_r_obj_movereference (&config.hosts_file_backup, _r_obj_concatstrings (2, _r_obj_getstring (config.hosts_file), L".bak"));

	// set end-of-line type
	if (_r_obj_isstringempty (config.eol))
		config.eol = _r_obj_createstring (L"\r\n");

	config.con_attr = _r_console_getcolor ();
}

INT _cdecl wmain (_In_ INT argc, _In_reads_ (argc) LPCWSTR argv[])
{
	SetConsoleTitle (_r_app_getname ());

	if (!_r_app_initialize ())
		return ERROR_APP_INIT_FAILURE;

	_r_console_writestringformat (L"%s %s\r\n%s\r\n",
								  _r_app_getname (),
								  _r_app_getversion (),
								  _r_app_getcopyright ()
	);

	if (argc <= 1)
	{
		_app_print_status (FACILITY_HELP, 0, NULL, NULL);
		return ERROR_SUCCESS;
	}

	_app_parsearguments (argv, argc);

	_app_setdefaults ();

	_app_print_status (FACILITY_INIT, 0, NULL, NULL);

	_app_startupdate ();

	//_r_fs_deletedirectory (config.cache_dir->buffer, FALSE);

	return ERROR_SUCCESS;
}

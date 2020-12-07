// hostsmgr
// Copyright (c) 2016-2021 Henry++

#pragma once

#include "routine.h"

#include "resource.h"
#include "app.h"

typedef struct _STATIC_DATA
{
	WCHAR eol[3];

	PR_STRING sources_file;
	PR_STRING whitelist_file;
	PR_STRING userlist_file;
	PR_STRING cache_dir;
	PR_STRING hosts_destination;
	PR_STRING hosts_file;
	PR_STRING hosts_file_temp;
	PR_STRING hosts_file_backup;

	BOOLEAN is_nobackup;
	BOOLEAN is_noresolver;
	BOOLEAN is_nocache;
} STATIC_DATA, *PSTATIC_DATA;

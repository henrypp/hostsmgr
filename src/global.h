// hostsmgr
// Copyright (c) 2016-2022 Henry++

#pragma once

#include "routine.h"

#include "app.h"
#include "rapp.h"
#include "main.h"

#include "resource.h"

DECLSPEC_SELECTANY STATIC_DATA config = {0};

DECLSPEC_SELECTANY R_QUEUED_LOCK console_lock = PR_QUEUED_LOCK_INIT;
DECLSPEC_SELECTANY R_QUEUED_LOCK exclude_lock = PR_QUEUED_LOCK_INIT;
DECLSPEC_SELECTANY R_QUEUED_LOCK exclude_mask_lock = PR_QUEUED_LOCK_INIT;
DECLSPEC_SELECTANY R_QUEUED_LOCK dnscrypt_lock = PR_QUEUED_LOCK_INIT;

DECLSPEC_SELECTANY R_FREE_LIST context_list = {0};

#include "helper.h"

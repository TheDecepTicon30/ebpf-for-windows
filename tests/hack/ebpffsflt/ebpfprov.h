// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Header file for the eBPF file operations extension.
 */

#pragma once

#include "cxplat.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"

#include <ntifs.h> // Must be included before ntddk.h
#include <netioddk.h>
#include <ntddk.h>
#include <ntstatus.h>

#define EF_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION
#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EF_EXT_POOL_TAG_DEFAULT 'lpof'

#define CXPLAT_FREE(x) cxplat_free(x, CXPLAT_POOL_FLAG_NON_PAGED, EF_EXT_POOL_TAG_DEFAULT)

// EF extension program context.
typedef struct _ef_program_context
{
    uint8_t* data_start;
    uint8_t* data_end;
    uint32_t uint32_data;
    uint16_t uint16_data;
    uint32_t helper_data_1;
    uint32_t helper_data_2;
} ef_program_context_t;

_Must_inspect_result_ ebpf_result_t
ef_ext_invoke_program(_Inout_ ef_program_context_t* context, _Out_ uint32_t* result);

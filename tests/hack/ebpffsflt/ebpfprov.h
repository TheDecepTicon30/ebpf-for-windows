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
#include "file_ops_helpers.h"

#include <ntifs.h> // Must be included before ntddk.h
#include <netioddk.h>
#include <ntddk.h>
#include <ntstatus.h>

#define EF_EXT_POOL_TAG_DEFAULT 'lpof'

#define CXPLAT_FREE(x) cxplat_free(x, CXPLAT_POOL_FLAG_NON_PAGED, EF_EXT_POOL_TAG_DEFAULT)

NTSTATUS
ef_ext_program_info_provider_register();

void
ef_ext_program_info_provider_unregister();

void
ef_ext_hook_provider_unregister();

NTSTATUS
ef_ext_hook_provider_register();

_Must_inspect_result_ ebpf_result_t
ef_ext_invoke_program(_Inout_ ef_program_context_t* context, _Out_ uint32_t* result);

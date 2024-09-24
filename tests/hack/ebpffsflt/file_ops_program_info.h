// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Header file with program info for file ops extension.
 */

#pragma once

#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "file_ops_helpers.h"

#define EF_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION
#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))

static const ebpf_context_descriptor_t _ef_ebpf_context_descriptor = {
    sizeof(ef_program_context_t),
    EBPF_OFFSET_OF(ef_program_context_t, data_start),
    EBPF_OFFSET_OF(ef_program_context_t, data_end),
    -1};

static const ebpf_program_type_descriptor_t _ef_ext_program_type_descriptor = {
    EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
    "file_ops",
    &_ef_ebpf_context_descriptor,
    EBPF_PROGRAM_TYPE_FILE_OPS_GUID,
    BPF_PROG_TYPE_FILE_OPS};

// EF Extension Helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _ef_ext_helper_function_prototype[] = {
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 1,
     "ef_ext_helper_function1",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 2,
     "ef_ext_find",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 3,
     "ef_ext_replace",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 4,
     "ef_ext_helper_implicit_1",
     EBPF_RETURN_TYPE_INTEGER,
     {0},
     {0},
     true},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 5,
     "ef_ext_helper_implicit_2",
     EBPF_RETURN_TYPE_INTEGER,
     {0},
     {0},
     true},
};

// Global helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _ef_ext_global_helper_function_prototype[] = {
    {
        EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
        BPF_FUNC_get_current_pid_tgid,
        "bpf_get_current_pid_tgid",
        EBPF_RETURN_TYPE_INTEGER,
    },
};

static const ebpf_program_info_t _ef_ext_program_info = {
    EBPF_PROGRAM_INFORMATION_HEADER,
    &_ef_ext_program_type_descriptor,
    EBPF_COUNT_OF(_ef_ext_helper_function_prototype),
    _ef_ext_helper_function_prototype,
    EBPF_COUNT_OF(_ef_ext_global_helper_function_prototype),
    _ef_ext_global_helper_function_prototype};

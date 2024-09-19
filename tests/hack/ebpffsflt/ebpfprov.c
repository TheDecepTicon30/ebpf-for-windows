// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief WDF based driver that does the following:
 * Registers as an eBPF extension program information provider and hook provider.
 */

#include "cxplat.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_program_attach_type_guids.h" // TODO(issue #2305): remove this include.
#include "ebpf_program_types.h"
#include "ebpf_structs.h"

#include <ntifs.h> // Must be included before ntddk.h
#include <netioddk.h>
#include <ntddk.h>
#include <ntstatus.h>

#define EF_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION
#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EF_PID_TGID_VALUE 9999
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

static const ebpf_context_descriptor_t _ef_ebpf_context_descriptor = {
    sizeof(ef_program_context_t),
    EBPF_OFFSET_OF(ef_program_context_t, data_start),
    EBPF_OFFSET_OF(ef_program_context_t, data_end),
    -1};

static const ebpf_program_type_descriptor_t _ef_ebpf_extension_program_type_descriptor = {
    EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
    "file_ops",
    &_ef_ebpf_context_descriptor,
    EBPF_PROGRAM_TYPE_FILE_OPS_GUID,
    BPF_PROG_TYPE_FILE_OPS};

// EF Extension Helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _ef_ebpf_extension_helper_function_prototype[] = {
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 1,
     "ef_ebpf_extension_helper_function1",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 2,
     "ef_ebpf_extension_find",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 3,
     "ef_ebpf_extension_replace",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_ANYTHING,
      EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE}},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 4,
     "ef_ebpf_extension_helper_implicit_1",
     EBPF_RETURN_TYPE_INTEGER,
     {0},
     {0},
     true},
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     EF_EXT_HELPER_FUNCTION_START + 5,
     "ef_ebpf_extension_helper_implicit_2",
     EBPF_RETURN_TYPE_INTEGER,
     {0},
     {0},
     true},
};

// Global helper function prototype descriptors.
static const ebpf_helper_function_prototype_t _ef_ebpf_extension_global_helper_function_prototype[] = {
    {
        EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
        BPF_FUNC_get_current_pid_tgid,
        "bpf_get_current_pid_tgid",
        EBPF_RETURN_TYPE_INTEGER,
    },
};

static const ebpf_program_info_t _ef_ebpf_extension_program_info = {
    EBPF_PROGRAM_INFORMATION_HEADER,
    &_ef_ebpf_extension_program_type_descriptor,
    EBPF_COUNT_OF(_ef_ebpf_extension_helper_function_prototype),
    _ef_ebpf_extension_helper_function_prototype,
    EBPF_COUNT_OF(_ef_ebpf_extension_global_helper_function_prototype),
    _ef_ebpf_extension_global_helper_function_prototype};

// Helper Function Definitions.

static int64_t
_ef_ebpf_extension_helper_function1(_In_ const ef_program_context_t* context)
{
    UNREFERENCED_PARAMETER(context);
    return 0;
}

static int64_t
_ef_ebpf_extension_find(_In_ const void* buffer, uint32_t size, _In_ const void* find, uint32_t arg_size)
{
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(arg_size);
    return strstr((char*)buffer, (char*)find) - (char*)buffer;
}

static int64_t
_ef_ebpf_extension_replace(
    _In_ const void* buffer, uint32_t size, int64_t position, _In_ const void* replace, uint32_t arg_size)
{
    int64_t result = 0;
    char* dest;
    char* end = (char*)buffer + size - 1;
    char* source = (char*)replace;
    UNREFERENCED_PARAMETER(arg_size);

    if (position < 0) {
        result = -1;
        goto Exit;
    }

    if (position >= size) {
        result = -1;
        goto Exit;
    }

    dest = (char*)buffer + position;
    while (dest != end) {
        if (*source == '\0') {
            break;
        }
        *dest++ = *source++;
    }

Exit:
    return result;
}

static int64_t
_ef_ebpf_extension_helper_implicit_1(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const ef_program_context_t* context)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);

    ef_program_context_t* ef_context = (ef_program_context_t*)context;
    return ef_context->helper_data_1;
}

static int64_t
_ef_ebpf_extension_helper_implicit_2(
    uint32_t arg,
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    _In_ const ef_program_context_t* context)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);

    ef_program_context_t* ef_context = (ef_program_context_t*)context;
    return ((uint64_t)ef_context->helper_data_2 + arg);
}

static const void* _ef_ebpf_extension_helpers[] = {
    (void*)&_ef_ebpf_extension_helper_function1,
    (void*)&_ef_ebpf_extension_find,
    (void*)&_ef_ebpf_extension_replace,
    (void*)&_ef_ebpf_extension_helper_implicit_1,
    (void*)&_ef_ebpf_extension_helper_implicit_2};

// Global Helper Function Definitions.
static uint64_t
_ef_get_pid_tgid()
{
    return EF_PID_TGID_VALUE;
}

typedef struct _ef_ebpf_extension_program_info_client
{
    HANDLE nmr_binding_handle;
    GUID client_module_id;
} ef_ebpf_extension_program_info_client_t;

static const ebpf_helper_function_addresses_t _ef_ebpf_extension_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ef_ebpf_extension_helpers),
    (uint64_t*)_ef_ebpf_extension_helpers};

static const void* _ef_global_helpers[] = {(void*)&_ef_get_pid_tgid};

static const ebpf_helper_function_addresses_t _ef_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER, EBPF_COUNT_OF(_ef_global_helpers), (uint64_t*)_ef_global_helpers};

ebpf_result_t
_ef_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

void
_ef_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

static ebpf_program_data_t _ef_ebpf_extension_program_data = {
    EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ef_ebpf_extension_program_info,
    .program_type_specific_helper_function_addresses = &_ef_ebpf_extension_helper_function_address_table,
    .global_helper_function_addresses = &_ef_global_helper_function_address_table,
    .context_create = &_ef_context_create,
    .context_destroy = &_ef_context_destroy,
    DISPATCH_LEVEL,
    true};

typedef struct _ef_program_context_header
{
    EBPF_CONTEXT_HEADER;
    ef_program_context_t context;
} ef_program_context_header_t;

ebpf_result_t
_ef_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t result;
    ef_program_context_header_t* context_header = NULL;
    ef_program_context_t* ef_context = NULL;

    *context = NULL;

    // This provider doesn't support data.
    if (data_in != NULL || data_size_in != 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // This provider requires context.
    if (context_in == NULL || context_size_in < sizeof(ef_program_context_t)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    context_header =
        cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, sizeof(ef_program_context_header_t), EF_EXT_POOL_TAG_DEFAULT);
    if (context_header == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    ef_context = (ef_program_context_t*)&context_header->context;

    memcpy(ef_context, context_in, sizeof(ef_program_context_t));

    *context = ef_context;
    context_header = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (context_header != NULL) {
        CXPLAT_FREE(context_header);
    }

    return result;
}

void
_ef_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    ef_program_context_header_t* context_header = NULL;
    if (context == NULL) {
        return;
    }
    context_header = CONTAINING_RECORD(context, ef_program_context_header_t, context);

    // This provider doesn't support data.
    *data_size_out = 0;

    if (context_out != NULL && *context_size_out >= sizeof(ef_program_context_t)) {
        memcpy(context_out, context, sizeof(ef_program_context_t));
        *context_size_out = sizeof(ef_program_context_t);
    } else {
        *context_size_out = 0;
    }

    CXPLAT_FREE(context_header);
}

typedef struct _ef_ebpf_extension_program_info_provider
{
    HANDLE nmr_provider_handle;
} ef_ebpf_extension_program_info_provider_t;

static ef_ebpf_extension_program_info_provider_t _ef_ebpf_extension_program_info_provider_context = {0};

typedef struct _ef_ebpf_extension_hook_provider ef_ebpf_extension_hook_provider_t;

/**
 *  @brief This is the per client binding context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _ef_ebpf_extension_hook_client
{
    HANDLE nmr_binding_handle;
    GUID client_module_id;
    const void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    ebpf_program_invoke_function_t invoke_program;
    ebpf_program_batch_begin_invoke_function_t begin_batch_program_invoke;
    ebpf_program_batch_end_invoke_function_t end_batch_program_invoke;
    ebpf_program_batch_invoke_function_t batch_program_invoke;
} ef_ebpf_extension_hook_client_t;

/**
 *  @brief This is the provider context of eBPF Hook NPI provider that
 *         maintains the provider registration state.
 */
typedef struct _ef_ebpf_extension_hook_provider
{
    HANDLE nmr_provider_handle;
    ef_ebpf_extension_hook_client_t* attached_client;
} ef_ebpf_extension_hook_provider_t;

static ef_ebpf_extension_hook_provider_t _ef_ebpf_extension_hook_provider_context = {0};

NPI_MODULEID DECLSPEC_SELECTANY _ef_ebpf_extension_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_FILE_OPS_GUID};

static NTSTATUS
_ef_ebpf_extension_program_info_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    ef_ebpf_extension_program_info_client_t* program_info_client = NULL;

    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(client_dispatch);
    UNREFERENCED_PARAMETER(client_binding_context);

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    program_info_client = cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED, sizeof(ef_ebpf_extension_program_info_client_t), EF_EXT_POOL_TAG_DEFAULT);
    if (program_info_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    RtlZeroMemory(program_info_client, sizeof(ef_ebpf_extension_program_info_client_t));

    program_info_client->nmr_binding_handle = nmr_binding_handle;
    program_info_client->client_module_id = client_registration_instance->ModuleId->Guid;

Exit:
    if (NT_SUCCESS(status)) {
        *provider_binding_context = program_info_client;
        program_info_client = NULL;
    } else if (program_info_client != NULL) {
        CXPLAT_FREE(program_info_client);
    }
    return status;
}

static NTSTATUS
_ef_ebpf_extension_program_info_provider_detach_client(_In_ const void* provider_binding_context)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(provider_binding_context);

    return status;
}

static void
_ef_ebpf_extension_program_info_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    CXPLAT_FREE(provider_binding_context);
}

const NPI_PROVIDER_CHARACTERISTICS _ef_ebpf_extension_program_info_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    _ef_ebpf_extension_program_info_provider_attach_client,
    _ef_ebpf_extension_program_info_provider_detach_client,
    _ef_ebpf_extension_program_info_provider_cleanup_binding_context,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_PROGRAM_INFO_EXTENSION_IID,
     &_ef_ebpf_extension_program_info_provider_moduleid,
     0,
     &_ef_ebpf_extension_program_data},
};

void
ef_ebpf_extension_program_info_provider_unregister()
{
    ef_ebpf_extension_program_info_provider_t* provider_context = &_ef_ebpf_extension_program_info_provider_context;
    NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
    }
}

NTSTATUS
ef_ebpf_extension_program_info_provider_register()
{
    ef_ebpf_extension_program_info_provider_t* local_provider_context;
    NTSTATUS status = STATUS_SUCCESS;

    local_provider_context = &_ef_ebpf_extension_program_info_provider_context;

    status = NmrRegisterProvider(
        &_ef_ebpf_extension_program_info_provider_characteristics,
        local_provider_context,
        &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ef_ebpf_extension_program_info_provider_unregister();
    }

    return status;
}

void
ef_ebpf_extension_hook_provider_unregister()
{
    ef_ebpf_extension_hook_provider_t* provider_context = &_ef_ebpf_extension_hook_provider_context;

    NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
    if (status == STATUS_PENDING) {
        // Wait for clients to detach.
        NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
    }
}

//
// Hook Provider.
//

static NTSTATUS
_ef_ebpf_extension_hook_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    NTSTATUS status = STATUS_SUCCESS;
    ef_ebpf_extension_hook_provider_t* local_provider_context = (ef_ebpf_extension_hook_provider_t*)provider_context;
    ef_ebpf_extension_hook_client_t* hook_client = NULL;
    ebpf_extension_program_dispatch_table_t* client_dispatch_table;

    if ((provider_binding_context == NULL) || (provider_dispatch == NULL) || (local_provider_context == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (local_provider_context->attached_client != NULL) {
        // Currently only a single client is allowed to attach.
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    hook_client =
        cxplat_allocate(CXPLAT_POOL_FLAG_NON_PAGED, sizeof(ef_ebpf_extension_hook_client_t), EF_EXT_POOL_TAG_DEFAULT);
    if (hook_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    RtlZeroMemory(hook_client, sizeof(ef_ebpf_extension_hook_client_t));

    if (hook_client == NULL) {
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    hook_client->nmr_binding_handle = nmr_binding_handle;
    hook_client->client_module_id = client_registration_instance->ModuleId->Guid;
    hook_client->client_binding_context = client_binding_context;
    hook_client->client_data = client_registration_instance->NpiSpecificCharacteristics;
    client_dispatch_table = (ebpf_extension_program_dispatch_table_t*)client_dispatch;
    if (client_dispatch_table == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    hook_client->invoke_program = client_dispatch_table->ebpf_program_invoke_function;
    hook_client->batch_program_invoke = client_dispatch_table->ebpf_program_batch_invoke_function;
    hook_client->begin_batch_program_invoke = client_dispatch_table->ebpf_program_batch_begin_invoke_function;
    hook_client->end_batch_program_invoke = client_dispatch_table->ebpf_program_batch_end_invoke_function;

    local_provider_context->attached_client = hook_client;

Exit:

    if (NT_SUCCESS(status)) {
        *provider_binding_context = hook_client;
        hook_client = NULL;
    } else if (hook_client != NULL) {
        CXPLAT_FREE(hook_client);
    }

    return status;
}

static NTSTATUS
_ef_ebpf_extension_hook_provider_detach_client(_In_ const void* provider_binding_context)
{
    NTSTATUS status = STATUS_SUCCESS;

    ef_ebpf_extension_hook_client_t* local_client_context = (ef_ebpf_extension_hook_client_t*)provider_binding_context;
    ef_ebpf_extension_hook_provider_t* provider_context = NULL;

    if (local_client_context == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    provider_context = &_ef_ebpf_extension_hook_provider_context;
    provider_context->attached_client = NULL;

Exit:
    return status;
}

static void
_ef_ebpf_extension_hook_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
{
    CXPLAT_FREE(provider_binding_context);
}

NPI_MODULEID DECLSPEC_SELECTANY _ef_ebpf_extension_hook_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_FILE_OPS_GUID};

// EF eBPF extension Hook NPI provider characteristics
ebpf_attach_provider_data_t _ef_ebpf_extension_attach_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_HEADER, EBPF_PROGRAM_TYPE_FILE_OPS_GUID, BPF_ATTACH_TYPE_SAMPLE, BPF_LINK_TYPE_UNSPEC};

const NPI_PROVIDER_CHARACTERISTICS _ef_ebpf_extension_hook_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    _ef_ebpf_extension_hook_provider_attach_client,
    _ef_ebpf_extension_hook_provider_detach_client,
    _ef_ebpf_extension_hook_provider_cleanup_binding_context,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_HOOK_EXTENSION_IID,
     &_ef_ebpf_extension_hook_provider_moduleid,
     0,
     &_ef_ebpf_extension_attach_provider_data},
};

NTSTATUS
ef_ebpf_extension_hook_provider_register()
{
    ef_ebpf_extension_hook_provider_t* local_provider_context;
    NTSTATUS status = STATUS_SUCCESS;

    local_provider_context = &_ef_ebpf_extension_hook_provider_context;

    status = NmrRegisterProvider(
        &_ef_ebpf_extension_hook_provider_characteristics,
        local_provider_context,
        &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ef_ebpf_extension_hook_provider_unregister();
    }

    return status;
}
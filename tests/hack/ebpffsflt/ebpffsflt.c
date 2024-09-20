// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @brief Implementation of file system mini-filter to provide eBPF hook points.
 */

#include "ebpfprov.h"

#include <fltKernel.h>
#include <suppress.h>

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;

#define EF_DBG_TRACE_ROUTINES 0x00000001
#define EF_DBG_TRACE_OPERATION_STATUS 0x00000002

ULONG gTraceFlags = 0;

#define EF_DBG_PRINT(_dbgLevel, _string) (FlagOn(gTraceFlags, (_dbgLevel)) ? DbgPrint _string : ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
EfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
EfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

VOID
EfInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID
EfInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS
EfInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
EfPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
EfPreOperationNoPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
EfPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
EfPostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, EfUnload)
#pragma alloc_text(PAGE, EfInstanceQueryTeardown)
#pragma alloc_text(PAGE, EfInstanceSetup)
#pragma alloc_text(PAGE, EfInstanceTeardownStart)
#pragma alloc_text(PAGE, EfInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, EfPreOperationCallback, EfPostCreateCallback},

    {IRP_MJ_CREATE_NAMED_PIPE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_CLOSE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_READ, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_WRITE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_QUERY_INFORMATION, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_SET_INFORMATION, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_QUERY_EA, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_SET_EA, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_FLUSH_BUFFERS, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_QUERY_VOLUME_INFORMATION, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_SET_VOLUME_INFORMATION, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_DIRECTORY_CONTROL, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_FILE_SYSTEM_CONTROL, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_DEVICE_CONTROL, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_SHUTDOWN, 0, EfPreOperationNoPostOperationCallback, NULL}, // post operations not supported

    {IRP_MJ_LOCK_CONTROL, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_CLEANUP, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_CREATE_MAILSLOT, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_QUERY_SECURITY, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_SET_SECURITY, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_QUERY_QUOTA, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_SET_QUOTA, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_PNP, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_ACQUIRE_FOR_MOD_WRITE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_RELEASE_FOR_MOD_WRITE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_ACQUIRE_FOR_CC_FLUSH, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_RELEASE_FOR_CC_FLUSH, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_NETWORK_QUERY_OPEN, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_MDL_READ, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_MDL_READ_COMPLETE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_PREPARE_MDL_WRITE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_MDL_WRITE_COMPLETE, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_VOLUME_MOUNT, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_VOLUME_DISMOUNT, 0, EfPreOperationCallback, EfPostOperationCallback},

    {IRP_MJ_OPERATION_END}};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION), //  Size
    FLT_REGISTRATION_VERSION, //  Version
    0,                        //  Flags

    NULL,      //  Context
    Callbacks, //  Operation callbacks

    EfUnload, //  MiniFilterUnload

    EfInstanceSetup,            //  InstanceSetup
    EfInstanceQueryTeardown,    //  InstanceQueryTeardown
    EfInstanceTeardownStart,    //  InstanceTeardownStart
    EfInstanceTeardownComplete, //  InstanceTeardownComplete

    NULL, //  GenerateFileName
    NULL, //  GenerateDestinationFileName
    NULL  //  NormalizeNameComponent

};

NTSTATUS
EfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are alwasys created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
EfInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}

VOID
EfInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfInstanceTeardownStart: Entered\n"));
}

VOID
EfInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfInstanceTeardownComplete: Entered\n"));
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!DriverEntry: Entered\n"));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    //
    //  Start filtering i/o
    //

    status = FltStartFiltering(gFilterHandle);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    //
    //  Register with eBPF extension.
    //

    status = ef_ext_program_info_provider_register();

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = ef_ext_hook_provider_register();

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status)) {

        EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!DriverEntry: Failed\n"));

        ef_ext_hook_provider_unregister();
        ef_ext_program_info_provider_unregister();

        if (gFilterHandle != NULL) {
            FltUnregisterFilter(gFilterHandle);
        }
    }

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!DriverEntry: Exited\n"));

    return status;
}

NTSTATUS
EfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unloaded indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfUnload: Entered\n"));

    ef_ext_hook_provider_unregister();
    ef_ext_program_info_provider_unregister();
    FltUnregisterFilter(gFilterHandle);

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfUnload: Exited\n"));

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
EfPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
/*++

Routine Description:

    This routine is the main pre-operation dispatch routine for this
    miniFilter. Since this is just a simple passThrough miniFilter it
    does not do anything with the callbackData but rather return
    FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
    miniFilter in the chain.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfPreOperationCallback: Entered\n"));

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
EfPreOperationNoPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
/*++

Routine Description:

    This routine is the main pre-operation dispatch routine for this
    miniFilter. Since this is just a simple passThrough miniFilter it
    does not do anything with the callbackData but rather return
    FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
    miniFilter in the chain.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfPreOperationNoPostOperationCallback: Entered\n"));

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
EfPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfPostOperationCallback: Entered\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
EfPostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
/*++

Routine Description:

    This routine is the post-create completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfPostCreateCallback: Entered\n"));

    UINT32 ebpfResult = 0;
    ef_program_context_t ebpfProgramContext = {0};

    ebpf_result_t ebpfInvokeResult = ef_ext_invoke_program(&ebpfProgramContext, &ebpfResult);

    EF_DBG_PRINT(
        EF_DBG_TRACE_ROUTINES,
        ("EbpfFsFlt!EfPostCreateCallback: ebpfInvokeResult = %d ebpfResult = %ul\n", ebpfInvokeResult, ebpfResult));

    EF_DBG_PRINT(EF_DBG_TRACE_ROUTINES, ("EbpfFsFlt!EfPostCreateCallback: Exited\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}

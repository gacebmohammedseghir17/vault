#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;

// Entropy calculation logic placeholder (In real driver, do not use float, use integer math for kernel)
BOOLEAN IsBufferEncrypted(PVOID Buffer, ULONG Length) {
    // A simplified representation. In a real kernel driver, floating point math is discouraged.
    // High entropy (> 7.5 bits/byte) strongly indicates encryption or compression.
    // We would use an integer-based approximation of Shannon Entropy here.
    return FALSE; 
}

FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    // Only inspect normal IRPs, skip paging I/O to avoid deadlock
    if (FLT_IS_PAGING_IO(Data) || FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PVOID writeBuffer = NULL;

    if (iopb->Parameters.Write.Length > 0) {
        if (iopb->Parameters.Write.MdlAddress != NULL) {
            writeBuffer = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress, NormalPagePriority);
        } else {
            writeBuffer = iopb->Parameters.Write.WriteBuffer;
        }

        if (writeBuffer != NULL) {
            __try {
                // Probe buffer and calculate entropy
                if (IsBufferEncrypted(writeBuffer, iopb->Parameters.Write.Length)) {
                    // Ransomware detected! High entropy write!
                    // 1. Block the write
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    
                    // 2. Notify User-Mode Agent via FltSendMessage
                    // NotifyUserModeAgent(Data->Thread->Cid.UniqueProcess);

                    return FLT_PREOP_COMPLETE;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE, 0, PreWriteCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof( FLT_REGISTRATION ),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    NULL, // Unload
    NULL, // InstanceSetup
    NULL, // InstanceQueryTeardown
    NULL, // InstanceTeardownStart
    NULL, // InstanceTeardownComplete
    NULL, // GenerateFileName
    NULL, // NormalizeNameComponent
    NULL  // NormalizeContextCleanup
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    // Register the Minifilter
    status = FltRegisterFilter( DriverObject, &FilterRegistration, &gFilterHandle );
    if (NT_SUCCESS( status )) {
        // Start filtering i/o
        status = FltStartFiltering( gFilterHandle );
        if (!NT_SUCCESS( status )) {
            FltUnregisterFilter( gFilterHandle );
        }
    }
    return status;
}

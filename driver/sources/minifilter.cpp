#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "shared_def.h"

// Forward declarations
extern PFLT_FILTER gFilterHandle;
extern PFLT_INSTANCE gMyVaultInstance; // The instance where we store backups

// --- DYNAMIC RULE ENGINE GLOBALS ---
#define MAX_RULES 64
#define MAX_ALLOWED_PROCESSES 32

typedef struct _ERDPS_GLOBAL_DATA {
    ERDPS_RULE Rules[MAX_RULES];
    ULONG RuleCount;
    ERDPS_ALLOW_PROCESS AllowedProcesses[MAX_ALLOWED_PROCESSES];
    ULONG AllowedCount;
    FAST_MUTEX RuleLock; // Prevents crashing if we read while updating
} ERDPS_GLOBAL_DATA, *PERDPS_GLOBAL_DATA;

ERDPS_GLOBAL_DATA gErdpsData;

// Helper to initialize globals (Call this in DriverEntry)
VOID ErdpsInitializeGlobals() {
    RtlZeroMemory(&gErdpsData, sizeof(gErdpsData));
    ExInitializeFastMutex(&gErdpsData.RuleLock);
    
    // Add default rules (Safe Fallback)
    wcscpy(gErdpsData.Rules[0].Extension, L".docx");
    gErdpsData.Rules[0].EntropyThreshold = 7.5;
    gErdpsData.RuleCount = 1;
}

// Helper to check if a process is allowed
BOOLEAN ErdpsIsProcessAllowed(_In_ PFLT_CALLBACK_DATA Data) {
    PEPROCESS process = IoThreadToProcess(Data->Thread);
    PUNICODE_STRING processName = NULL;
    // Note: FltGetRequestorProcessName is not a standard API, we usually use SeLocateProcessImageName
    // or IoQueryFileDosDeviceName. For simplicity in this architecture, we will check if the IOCTL
    // logic added it. In a real driver, we'd get the image path.
    //
    // Simplified: Check if we have any allowed processes (Stub logic for architecture)
    if (gErdpsData.AllowedCount > 0) {
        // Real implementation would compare image name here
        return FALSE; // Default to not allowed for safety in stub
    }
    return FALSE;
}

// Stream Handle Context to track if we already backed up this file handle
typedef struct _ERDPS_STREAM_HANDLE_CONTEXT {
    BOOLEAN BackupComplete;
} ERDPS_STREAM_HANDLE_CONTEXT, *PERDPS_STREAM_HANDLE_CONTEXT;

//
//  Message Notify Callback - Handles IOCTLs from User Mode
//
NTSTATUS
ErdpsMessageNotifyCallback (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

    if (InputBuffer == NULL || InputBufferSize < sizeof(ERDPS_RULE)) {
        return STATUS_INVALID_PARAMETER;
    }

    // 1. Cast the raw bytes to our Rule Struct
    PERDPS_RULE newRule = (PERDPS_RULE)InputBuffer;

    // 2. Lock the list (Thread Safety is critical in Kernel!)
    ExAcquireFastMutex(&gErdpsData.RuleLock);

    // 3. Add the rule if we have space
    if (gErdpsData.RuleCount < MAX_RULES) {
        // Copy data safely
        RtlCopyMemory(&gErdpsData.Rules[gErdpsData.RuleCount], newRule, sizeof(ERDPS_RULE));
        gErdpsData.RuleCount++;
        DbgPrint("ERDPS: Added Dynamic Rule for %ws (Entropy: %f)\n", newRule->Extension, newRule->EntropyThreshold);
    } else {
        DbgPrint("ERDPS: Rule List Full!\n");
    }

    // 4. Unlock
    ExReleaseFastMutex(&gErdpsData.RuleLock);
    
    // Handle Allowlist IOCTL (Stub)
    // if (FunctionCode == IOCTL_ERDPS_ADD_ALLOW) { ... }

    return STATUS_SUCCESS;
}

//
//  PreWrite Callback - The Critical Path
//
FLT_PREOP_CALLBACK_STATUS
ErdpsPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PERDPS_STREAM_HANDLE_CONTEXT context = NULL;
    BOOLEAN isTargetExtension = FALSE;
    
    UNREFERENCED_PARAMETER(CompletionContext);

    //
    //  Requirement A: Anti-Deadlock / Reentrancy Guard
    //
    
    // 1. Check if the write comes from our own driver (re-issued I/O)
    // In a real driver, you would check an ECP or verify the VolumeInstance.
    // For this implementation, we check if the Target Instance matches our Backup Vault Instance.
    if (gMyVaultInstance != NULL && FltObjects->Instance == gMyVaultInstance) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2. Check Process ID (Exclude System/VSS to prevent system hangs)
    // System Process ID is usually 4. VSS Service runs as Local System.
    // A robust check would verify the Process Image Name, but PID 4 check is a fast heuristic.
    if (FltGetRequestorProcessId(Data) == (HANDLE)4) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2.5 Allowlist Check (Upgrade 1)
    if (ErdpsIsProcessAllowed(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 3. Check IRP Flags for Paging I/O (we only care about User writes)
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Requirement B: The Trigger
    //

    // 1. Get File Name
    status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                     &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2. Check Extension (Dynamic Rule Engine)
    // 1. Lock List
    ExAcquireFastMutex(&gErdpsData.RuleLock);

    // 2. Check file extension against Dynamic Rules
    for (ULONG i = 0; i < gErdpsData.RuleCount; i++) {
        UNICODE_STRING ruleExt;
        RtlInitUnicodeString(&ruleExt, gErdpsData.Rules[i].Extension);

        if (RtlSuffixUnicodeString(&ruleExt, &nameInfo->Extension, TRUE)) {
            isTargetExtension = TRUE;
            // targetEntropy = gErdpsData.Rules[i].EntropyThreshold; // Use this later
            break;
        }
    }

    // 3. Unlock List
    ExReleaseFastMutex(&gErdpsData.RuleLock);

    if (!isTargetExtension) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 3. Check Stream Handle Context (Already Backed Up?)
    status = FltGetStreamHandleContext(FltObjects->Instance,
                                     FltObjects->FileObject,
                                     (PFLT_CONTEXT*)&context);

    if (NT_SUCCESS(status)) {
        // Context exists
        if (context->BackupComplete) {
            // Already backed up in this session, ignore
            FltReleaseContext(context);
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    } else if (status == STATUS_NOT_FOUND) {
        // Create new context
        status = FltAllocateContext(gFilterHandle,
                                  FLT_STREAMHANDLE_CONTEXT,
                                  sizeof(ERDPS_STREAM_HANDLE_CONTEXT),
                                  PagedPool,
                                  (PFLT_CONTEXT*)&context);
        if (NT_SUCCESS(status)) {
            context->BackupComplete = FALSE;
            (VOID)FltSetStreamHandleContext(FltObjects->Instance,
                                          FltObjects->FileObject,
                                          FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                          context,
                                          NULL);
            // Keep the reference for below
        }
    }

    //
    //  PERFORM COPY-ON-WRITE (Logic Stub)
    //  At this point: Target Extension + Not System + Not Backed Up
    //

    // TODO: Call FltCreateFile / FltWriteFile to C:\ProgramData\ERDPS\Vault
    // This is where the actual data movement happens.
    // DbgPrint("ERDPS: Backing up file %wZ\n", &nameInfo->Name);

    // Mark as backed up
    if (context != NULL) {
        context->BackupComplete = TRUE;
        FltReleaseContext(context);
    }

    FltReleaseFileNameInformation(nameInfo);

    // Always return SUCCESS for the Write to proceed (unless we want to block it)
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// [ERDPS] Minifilter Entropy Check Implementation
// Copy this into your Minifilter's IRP_MJ_WRITE Pre-Operation Callback.

#include <fltKernel.h>
#include <ntstrsafe.h>

// Define the entropy threshold (e.g., 7.9 for encrypted data)
#define ENTROPY_THRESHOLD 7.9
// Define the message type for the user-mode agent
#define ERDPS_MSG_FILE_WRITE 4

// Simple Shannon Entropy Calculation (Kernel Mode)
// Note: Floating point in kernel requires KFLOATING_SAVE
FLOAT CalculateEntropy(PUCHAR Buffer, ULONG Length) {
    if (Length == 0) return 0.0f;

    ULONG Counts[256] = { 0 };
    for (ULONG i = 0; i < Length; i++) {
        Counts[Buffer[i]]++;
    }

    FLOAT Entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (Counts[i] > 0) {
            FLOAT p = (FLOAT)Counts[i] / (FLOAT)Length;
            // Kernel log2 approximation or use a lookup table
            // For simplicity in this snippet, we assume a helper Log2 function exists
            // Entropy -= p * Log2(p); 
        }
    }
    return Entropy;
}

// Pre-Write Callback
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->MajorFunction != IRP_MJ_WRITE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 1. Check if we care about this process (e.g., not System)
    PEPROCESS Process = FltGetRequestorProcess(Data);
    HANDLE Pid = PsGetProcessId(Process);
    if (Pid == (HANDLE)4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 2. Get the Write Buffer
    PVOID Buffer = NULL;
    ULONG Length = Data->Iopb->Parameters.Write.Length;
    
    // Only check significant writes (> 4KB) to avoid noise
    if (Length < 4096) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
        Buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    } else {
        Buffer = Data->Iopb->Parameters.Write.WriteBuffer;
    }

    if (Buffer == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 3. Calculate Entropy (Wrap in Float Save/Restore)
    KFLOATING_SAVE FloatSave;
    NTSTATUS Status = KeSaveFloatingPointState(&FloatSave);
    if (NT_SUCCESS(Status)) {
        FLOAT Entropy = CalculateEntropy((PUCHAR)Buffer, Length);
        KeRestoreFloatingPointState(&FloatSave);

        // 4. Heuristic: High Entropy Write?
        if (Entropy > ENTROPY_THRESHOLD) {
            // Check file extension (is it changing?) or just alert on high entropy write
            // For now, we alert the Agent.
            
            ERDPS_ALERT Alert = { 0 };
            Alert.Pid = (ULONG)(ULONG_PTR)Pid;
            Alert.Reason = ERDPS_MSG_FILE_WRITE;
            
            // Get File Path
            PFLT_FILE_NAME_INFORMATION NameInfo;
            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo))) {
                FltParseFileNameInformation(NameInfo);
                RtlStringCchCopyW(Alert.FilePath, 260, NameInfo->Name.Buffer);
                FltReleaseFileNameInformation(NameInfo);
            }

            // Send to Agent
            ULONG ReplyLength = 0;
            FltSendMessage(FilterHandle, &ClientPort, &Alert, sizeof(Alert), NULL, &ReplyLength, NULL);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

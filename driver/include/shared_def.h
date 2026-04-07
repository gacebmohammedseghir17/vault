#ifndef _SHARED_DEF_H_
#define _SHARED_DEF_H_

// Force 1-byte alignment for stable ABI between C++ (Driver) and Rust (User)
#pragma pack(push, 1)

// Message Types
#define ERDPS_MSG_FILE_WRITE 1
#define ERDPS_MSG_FILE_CREATE 2
#define ERDPS_MSG_PROCESS_CREATE 3

// Maximum path length for the struct
#define MAX_PATH_LEN 512

typedef struct _RANSOM_EVENT {
    unsigned long ProcessId;      // 4 bytes
    unsigned long ThreadId;       // 4 bytes
    unsigned long EventType;      // 4 bytes
    double EntropyScore;          // 8 bytes
    unsigned long long Timestamp; // 8 bytes (Windows FILETIME or Unix Epoch)
    wchar_t FilePath[MAX_PATH_LEN]; // 512 * 2 = 1024 bytes
} RANSOM_EVENT, *PRANSOM_EVENT;

// New: Command to update Kernel Rules
#define IOCTL_ERDPS_ADD_RULE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ERDPS_CLEAR_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ERDPS_ADD_ALLOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ERDPS_REMOVE_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _ERDPS_RULE {
    wchar_t Extension[8]; // e.g., ".docx"
    double EntropyThreshold; // e.g., 7.5
    unsigned char EnableBackup; // BOOLEAN is typically unsigned char
} ERDPS_RULE, *PERDPS_RULE;

typedef struct _ERDPS_ALLOW_PROCESS {
    wchar_t ProcessName[64]; // e.g., "git.exe"
} ERDPS_ALLOW_PROCESS, *PERDPS_ALLOW_PROCESS;

#pragma pack(pop)

#endif // _SHARED_DEF_H_

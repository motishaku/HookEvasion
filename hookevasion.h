#pragma once
#include <Windows.h>

#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040 // https://processhacker.sourceforge.io/doc/ntbasic_8h.html
#define FILE_OVERWRITE_IF 0x00000005 // https://processhacker.sourceforge.io/doc/ntioapi_8h.html
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020 // ^
#define 	FILE_OPEN   0x00000001 // ^^
#define 	FILE_NON_DIRECTORY_FILE   0x00000040 // ^^^
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020 // you got it by now.


// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-initializeobjectattributes
#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }



typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,                   // 2
	FileBothDirectoryInformation,                   // 3
	FileBasicInformation,                           // 4
	FileStandardInformation,                        // 5
	FileInternalInformation,                        // 6
	FileEaInformation,                              // 7
	FileAccessInformation,                          // 8
	FileNameInformation,                            // 9
	FileRenameInformation,                          // 10
	FileLinkInformation,                            // 11
	FileNamesInformation,                           // 12
	FileDispositionInformation,                     // 13
	FilePositionInformation,                        // 14
	FileFullEaInformation,                          // 15
	FileModeInformation,                            // 16
	FileAlignmentInformation,                       // 17
	FileAllInformation,                             // 18
	FileAllocationInformation,                      // 19
	FileEndOfFileInformation,                       // 20
	FileAlternateNameInformation,                   // 21
	FileStreamInformation,                          // 22
	FilePipeInformation,                            // 23
	FilePipeLocalInformation,                       // 24
	FilePipeRemoteInformation,                      // 25
	FileMailslotQueryInformation,                   // 26
	FileMailslotSetInformation,                     // 27
	FileCompressionInformation,                     // 28
	FileObjectIdInformation,                        // 29
	FileCompletionInformation,                      // 30
	FileMoveClusterInformation,                     // 31
	FileQuotaInformation,                           // 32
	FileReparsePointInformation,                    // 33
	FileNetworkOpenInformation,                     // 34
	FileAttributeTagInformation,                    // 35
	FileTrackingInformation,                        // 36
	FileIdBothDirectoryInformation,                 // 37
	FileIdFullDirectoryInformation,                 // 38
	FileValidDataLengthInformation,                 // 39
	FileShortNameInformation,                       // 40
	FileIoCompletionNotificationInformation,        // 41
	FileIoStatusBlockRangeInformation,              // 42
	FileIoPriorityHintInformation,                  // 43
	FileSfioReserveInformation,                     // 44
	FileSfioVolumeInformation,                      // 45
	FileHardLinkInformation,                        // 46
	FileProcessIdsUsingFileInformation,             // 47
	FileNormalizedNameInformation,                  // 48
	FileNetworkPhysicalNameInformation,             // 49
	FileIdGlobalTxDirectoryInformation,             // 50
	FileIsRemoteDeviceInformation,                  // 51
	FileUnusedInformation,                          // 52
	FileNumaNodeInformation,                        // 53
	FileStandardLinkInformation,                    // 54
	FileRemoteProtocolInformation,                  // 55

		//
		//  These are special versions of these operations (defined earlier)
		//  which can be used by kernel mode drivers only to bypass security
		//  access checks for Rename and HardLink operations.  These operations
		//  are only recognized by the IOManager, a file system should never
		//  receive these.
		//

		FileRenameInformationBypassAccessCheck,         // 56
		FileLinkInformationBypassAccessCheck,           // 57

			//
			// End of special information classes reserved for IOManager.
			//

			FileVolumeNameInformation,                      // 58
			FileIdInformation,                              // 59
			FileIdExtdDirectoryInformation,                 // 60
			FileReplaceCompletionInformation,               // 61
			FileHardLinkFullIdInformation,                  // 62
			FileIdExtdBothDirectoryInformation,             // 63
			FileDispositionInformationEx,                   // 64
			FileRenameInformationEx,                        // 65
			FileRenameInformationExBypassAccessCheck,       // 66
			FileDesiredStorageClassInformation,             // 67
			FileStatInformation,                            // 68
			FileMemoryPartitionInformation,                 // 69
			FileStatLxInformation,                          // 70
			FileCaseSensitiveInformation,                   // 71
			FileLinkInformationEx,                          // 72
			FileLinkInformationExBypassAccessCheck,         // 73
			FileStorageReserveIdInformation,                // 74
			FileCaseSensitiveInformationForceAccessCheck,   // 75
			FileKnownFolderInformation,   // 76

			FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS

	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS

	PWSTR  Buffer;
#endif // MIDL_PASS
}
UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;


typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


EXTERN_C NTSTATUS MyNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS MyNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
EXTERN_C NTSTATUS MyNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAcess, PVOID ObjectAttributes, HANDLE ProcessHandle, PTHREAD_START_ROUTINE StartAddress, PVOID Parameter, BOOLEAN CreateSuspended, ULONG StackZeroBits, SIZE_T StackCommit, SIZE_T StackReserve, PVOID pThreadExData);
EXTERN_C NTSTATUS MyNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
EXTERN_C NTSTATUS MyNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
EXTERN_C NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
EXTERN_C NTSTATUS MyNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS(*NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);


NTSTATUS(*NtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PSIZE_T NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
	);


NTSTATUS(*NtCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAcess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PTHREAD_START_ROUTINE StartAddress,
	PVOID Parameter,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	SIZE_T StackCommit,
	SIZE_T StackReserve,
	PVOID pThreadExData
	);

NTSTATUS(*NtWaitForSingleObject)(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout
	);

NTSTATUS(*NtQueryInformationFile)(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

NTSTATUS(*NtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	);

NTSTATUS(*NtReadFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);
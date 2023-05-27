#include <ntifs.h>
#include <ntddk.h>
#include "types.h"
#include "PureDOOM.h"

typedef struct _WIN32K_THREAD_CONTEXT {
	KAPC Apc;
	KEVENT CompletedEvent;
} WIN32K_THREAD_CONTEXT, *PWIN32K_THREAD_CONTEXT;

int _fltused = 0x9875; // THIS JUST WORKS AND I DONT KNOW WHY!

NT_USER_GET_CURSOR_POS NtUserGetCursorPos = NULL;				// Win32kfull
NT_USER_GET_DC NtUserGetDc = NULL;								// Win32kbase
NT_GDI_SELECT_BRUSH NtGdiSelectBrush = NULL;					// Win32kbase GreSelectBrush
NT_GDI_PAT_BLT NtGdiPatBlt = NULL;								// Win32kfull
NT_USER_RELEASE_DC NtUserReleaseDc = NULL;						// Win32kbase
NT_GDI_CREATE_SOLID_BRUSH NtGdiCreateSolidBrush = NULL;			// Win32kfull
NT_GDI_DELETE_OBJECT_APP NtGdiDeleteObjectApp = NULL;			// Win32kbase
NT_GDI_CREATE_BITMAP NtGdiCreateBitmap = NULL;					// Win32kfull
NT_GDI_SELECT_BITMAP NtGdiSelectBitmap = NULL;					// Win32kbase GreSelectBitmap
NT_GDI_CREATE_COMPATIBLE_DC NtGdiCreateCompatibleDc = NULL;		// Win32kbase GreCreateCompatibleDC
NT_GDI_BIT_BLT NtGdiBitBlt = NULL;								// Win32kfull NtGdiBitBlt
NT_USER_GET_KEY_STATE NtUserGetKeyState = NULL;					// Win32kbase

__forceinline wchar_t locase_w(wchar_t c) {
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

int _strcmpi_w(const wchar_t* s1, const wchar_t* s2) {
	wchar_t c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = locase_w(*s1);
		c2 = locase_w(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}


PVOID GetModuleBase(WCHAR* Name, PDRIVER_OBJECT DriverObject) {
	PLDR_DATA_TABLE_ENTRY entry =
		(PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY first = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first) {
		if (_strcmpi_w(entry->BaseDllName.Buffer, Name) == 0) {
			return entry->DllBase;
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	return NULL;
}

NTSTATUS
OpenSessionProcessThread(
	_Outptr_ PEPROCESS *Process,
	_Outptr_ PETHREAD *Thread,
	_In_ PUNICODE_STRING ProcessName,
	_In_ ULONG SessionId,
	_Out_ PVOID *Win32Process,
	_Out_ PVOID *Win32Thread,
	_Out_ PCLIENT_ID ClientId
	)
{
	ULONG Size;
	NTSTATUS Status;
	if ((Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH))
		return Status;
	const PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = ExAllocatePoolZero(NonPagedPool, 2ull * Size, 'mooD');
	if (SystemProcessInfo == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	Status = ZwQuerySystemInformation(SystemProcessInformation,
										SystemProcessInfo,
										2 * Size,
										NULL);
	if (!NT_SUCCESS(Status)) {
		ExFreePool(SystemProcessInfo);
		return Status;
	}

	PSYSTEM_PROCESS_INFORMATION Entry = SystemProcessInfo;
	Status = STATUS_NOT_FOUND;

	while (TRUE) {

		if (Entry->ImageName.Buffer != NULL && RtlEqualUnicodeString(&Entry->ImageName, ProcessName, TRUE)) {
			Status = PsLookupProcessByProcessId(Entry->UniqueProcessId, Process);
			if (NT_SUCCESS(Status)) {
				if (PsGetProcessSessionIdEx(*Process) == SessionId) {
					// hack to (probably) find the main thread ID
					CLIENT_ID MinThreadIdCid = { .UniqueProcess = NULL, .UniqueThread = (HANDLE)MAXULONG_PTR };
					for (ULONG i = 0; i < Entry->NumberOfThreads; ++i) {
						if ((ULONG)(ULONG_PTR)Entry->Threads[i].ClientId.UniqueThread < (ULONG)(ULONG_PTR)MinThreadIdCid.UniqueThread) {
							MinThreadIdCid = Entry->Threads[i].ClientId;
						}
					}

					for (ULONG i = 0; i < Entry->NumberOfThreads; ++i) {
						Status = PsLookupProcessThreadByCid(&MinThreadIdCid, NULL, Thread);
						if (NT_SUCCESS(Status)) {
							if ((*Win32Process = PsGetProcessWin32Process(*Process)) != NULL &&
								(*Win32Thread = PsGetThreadWin32Thread(*Thread)) != NULL) {
								*ClientId = MinThreadIdCid;
								ExFreePool(SystemProcessInfo);
								return STATUS_SUCCESS;
							}
							ObDereferenceObject(*Thread);
						}
					}
				}
				ObDereferenceObject(*Process);
			}
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)Entry + Entry->NextEntryOffset);
	}

	ExFreePool(SystemProcessInfo);
	return Status;
}

NTSTATUS CreateThread(PVOID entry) {
	HANDLE threadHandle = NULL;
	NTSTATUS status = PsCreateSystemThread(&threadHandle, NULL, NULL, NULL,
		NULL, (PKSTART_ROUTINE)entry, NULL);

	if (!NT_SUCCESS(status)) return status;

	ZwClose(threadHandle);
	return status;
}

BOOLEAN FrameRect(HDC hDC, CONST RECT* lprc, HBRUSH hbr) {
	HBRUSH oldbrush = NULL;
	RECT r = *lprc;

	if ((r.right <= r.left) || (r.bottom <= r.top))
		return FALSE;
	// if (!(oldbrush = NtGdiSelectBrush(hDC, hbr))) return false;
	oldbrush = NtGdiSelectBrush(hDC, hbr);
	NtGdiPatBlt(hDC, r.left, r.top, 1, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.right - 1, r.top, 1, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.top, r.right - r.left, 1, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.bottom - 1, r.right - r.left, 1, PATCOPY);

	if (oldbrush)
		NtGdiSelectBrush(hDC, oldbrush);
	return TRUE;
}

PVOID AllocateUserMemory(SIZE_T Size) {
	PVOID pMem = NULL;
	NTSTATUS statusAlloc = ZwAllocateVirtualMemory(
		NtCurrentProcess(), &pMem, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
	return pMem;
}

BOOLEAN Running = TRUE;

VOID Sleep(INT ms) {
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -(ms) * 10 * 1000;
	KeDelayExecutionThread(KernelMode, TRUE, &time);
}


VOID* DoomOpen(CHAR* File, CHAR* Mode) {
	ANSI_STRING ansiName = { 0 };
	UNICODE_STRING uniName = { 0 };

	RtlInitAnsiString(&ansiName, File);

	RtlAnsiStringToUnicodeString(&uniName, &ansiName, TRUE);

	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr = { 0 };

	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	IO_STATUS_BLOCK ioSB = { 0 };

	NTSTATUS status =
		ZwCreateFile(&hFile, FILE_GENERIC_READ, &objAttr, &ioSB, 0,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF,
			FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0);

	if (status != 0)
		hFile = NULL;

	return hFile;
}

VOID DoomClose(VOID* Handle) {
	if (Handle == NULL)
		return;
	ZwClose(Handle);
}

INT DoomRead(VOID* Handle, VOID* Buf, INT Count) {
	if (Handle == NULL)
		return 0;

	INT nRead = 0;

	IO_STATUS_BLOCK ioSB = { 0 };

	if (ZwReadFile(Handle, NULL, NULL, NULL, &ioSB, Buf, Count, NULL, NULL) ==
		STATUS_SUCCESS) {
		ZwWaitForSingleObject(Handle, FALSE, NULL);

		if (ioSB.Status != STATUS_SUCCESS)
			return 0;
		if (ioSB.Information == 0)
			return Count;

		nRead = ioSB.Information;
	}

	return nRead;
}

INT DoomTell(VOID* Handle) {
	if (Handle == NULL)
		return 0;

	IO_STATUS_BLOCK ioSB = { 0 };
	FILE_POSITION_INFORMATION filePos = { 0 };

	if (ZwQueryInformationFile(Handle, &ioSB, &filePos,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation) != STATUS_SUCCESS)
		return -1;

	return (int)(filePos.CurrentByteOffset.QuadPart);
}

INT DoomEof(VOID* Handle) {
	if (Handle == NULL)
		return -1;

	ULONGLONG fileSize = 0;
	IO_STATUS_BLOCK ioSB = { 0 };
	FILE_STANDARD_INFORMATION fileStd = { 0 };

	if (ZwQueryInformationFile(Handle, &ioSB, &fileStd,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation) != STATUS_SUCCESS)
		return -1;

	fileSize = fileStd.EndOfFile.QuadPart;

	if (DoomTell(Handle) >= fileSize - 1)
		return 1;
	return 0;
}

INT DoomSeek(VOID* Handle, INT Offset, doom_seek_t SeekType) {
	if (Handle == NULL)
		return -1;

	INT currOffset = Offset;

	ULONGLONG fileSize = 0;
	IO_STATUS_BLOCK ioSB = { 0 };
	FILE_STANDARD_INFORMATION fileStd = { 0 };

	if (ZwQueryInformationFile(Handle, &ioSB, &fileStd,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation) != STATUS_SUCCESS)
		return -1;

	fileSize = fileStd.EndOfFile.QuadPart;

	INT curPos = DoomTell(Handle);
	if (curPos < 0)
		return -1;

	if (SeekType == DOOM_SEEK_CUR)
		currOffset = curPos + Offset;
	if (SeekType == DOOM_SEEK_END)
		currOffset = fileSize - 1ull + Offset;

	FILE_POSITION_INFORMATION filePos = { 0 };
	filePos.CurrentByteOffset.QuadPart = currOffset;

	if (ZwSetInformationFile(Handle, &ioSB, &filePos,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation) != STATUS_SUCCESS)
		return -1;

	return 0;
}

VOID* DoomMalloc(SIZE_T size) {
	return AllocateUserMemory(size);
}

VOID DoomFree(VOID* Mem) {
	// genius
	return;
}

VOID DoomPrint(CHAR* String) {
	DbgPrint("[DOOM]: %s\n", String);
}

VOID DoomExit(INT code) {
	DbgPrint("[DOOM]: Exiting with code %d\n", code);
	Running = FALSE;
}

#define DRIVE_ROOT "X:\\"

char* DoomGetEnv(CHAR* Name) {
	if (!strcmp(Name, "HOME"))
		return DRIVE_ROOT;
	return NULL;
}

VOID DoomGetTime(INT* sec, INT* usec) {
	LARGE_INTEGER TimeSince1607 = { 0 };
	KeQuerySystemTimePrecise(&TimeSince1607);

	TIME_FIELDS TimeButInASaneFormat = { 0 };

	RtlTimeToTimeFields(&TimeSince1607, &TimeButInASaneFormat);

	*sec = TimeButInASaneFormat.Second;
	*usec = TimeButInASaneFormat.Milliseconds * 1000;
}

// Kill me
VOID DoomProcessKeys(NT_USER_GET_KEY_STATE Function) {
	NT_USER_GET_KEY_STATE NtUserGetKeyState = Function;
	if (NtUserGetKeyState(VK_RETURN) & 0x8000)
		doom_key_down(DOOM_KEY_ENTER);
	if (!(NtUserGetKeyState(VK_RETURN) & 0x8000))
		doom_key_up(DOOM_KEY_ENTER);

	if (NtUserGetKeyState(VK_LEFT) & 0x8000)
		doom_key_down(DOOM_KEY_LEFT_ARROW);
	if (!(NtUserGetKeyState(VK_LEFT) & 0x8000))
		doom_key_up(DOOM_KEY_LEFT_ARROW);

	if (NtUserGetKeyState(VK_RIGHT) & 0x8000)
		doom_key_down(DOOM_KEY_RIGHT_ARROW);
	if (!(NtUserGetKeyState(VK_RIGHT) & 0x8000))
		doom_key_up(DOOM_KEY_RIGHT_ARROW);

	if (NtUserGetKeyState(VK_UP) & 0x8000)
		doom_key_down(DOOM_KEY_UP_ARROW);
	if (!(NtUserGetKeyState(VK_UP) & 0x8000))
		doom_key_up(DOOM_KEY_UP_ARROW);

	if (NtUserGetKeyState(VK_DOWN) & 0x8000)
		doom_key_down(DOOM_KEY_DOWN_ARROW);
	if (!(NtUserGetKeyState(VK_DOWN) & 0x8000))
		doom_key_up(DOOM_KEY_DOWN_ARROW);

	if (NtUserGetKeyState(VK_SPACE) & 0x8000)
		doom_key_down(DOOM_KEY_SPACE);
	if (!(NtUserGetKeyState(VK_SPACE) & 0x8000))
		doom_key_up(DOOM_KEY_SPACE);

	if (NtUserGetKeyState(VK_CONTROL) & 0x8000)
		doom_key_down(DOOM_KEY_CTRL);
	if (!(NtUserGetKeyState(VK_CONTROL) & 0x8000))
		doom_key_up(DOOM_KEY_CTRL);

	if (NtUserGetKeyState(VK_ESCAPE) & 0x8000)
		doom_key_down(DOOM_KEY_ESCAPE);
	if (!(NtUserGetKeyState(VK_ESCAPE) & 0x8000))
		doom_key_up(DOOM_KEY_ESCAPE);

	if (NtUserGetKeyState('Y') & 0x8000)
		doom_key_down(DOOM_KEY_Y);
	if (!(NtUserGetKeyState('Y') & 0x8000))
		doom_key_up(DOOM_KEY_Y);
}

VOID
Win32kThreadApcRoutine(
	_In_ PRKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE *NormalRoutine,
	_Inout_ PVOID *NormalContext,
	_Inout_ PVOID *SystemArgument1,
	_Inout_ PVOID *SystemArgument2
	)
{
	PWIN32K_THREAD_CONTEXT Context = *SystemArgument1;
	PETHREAD Thread = KeGetCurrentThread();

	if (PsGetThreadWin32Thread(Thread) == NULL) {
		DoomPrint("[!] Current thread context does not have a Win32 thread\n");
		KeSetEvent(&Context->CompletedEvent, 0, FALSE);
		return;
	}

	HDC hdc = NtUserGetDc(0);
	HDC memHdc = NtGdiCreateCompatibleDc(hdc);

	while (Running && !PsIsThreadTerminating(Thread)) {
		doom_update();

		BYTE* framebuffer = doom_get_framebuffer(4);

		HBITMAP Result = NtGdiCreateBitmap(320, 200, 1, 32, framebuffer);

		HBITMAP Old = NtGdiSelectBitmap(memHdc, Result);

		NtGdiBitBlt(hdc, 0, 0, 300, 200, memHdc, 0, 0, SRCCOPY, 0, 0);

		DoomProcessKeys(NtUserGetKeyState);

		Sleep(33);
	}

	NtUserReleaseDc(memHdc);
	NtUserReleaseDc(hdc);

	KeSetEvent(&Context->CompletedEvent, 0, FALSE);
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("[*] Goodbye Cruel World\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath) {

	DbgPrint("[*] Hello World!\n");

	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	PVOID Win32kBase = GetModuleBase(L"Win32kbase.sys", DriverObject);
	PVOID Win32kFullBase = GetModuleBase(L"Win32kfull.sys", DriverObject);

	if (!Win32kBase || !Win32kFullBase) {
		DbgPrint("[!] Failed to get base of Win32k!!!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DbgPrint("[*] Got Win32k base at 0x%llx and Win32kfull at 0x%llx\n",
		Win32kBase, Win32kFullBase);


	PVOID Win32Process = 0;
	PVOID Win32Thread = 0;
	PETHREAD TargetThread = NULL;
	PEPROCESS TargetProcess = NULL;
	CLIENT_ID targetCid = { 0 };
	UNICODE_STRING TargetProcessName = RTL_CONSTANT_STRING(L"explorer.exe");

	NTSTATUS Status = OpenSessionProcessThread(&TargetProcess, &TargetThread, &TargetProcessName, 1,  &Win32Process, &Win32Thread, &targetCid);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("[!] Failed to get a thread from process \"%wZ\"\n", &TargetProcessName);
		return Status;
	}
	Status = PsAcquireProcessExitSynchronization(TargetProcess);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(TargetThread);
		ObDereferenceObject(TargetProcess);
		DbgPrint("[!] Failed to acquire rundown protection on process \"%wZ\"\n", &TargetProcessName);
		return Status;
	}

	DbgPrint("[*] TargetThread 0x%llX at 0x%p, thread 0x%llX at 0x%p\n",
		(ULONG_PTR)targetCid.UniqueProcess, TargetProcess,
		(ULONG_PTR)targetCid.UniqueThread, TargetThread);
	DbgPrint("[*] Win32Process = 0x%p\n", Win32Process);
	DbgPrint("[*] Win32Thread = 0x%p\n", Win32Thread);

	KAPC_STATE Apc = { 0 };
	KeStackAttachProcess(TargetProcess, &Apc);

	NtUserGetDc = RtlFindExportedRoutineByName(Win32kBase, "NtUserGetDC");
	NtGdiPatBlt =
		RtlFindExportedRoutineByName(Win32kFullBase, "NtGdiPatBlt");
	NtGdiSelectBrush =
		RtlFindExportedRoutineByName(Win32kBase, "GreSelectBrush");
	NtUserReleaseDc =
		RtlFindExportedRoutineByName(Win32kBase, "NtUserReleaseDC");
	NtGdiCreateSolidBrush =
		RtlFindExportedRoutineByName(Win32kFullBase, "NtGdiCreateSolidBrush");
	NtGdiDeleteObjectApp =
		RtlFindExportedRoutineByName(Win32kBase, "NtGdiDeleteObjectApp");
	NtGdiCreateBitmap =
		RtlFindExportedRoutineByName(Win32kFullBase, "NtGdiCreateBitmap");
	NtGdiSelectBitmap =
		RtlFindExportedRoutineByName(Win32kBase, "GreSelectBitmap");
	NtGdiCreateCompatibleDc =
		RtlFindExportedRoutineByName(Win32kBase, "GreCreateCompatibleDC");
	NtGdiBitBlt = RtlFindExportedRoutineByName(Win32kFullBase, "NtGdiBitBlt");
	NtUserGetKeyState =
		RtlFindExportedRoutineByName(Win32kBase, "NtUserGetKeyState");

	if (!NtUserGetDc || !NtGdiPatBlt || !NtGdiSelectBrush || !NtUserReleaseDc || !NtGdiCreateSolidBrush || !NtGdiDeleteObjectApp || !NtUserGetKeyState) {
		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(TargetThread);
		PsReleaseProcessExitSynchronization(TargetProcess);
		ObDereferenceObject(TargetProcess);
		DbgPrint("[!] Failed to get required function addresses !!\n");
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	doom_set_file_io(DoomOpen, DoomClose, DoomRead, NULL, DoomSeek, DoomTell,
		DoomEof);
	doom_set_malloc(DoomMalloc, DoomFree);
	doom_set_exit(DoomExit);
	doom_set_getenv(DoomGetEnv);
	doom_set_gettime(DoomGetTime);
	doom_set_print(DoomPrint);

	char* argv[] = { "doom", "-file", "\\??\\\\C:\\DOOM.WAD" };

	doom_init(3, argv, 0);

	// Queue user APC to run the game loop
	WIN32K_THREAD_CONTEXT Context;
	RtlZeroMemory(&Context, sizeof(Context));
	KeInitializeEvent(&Context.CompletedEvent, NotificationEvent, FALSE);
	KeInitializeApc(&Context.Apc,
					TargetThread,
					OriginalApcEnvironment,
					Win32kThreadApcRoutine,
					NULL,
					NULL,
					UserMode,
					NULL);

	BOOLEAN Inserted = KeInsertQueueApc(&Context.Apc,
						&Context,
						NULL,
						2);
	ObDereferenceObject(TargetThread);
	if (Inserted) {
		Status = KeWaitForSingleObject(&Context.CompletedEvent,
										Executive,
										KernelMode,
										FALSE,
										NULL);
	} else {
		Status = STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&Apc);

	if (TargetProcess != NULL) {
		PsReleaseProcessExitSynchronization(TargetProcess);
		ObDereferenceObject(TargetProcess);
	}

	return STATUS_SUCCESS;
}

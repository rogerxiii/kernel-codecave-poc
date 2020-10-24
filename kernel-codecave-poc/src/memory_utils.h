#pragma once

#include <ntifs.h>

#include "nt_defines.h"

typedef unsigned long long QWORD;

//define credits: learn_more
#define INRANGE(x,a,b)  (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

static QWORD find_pattern_nt(_In_ CONST CHAR* sig, _In_ QWORD start, _In_ QWORD size)
{
	QWORD match = 0;
	const char* pat = sig;

	for (QWORD cur = start; cur < (start + size); ++cur)
	{
		if (!*pat) return match;

		else if (*(BYTE*)pat == '\?' || *(BYTE*)cur == getByte(pat))
		{
			if (!match) match = cur;

			if (!pat[2]) return match;

			else if (*(WORD*)pat == '\?\?' || *(BYTE*)pat != '\?') pat += 3;
			else pat += 2;
		}

		else
		{
			pat = sig;
			match = 0;
		}
	}

	return 0;
}

static BOOLEAN is_retop(_In_ BYTE op)
{
	return op == 0xC2 ||   // RETN + POP
		op == 0xC3 ||      // RETN
		op == 0xCA ||      // RETF + POP
		op == 0xCB;        // RETF
}

/*
	Finds a suitable length code cave inside the .text section of the given module
	A valid code cave is a sequence of CC bytes prefixed by a return statement
*/
static QWORD find_codecave(_In_ VOID* module, _In_ INT length, _In_opt_ QWORD begin)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
	
	QWORD start = 0, size = 0;

	QWORD header_offset = (QWORD)IMAGE_FIRST_SECTION(nt_headers);
	for (INT x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
	{
		IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

		if (strcmp((CHAR*)header->Name, ".text") == 0)
		{
			start = (QWORD)module + header->PointerToRawData;
			size = header->SizeOfRawData;
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	QWORD match = 0;
	INT curlength = 0;
	BOOLEAN ret = FALSE;

	for (QWORD cur = (begin ? begin : start); cur < start + size; ++cur)
	{
		if (!ret && is_retop(*(BYTE*)cur)) ret = TRUE;
		else if (ret && *(BYTE*)cur == 0xCC)
		{
			if (!match) match = cur;
			if (++curlength == length) return match;
		}

		else
		{
			match = curlength = 0;
			ret = FALSE;
		}
	}

	return 0;
}

/*
	Remaps the page where the target address is in with PAGE_EXECUTE_READWRITE protection and patches in the given bytes
	If this is the restore routine, then after patching in the bytes the protection is set back to PAGE_READONLY
*/
static BOOLEAN remap_page(_In_ VOID* address, _In_ BYTE* asm, _In_ ULONG length, _In_ BOOLEAN restore)
{
	MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
	if (!mdl)
	{
		DbgPrint("[-] Failed allocating MDL!\n");
		return FALSE;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (!map_address)
	{
		DbgPrint("[-] Failed mapping the page!\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (status)
	{
		DbgPrint("[-] Failed MmProtectMdlSystemAddress with status: 0x%lX\n", status);
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	RtlCopyMemory(map_address, asm, length);

	if (restore)
	{
		status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
		if (status)
		{
			DbgPrint("[-] Failed second MmProtectMdlSystemAddress with status: 0x%lX\n", status);
			MmUnmapLockedPages(map_address, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return FALSE;
		}
	}

	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

static BOOLEAN patch_codecave_detour(_In_ QWORD address, _In_ QWORD target)
{
	BYTE asm[16] = {
		0x50,                                                        // push rax
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
		0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
		0xC3                                                         // retn
	};
	*(QWORD*)(asm + 3) = target;

	return remap_page((VOID*)address, asm, 16, FALSE);
}

static BOOLEAN restore_codecave_detour(_In_ QWORD address)
{
	BYTE asm[16] = {
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
	};

	return remap_page((VOID*)address, asm, 16, TRUE);
}

static VOID to_lower(_In_ CHAR* in, _Out_ CHAR* out)
{
	INT i = -1;
	while (in[++i] != '\x00') out[i] = (CHAR)tolower(in[i]);
}

static BOOLEAN is_pg_protected(_In_ CONST CHAR* image)
{
	static const INT count = 8;
	static const char* images[] = { "win32kbase.sys", "tm.sys", "clfs.sys", "msrpc.sys", "ndis.sys", "ntfs.sys", "tcpip.sys", "fltmgr.sys" };

	for (INT i = 0; i < count; ++i) if (strstr(images[i], image)) return TRUE;
	return FALSE;
}
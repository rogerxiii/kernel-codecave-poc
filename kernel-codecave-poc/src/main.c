#include "memory_utils.h"

#define SystemModuleInformation 0x0B
__kernel_entry NTSTATUS ZwQuerySystemInformation(IN ULONG SystemInformationClass, OUT VOID* SystemInformation, IN ULONG SystemInformationLength, OUT ULONG* ReturnLength);

typedef LDR_DATA_TABLE_ENTRY*(*MiLookupDataTableEntry_fn)(IN VOID* Address, IN BOOLEAN);
MiLookupDataTableEntry_fn MiLookupDataTableEntry;

QWORD g_callback_address = 0, g_thread_address = 0;



/*
	The (detoured) CreateProcess callback will enter here
	Note that the accompanying shellcode cannot be removed, as it still gets called regularly
*/
VOID create_process_callback(_In_ KPROCESS* process, _In_ HANDLE process_id, _In_ PS_CREATE_NOTIFY_INFO* create_info)
{
	UNREFERENCED_PARAMETER(process_id);
	UNREFERENCED_PARAMETER(create_info);

	EPROCESS* proc = (EPROCESS*)process;
	DbgPrint("[+] [callback] Process created: %s\n", proc->ImageFileName);
}

/*
	The (detoured) main thread will enter here, this can be looped infinitely without worry
	As soon as the thread gets created the shellcode and the page protection are restored to hide any traces
*/
VOID main_thread()
{
	DbgPrint("[+] Inside main thread\n");

	if (!restore_codecave_detour(g_thread_address)) DbgPrint("[-] Failed restoring thread code cave!\n");
	else DbgPrint("[+] Restored thread code cave");

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_callback_address, FALSE);
	if (status) DbgPrint("[-] Failed PsSetCreateProcessNotifyRoutineEx with status: 0x%lX\n", status);
	else DbgPrint("[+] Registered CreateProcess notify routine\n");
}

VOID* get_module_list()
{
	// We call the function once to get a rough estimate of the size of the structure, then we add a few kb
	ULONG length = 0;
	ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
	length += (10 * 1024);

	VOID* module_list = ExAllocatePool(PagedPool | POOL_COLD_ALLOCATION, length);
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length);

	if (status)
	{
		DbgPrint("[-] Failed ZwQuerySystemInformation with 0x%lX\n", status);
		if (module_list) ExFreePool(module_list);
		return 0;
	}

	if (!module_list)
	{
		DbgPrint("[-] Module list is empty\n");
		return 0;
	}

	return module_list;
}

BOOLEAN apply_codecaves()
{
	VOID* module_list = get_module_list();
	if (!module_list) return FALSE;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;
	
	/*
		We need to find 2 16 byte codecaves, preferably in the same module:
		g_callback_address will be the detour to the CreateProcess callback
		g_thread_address will be the detour for our main thread
	*/
	for (ULONG i = 1; i < modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];

		CHAR driver_name[0x0100] = { 0 };
		to_lower(module->FullPathName, driver_name);
		if (!strstr(driver_name, ".sys") || strstr(driver_name, "win32kbase")) continue;

		g_callback_address = find_codecave(module->ImageBase, 16, 0);
		if (!g_callback_address) continue;

		g_thread_address = find_codecave(module->ImageBase, 16, g_callback_address + 16);
		if (!g_thread_address)
		{
			g_callback_address = 0;
			continue;
		}

		LDR_DATA_TABLE_ENTRY* ldr = MiLookupDataTableEntry((VOID*)g_callback_address, FALSE);
		if (!ldr)
		{
			g_callback_address = g_thread_address = 0;
			continue;
		}

		// Setting the 0x20 data table entry flag makes MmVerifyCallbackFunction pass
		ldr->Flags |= 0x20;
		DbgPrint("[+] Found places for both code caves in module %s\n", driver_name + module->OffsetToFileName);

		break;
	}

	ExFreePool(module_list);

	/*
		Instead of just stopping we could loosen our restrictions and search for 2 code caves in separate modules
		But in practice, 16 byte code caves are quite common, so this shouldn't really happen
	*/
	if (!g_callback_address || !g_thread_address)
	{
		DbgPrint("[-] Failed to find all required code caves in any driver module!\n");
		return FALSE;
	}

	if (!patch_codecave_detour(g_callback_address, (QWORD)&create_process_callback))
	{
		DbgPrint("[-] Failed patching in create_process_callback redirection code cave!\n");
		return FALSE;
	}

	if (!patch_codecave_detour(g_thread_address, (QWORD)&main_thread))
	{
		DbgPrint("[-] Failed patching in main_thread redirection code cave!\n");
		return FALSE;
	}

	DbgPrint("[+] Patched in both code caves succesfully\n");

	HANDLE thread;
	NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, 0, 0, 0, (KSTART_ROUTINE*)g_thread_address, 0);
	if (status) DbgPrint("[-] PsCreateSystemThread failed, status = 0x%08X\n", status);
	else DbgPrint("[+] Created a system thread in target space\n");

	return TRUE;
}

// Custom entry point, don't create a driver object here because that would just add another detection vector
NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	VOID* module_list = get_module_list();
	if (!module_list) return STATUS_UNSUCCESSFUL;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;

	// First module is always ntoskrnl.exe
	RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[0];

	QWORD address = find_pattern_nt("48 8B C4 48 89 58 08 48 89 70 18 57 48 83 EC 20 33 F6", (QWORD)module->ImageBase, module->ImageSize);
	if (!address) 
	{
		DbgPrint("[-] Could not find MiLookupDataTableEntry\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[+] Found MiLookupDataTableEntry at 0x%p\n", (VOID*)address);
	MiLookupDataTableEntry = (MiLookupDataTableEntry_fn)address;

	ExFreePool(module_list);
	if (!apply_codecaves()) DbgPrint("[-] Failed applying code caves\n");

	return STATUS_UNSUCCESSFUL;
}
#include "memory_utils.h"



#define ignore_param(p) p // Use unreferenced parameter to suppress warnings
#define SystemModuleInformation 0x0B

__kernel_entry NTSTATUS ZwQuerySystemInformation(IN ULONG SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);

typedef PLDR_DATA_TABLE_ENTRY(*MiLookupDataTableEntry_fn)(IN PVOID Address, IN BOOLEAN);
MiLookupDataTableEntry_fn MiLookupDataTableEntry;



void create_process_callback(_In_ PEPROCESS process, _In_ HANDLE process_id, _In_ PPS_CREATE_NOTIFY_INFO create_info)
{
	ignore_param(process_id);
	ignore_param(create_info);

	EPROCESS* proc = (EPROCESS*)process;
	DbgPrint("[+] [callback] Process created: %s\n", proc->ImageFileName);
}

QWORD g_callback_address = 0;
void main_thread()
{
	DbgPrint("[+] Inside main_thread\n");

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)g_callback_address, FALSE);
	if (status) DbgPrint("[-] Failed PsSetCreateProcessNotifyRoutineEx with status: 0x%lX\n", status);
	else DbgPrint("[+] Registered CreateProcess notify routine\n");
}

void* get_module_list()
{
	// We call the function once to get a rough estimate of the size of the structure, then we add a few kb
	ULONG length = 0;
	ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
	length += (10 * 1024);

	void* module_list = ExAllocatePool(PagedPool | POOL_COLD_ALLOCATION, length);
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

NTSTATUS apply_codecaves()
{
	void* module_list = get_module_list();
	if (!module_list) return STATUS_UNSUCCESSFUL;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;
	
	/*
		We need to find 2 16 byte codecaves:
		address will be the detour to the CreateProcess callback and we store this in g_callback_address
		address2 will be the detour for our main thread
	*/
	QWORD address = 0, address2 = 0;

	for (long i = 1; i < (long)modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];

		char driver_name[0x0100] = { 0 };
		to_lower(module->FullPathName, driver_name);
		if (!strstr(driver_name, ".sys") || strstr(driver_name, "win32kbase")) continue;

		address = find_codecave(module->ImageBase, 16, 0);
		if (!address) continue;

		address2 = find_codecave(module->ImageBase, 16, 0);
		if (address2 == address) address2 = find_codecave(module->ImageBase, 16, address + 16);
		if (!address)
		{
			address = 0;
			continue;
		}

		LDR_DATA_TABLE_ENTRY* ldr = MiLookupDataTableEntry((void*)address, FALSE);
		if (!ldr)
		{
			address = address2 = 0;
			continue;
		}

		// Setting the 0x20 data table entry flag makes MmVerifyCallbackFunction pass
		ldr->Flags |= 0x20;
		DbgPrint("[+] Found places for both code caves in module %s\n", driver_name + module->OffsetToFileName);

		break;
	}

	ExFreePool(module_list);

	if (!address || !address2)
	{
		DbgPrint("[-] Failed to find all required code caves in any driver module!\n");
		return STATUS_UNSUCCESSFUL;
	}

	g_callback_address = address;
	if (patch_codecave_detour(address, (QWORD)&create_process_callback))
	{
		DbgPrint("[-] Failed patching in create_process_callback redirection code cave!\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (patch_codecave_detour(address2, (QWORD)&main_thread))
	{
		DbgPrint("[-] Failed patching in main_thread redirection code cave!\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("[+] Patched in both code caves succesfully\n");

	HANDLE thread;
	NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, 0, 0, 0, (PKSTART_ROUTINE)address2, 0);
	if (status) DbgPrint("[-] PsCreateSystemThread failed, status = 0x%08X\n", status);
	else DbgPrint("[+] Created a system thread in target space\n");

	return STATUS_SUCCESS;
}

// Custom entry point, we don't create a driver object here because that would just add another detection vector
NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
	ignore_param(driver_object);
	ignore_param(registry_path);

	void* module_list = get_module_list();
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
	DbgPrint("[+] Found MiLookupDataTableEntry at 0x%p\n", (void*)address);
	MiLookupDataTableEntry = (MiLookupDataTableEntry_fn)address;

	ExFreePool(module_list);
	if (apply_codecaves()) DbgPrint("[-] Failed applying code caves\n");

	return STATUS_UNSUCCESSFUL;
}
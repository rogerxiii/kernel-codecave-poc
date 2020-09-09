## Kernel code cave PoC
When using a manual mapped driver, there are some limitations and detection vectors you will have to deal with. This proof of concept deals with 2 of them: having a thread which has a base address not in a valid module and registering notify routines where the callback is not in a valid module, thus triggering PatchGuard.  
  
Note that this has only been tested on *Windows 10 version 2004 build 19041.450,* you might need different structures for earlier/later versions.

## Method
We search for code caves in the .text section of valid driver modules, then we patch in a jump back to our manual mapped code.  
We specifically search for CC bytes instead of simply 00 and 90, to make sure that the target module will not use the memory at a later point.  
  
In this PoC a thread is created and *PsSetCreateProcessNotifyRoutineEx* is called to register a callback.  
One extra thing to note is that we also have to bypass the *MmVerifyCallbackFunction* check, which we do by directly changing the data table entry flags corresponding to the memory region.  
  
For more information, see this thread:
https://www.unknowncheats.me/forum/xxxxxxxxxxxx
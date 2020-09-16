## Kernel code cave PoC
When using a manual mapped driver, there are some limitations and detection vectors you will have to deal with. This proof of concept deals with 2 of them:  
Having a thread which has a base address not in a valid module and registering notify routines where the callback is not in a valid module, which can trigger *PatchGuard*, depending on which routine.  
  
Note that this has only been tested on *Windows 10 version 2004 build 19041.450,* you might need different structures for earlier/later versions.
  
## How it works
We search for code caves in the .text section of valid driver modules, then we patch in a jump back to our manual mapped code.  
We specifically search for CC bytes instead of simply 00 or 90, to make sure that the target module will not use the memory at a later point.  
One more criteria for a valid code cave is that the sequence of CC bytes is prefixed by a return opcode.  
  
In this proof of concept a thread is created and *PsSetCreateProcessNotifyRoutineEx* is called to register a callback.  
One extra thing to note is that we also have to bypass the *MmVerifyCallbackFunction* check, which we do by directly changing the data table entry flags corresponding to the memory region.  
  
After the thread has been created, the shellcode is immediately restored to prevent any integrity checks from catching the modifications.  
Obviously, this won't work for the notify callback shellcode as this still gets executed regularly.  
  
For more information, see this thread:  
https://www.unknowncheats.me/forum/c-and-c-/415662-kernel-code-cave-poc.html
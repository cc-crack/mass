# Inject tracer issue
## Background

If you have read all of the ```*****``` code you will note that the most of logs are produced by the tracer. If you are going deep into how *****.dll injected there are many gaps in that process.
In your test maybe you have found that sometimes tracer's logs were missing like ```*****-***``` or the behaviors on the x64 platform were so weird because of there are a lot of codes for the trade-off in an asynchrony process.


## Inject tracer form kernel.

The good news is we have a kernel module called ```*****```, it will help to inject the tracer into target process at a perfect moment in less code.

It is an old APC trick. Basically, we insert an APC during the process creation, and the APC routine will be executed while some sys-call return to ring3 and load ```*****.dll```.

It sounds cool, doesn't it? It is very simply and clearly approach to inject code. But there are some things worthy to note.

At first, you should know the precision context of the APC routine executed and what happened while CreateProcessW(CREATE_SUSPENDED) called.

Actually, CreateProcessW has two steps to create a process. It will call NtCreateProcessEx first basically it means "fork".

It falls into the kernel via NtCreateProcessEx, if everything goes well the object manager will create an initialed  ```EPROCESS``` object, prepare target process memory space and PSNotifyRoutine will be called.
In step two, the main thread of target process will be created via NtCreateThread. 

Similarly, ```NtCreateThread``` in kernel responds to initial thread data struct, after that for user thread a user mode APC which routine is ```PspSystemDll.LoaderInitRoutine``` will be inserted.

It will be back to ring3, EIP equal to ```LdrInitializeThunk```.

In ```LdrInitializeThunk``` all of the dependencies will be loaded(```LdrpInitialize```). Target process image will be loaded and ntdll, kernel32..., you can observe them in LoadImageNotifyRoutine one by one. 

If you observer it in a kernel debugger you can see that they are all in ZwMapViewOfSection's call stack. 

When ```LdrpInitialize``` has done, ```ZwContinue``` will be called to set EIP to ```RtlUserThreadStart``` and going into kernel and second time backing to ring3, stopping at ```RtlUserThreadStart```.

For now ```CreateProcessW(CREATE_SUSPENDED)```done.

In this process there have many special situations, for WOW64 the second back to ring3 will stop at ```ntdll!RtlUserThreadStart```. 

You can see the WOW64 system has been initialed complete, wow64.dll, wow64cpu.dll, wow64win.dll, syswow64\ntdll.dll have to be loaded but no more dependency module.

After a glance at the whole process now we must choose the right context to insert our loader code.

First, neither ```PSNotifyRoutine``` or ```ThreadNotify``` is a good choice, target process is empty and you can not call any API.

So we can insert the APC in ```LoadImageNotifyRoutine```. Because of ```*****.dll``` has so many dependencies, the best injecting moment should be after kernel32.dll loaded.

And the call stack usually looks like this:
```
 ntdll!ZwMapViewOfSection+0x14
 ntdll!LdrpMapViewOfSection+0xb5
 ntdll!LdrpMapImage+0x72
 ntdll!LdrpMapDllWithSectionHandle+0x2d
 ntdll!LdrpLoadKnownDll+0xe6
 ntdll!LdrpFindOrPrepareLoadingModule+0xa6
 ntdll!LdrpLoadDllInternal+0x110
 ntdll!LdrpLoadDll+0xf1
 ntdll!LdrLoadDll+0x8c
 ntdll!LdrpInitializeProcess+0x1669
 ntdll!_LdrpInitialize+0x4e934
 ntdll!LdrInitializeThunk+0xe
```
As you see here is NTDLL's loader. This is the most mystical part...

We can't directly call ```LoadLibrary(*****.dll)``` here, in the loader stage there are so many taboos and rule and the rule number 0 is that you can not call ```LoadLibrary``` here...


Target DLL's DllMain will execute some un-except functions here if a related module has not been initialized that will raise an exception without handling. And in older NT system like XP, there have many lock issues.

That's why the M$ remark that it is not safe to call LoadLibrary in DllMain, actually that depends on how the DLL implemented.

[More informations](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682583(v=vs.85).aspx)

So we run a shellcode in APC routine to hook ZwContinue since ```LdrpInitialize``` will call ```Zwcontinue``` back to the kernel.

When ```LdrpInitialize``` has been done we get an opportunity to load ```*****.dll``` in a clearly and safely context.

## Known issue

Unless we have a strict tracer that it can be loaded in first APC routine, we will miss the behaviors of DllMain of target process static imports DLL.
TLS should be another issue.

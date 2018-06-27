32->
	XP->

ntdll!KiUserApcDispatcher:
001b:7c90e450 8d7c2410        lea     edi,[esp+10h]
001b:7c90e454 58              pop     eax
001b:7c90e455 ffd0            call    eax// FIRST RETURN IS LdrInitializeThunk and second return
001b:7c90e457 6a01            push    1
001b:7c90e459 57              push    edi
001b:7c90e45a e8ffebffff      call    ntdll!ZwContinue (7c90d05e) //EIP == Kernel32!BaseProcessStartThunk (NOT EXPORT FUNCTION)
001b:7c90e45f 90              nop

		LdrInitializeThunk:
ntdll!LdrInitializeThunk:
7c901166 8d442410        lea     eax,[esp+10h]
7c90116a 89442404        mov     dword ptr [esp+4],eax
7c90116e 33ed            xor     ebp,ebp
7c901170 e9da870100      jmp     ntdll!LdrpInitialize (7c91994f)
7c901175 90              nop


		ZwContinue:
ntdll!ZwContinue:
7c90d05e b820000000      mov     eax,20h
7c90d063 ba0003fe7f      mov     edx,offset SharedUserData!SystemCallStub (7ffe0300)
7c90d068 ff12            call    dword ptr [edx]
7c90d06a c20800          ret     8
7c90d06d 90              nop

	WIN7->
		LdrInitializeThunk:
ntdll!LdrInitializeThunk:
001b:77dc3649 8bff            mov     edi,edi
001b:77dc364b 55              push    ebp
001b:77dc364c 8bec            mov     ebp,esp
001b:77dc364e ff750c          push    dword ptr [ebp+0Ch]
001b:77dc3651 ff7508          push    dword ptr [ebp+8]
001b:77dc3654 e816000000      call    ntdll!LdrpInitialize (77dc366f)
001b:77dc3659 6a01            push    1
001b:77dc365b ff7508          push    dword ptr [ebp+8]
001b:77dc365e e8451ffeff      call    ntdll!ZwContinue (77da55a8) // EIP == RtlUserThreadStart
001b:77dc3663 50              push    eax
001b:77dc3664 e8dc3afeff      call    ntdll!RtlRaiseStatus (77da7145)
001b:77dc3669 cc              int     3
001b:77dc366a 90              nop
001b:77dc366b 90              nop
001b:77dc366c 90              nop
001b:77dc366d 90              nop
001b:77dc366e 90              nop

		ZwContinue:
ntdll!ZwContinue:
001b:77da55a8 b83c000000      mov     eax,3Ch
001b:77da55ad ba0003fe7f      mov     edx,offset SharedUserData!SystemCallStub (7ffe0300)
001b:77da55b2 ff12            call    dword ptr [edx]
001b:77da55b4 c20800          ret     8
001b:77da55b7 90              nop

	WIN8->
		LdrInitializeThunk:
		ZwContinue:
	WIN81->
		LdrInitializeThunk:
		ZwContinue:
	WIN10->
		LdrInitializeThunk:
ntdll!LdrInitializeThunk:
001b:77d0fe20 8bff            mov     edi,edi
001b:77d0fe22 55              push    ebp
001b:77d0fe23 8bec            mov     ebp,esp
001b:77d0fe25 8b550c          mov     edx,dword ptr [ebp+0Ch]
001b:77d0fe28 8b4d08          mov     ecx,dword ptr [ebp+8]
001b:77d0fe2b e816000000      call    ntdll!LdrpInitialize (77d0fe46)
001b:77d0fe30 6a01            push    1
001b:77d0fe32 ff7508          push    dword ptr [ebp+8]
001b:77d0fe35 e8f60c0200      call    ntdll!NtContinue (77d30b30) //EIP == 
001b:77d0fe3a 50              push    eax
001b:77d0fe3b e8b0410300      call    ntdll!RtlRaiseStatus (77d43ff0)
001b:77d0fe40 cc              int     3
001b:77d0fe41 cc              int     3
001b:77d0fe42 cc              int     3
001b:77d0fe43 cc              int     3
001b:77d0fe44 cc              int     3
001b:77d0fe45 cc              int     3
		ZwContinue:
ntdll!NtContinue:
77d30b30 b878010000      mov     eax,178h
77d30b35 e803000000      call    ntdll!ZwContinue+0xd (77d30b3d)
77d30b3a c20800          ret     8
77d30b3d 8bd4            mov     edx,esp
77d30b3f 0f34            sysenter
77d30b41 c3              ret

	
WOW64->
	XP->
		LdrInitializeThunk:
		ZwContinue:
	WIN7->
		LdrInitializeThunk:
		ZwContinue:
	WIN8->
		LdrInitializeThunk:
		ZwContinue:
	WIN81->
		LdrInitializeThunk:
                              ; Exported entry 140. LdrInitializeThunk


                              ; Attributes: noreturn bp-based frame

                              ; int __cdecl LdrInitializeThunk(PCONTEXT Context, int)
                              public LdrInitializeThunk
                              LdrInitializeThunk proc near

                              Context= dword ptr  8
                              arg_4= dword ptr  0Ch

8B FF                         mov     edi, edi
55                            push    ebp
8B EC                         mov     ebp, esp
8B 55 0C                      mov     edx, [ebp+arg_4]
8B 4D 08                      mov     ecx, [ebp+Context]
E8 A1 02 00 00                call    sub_6B2C9847
6A 01                         push    1               ; TestAlert
FF 75 08                      push    [ebp+Context]   ; Context
E8 70 2A FF FF                call    ZwContinue
50                            push    eax             ; Status
E8 F6 48 FF FF                call    RtlRaiseStatus
CC                            int     3               ; Trap to Debugger
                              LdrInitializeThunk endp
		ZwContinue:
                              ; Exported entry 261. NtContinue
                              ; Exported entry 1638. ZwContinue



                              ; NTSTATUS __stdcall ZwContinue(PCONTEXT Context, BOOLEAN TestAlert)
                              public ZwContinue
                              ZwContinue proc near

                              Context= dword ptr  4
                              TestAlert= byte ptr  8

B8 42 00 00 00                mov     eax, 42h        ; NtContinue
64 FF 15 C0 00 00 00          call    large dword ptr fs:0C0h
C2 08 00                      retn    8
                              ZwContinue endp

	WIN10->
		LdrInitializeThunk:
.text:4B2E7580                               ; Exported entry 139. LdrInitializeThunk
.text:4B2E7580
.text:4B2E7580                               ; __stdcall LdrInitializeThunk(x, x)
.text:4B2E7580                                               public _LdrInitializeThunk@8
.text:4B2E7580                               _LdrInitializeThunk@8:                  ; DATA XREF: .text:off_4B3798A8o
.text:4B2E7580 8B FF                                         mov     edi, edi
.text:4B2E7582 55                                            push    ebp
.text:4B2E7583 8B EC                                         mov     ebp, esp
.text:4B2E7585 8B 55 0C                                      mov     edx, [ebp+0Ch]
.text:4B2E7588 8B 4D 08                                      mov     ecx, [ebp+8]
.text:4B2E758B E8 16 00 00 00                                call    _LdrpInitialize@8 ; LdrpInitialize(x,x)
.text:4B2E7590 6A 01                                         push    1
.text:4B2E7592 FF 75 08                                      push    dword ptr [ebp+8]
.text:4B2E7595 E8 66 74 00 00                                call    _ZwContinue@8   ; ZwContinue(x,x)
.text:4B2E759A 50                                            push    eax
.text:4B2E759B E8 C0 B9 01 00                                call    _RtlRaiseStatus@4 ; RtlRaiseStatus(x)
.text:4B2E759B                               ; ---------------------------------------------------------------------------
.text:4B2E75A0 CC CC CC CC CC CC                             db 6 dup(0CCh)

		ZwContinue:
.text:4B2EEA00                               ; NTSTATUS __stdcall ZwContinue(PCONTEXT Context, BOOLEAN TestAlert)
.text:4B2EEA00                                               public _ZwContinue@8
.text:4B2EEA00                               _ZwContinue@8   proc near               ; CODE XREF: RtlUnwind(x,x,x,x)+10Bp
.text:4B2EEA00                                                                       ; .text:4B2E7595p ...
.text:4B2EEA00
.text:4B2EEA00                               Context         = dword ptr  4
.text:4B2EEA00                               TestAlert       = byte ptr  8
.text:4B2EEA00
.text:4B2EEA00 B8 43 00 00 00                                mov     eax, 43h        ; NtContinue
.text:4B2EEA05 BA F0 2C 30 4B                                mov     edx, offset _Wow64SystemServiceCall@0 ; Wow64SystemServiceCall()
.text:4B2EEA0A FF D2                                         call    edx ; Wow64SystemServiceCall() ; Wow64SystemServiceCall()
.text:4B2EEA0C C2 08 00                                      retn    8
.text:4B2EEA0C                               _ZwContinue@8   endp

X64->
	XP->
		LdrInitializeThunk:
		ZwContinue:
	WIN7->
		LdrInitializeThunk:
		ZwContinue:
	WIN8->
		LdrInitializeThunk:
		ZwContinue:
	WIN81->
		LdrInitializeThunk:
		ZwContinue:

	WIN10->
		LdrInitializeThunk:
				LdrInitializeThunk                                                      ; Exported entry 135. LdrInitializeThunk
LdrInitializeThunk
LdrInitializeThunk
LdrInitializeThunk
LdrInitializeThunk                                                      public LdrInitializeThunk
LdrInitializeThunk                                                      LdrInitializeThunk proc near
LdrInitializeThunk      40 53                                           push    rbx
LdrInitializeThunk+2    48 83 EC 20                                     sub     rsp, 20h
LdrInitializeThunk+6    48 8B D9                                        mov     rbx, rcx
LdrInitializeThunk+9    E8 1A 00 00 00                                  call    LdrpInitialize
LdrInitializeThunk+E    B2 01                                           mov     dl, 1
LdrInitializeThunk+10   48 8B CB                                        mov     rcx, rbx
LdrInitializeThunk+13   E8 68 C9 02 00                                  call    ZwContinue	//EIP == RtlUserThreadStart
LdrInitializeThunk+18   8B C8                                           mov     ecx, eax
LdrInitializeThunk+1A   E8 C1 BA 02 00                                  call    RtlRaiseStatus


		ZwContinue:

ZwContinue      ; Exported entry 259. NtContinue
ZwContinue      ; Exported entry 1723. ZwContinue
ZwContinue
ZwContinue      ; =============== S U B R O U T I N E =======================================
ZwContinue
ZwContinue
ZwContinue                      public ZwContinue
ZwContinue      ZwContinue      proc near               ; CODE XREF: LdrInitializeThunk+13p
ZwContinue                                              ; KiUserApcDispatcher+33p ...
ZwContinue                      mov     r10, rcx        ; NtContinue
ZwContinue+3                    mov     eax, 43h
ZwContinue+8                    test    byte ptr ds:7FFE0308h, 1
ZwContinue+10                   jnz     short loc_1800A6935
ZwContinue+12                   syscall
ZwContinue+14                   retn
ZwContinue+15   ; ---------------------------------------------------------------------------
ZwContinue+15
ZwContinue+15   loc_1800A6935:                          ; CODE XREF: ZwContinue+10j
ZwContinue+15                   int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
ZwContinue+15                                           ; DS:SI -> counted CR-terminated command string
ZwContinue+17                   retn
ZwContinue+17   ZwContinue      endp
ZwContinue+17

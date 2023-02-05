.code
extern CalledHookTimes:dq
extern CheckCallCtx:PROC
extern ExceptionHandler:PROC
extern FindExceptionRecord:PROC
extern KeBugCheck:PROC
extern BpMe:PROC
extern OldHalQueryCounter:dq

HalpTscQueryCounterOrdered PROC

	rdtscp
	shl      rdx, 20h
	or       rax, rdx
	ret
HalpTscQueryCounterOrdered ENDP;

;r13 = exception context
HookPosition PROC

	push rcx
	push rdx
    sub rsp,0E8h  

    lea rax, CalledHookTimes
    lock inc qword ptr [rax]
       
	call CheckCallCtx
	cmp rax,1
	jne filt
    
    ;to do clear KiFreezeFlag
    ;fix: not neccessary to clear since no other function use it

    ;is an exception
	call FindExceptionRecord
    cmp rax,0
    je dbgbreak

	mov rcx, rax
	mov rdx, r13
	call ExceptionHandler
    
    ; still here so it's a debug break or something

dbgbreak:
    mov rcx,0DEADC0DEh
    call BpMe
filt:
    add rsp, 0E8h  
	pop rdx
	pop rcx
	;jmp HalpTscQueryCounterOrdered

    jmp [OldHalQueryCounter]

HookPosition ENDP

CalloutReturn proc
    ;push stack segment selector
    mov eax, ss
    push rax

    ;push stack pointer
    mov rax, [rcx + 0]
    push rax

    ;push arithmetic/system flags   rflags
    mov rax, [rcx + 78h]    
    ;xor rax, 200h ; enable interrupts
    push rax

    ;push code segment selector
    mov eax, cs
    push rax

    ;push instruction pointer
    mov rax, [rcx + 8]
    push rax

    ;set arguments

    mov rdx, [rcx + 18h]
    mov r8,  [rcx + 20h]
    mov r9,  [rcx + 28h]
    mov rax, [rcx + 30h]

    mov r12, [rcx + 38h]
    mov r13, [rcx + 40h]
    mov r14, [rcx + 48h]
    mov r15, [rcx + 50h]
    mov rdi, [rcx + 58h]
    mov rsi, [rcx + 60h]
    mov rbx, [rcx + 68h]
    mov rbp, [rcx + 70h]

    mov rcx, [rcx + 10h]

    ;clear trace
    xor rax, rax

    ;goto code
    iretq
CalloutReturn endp

GetR12 proc
    mov rax,r12
    ret
GetR12 endp

SetR12 proc
    mov r12,rcx
    ret
SetR12 endp

GetR13 proc
    mov rax,r13
    ret
GetR13 endp

SetR13 proc
    mov r13,rcx
    ret
SetR13 endp

end
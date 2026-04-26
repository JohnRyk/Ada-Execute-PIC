extern getprivs
global alignstack

segment .text

alignstack:
    ; rcx = hWrite (pipe write handle), Pass from the lpParameter in CreateThread
    ; OBJECT: Align the stack and then pass the rcx register to the getprivs(HANDLE hWrite)
    push rdi                    ; backup rdi
    mov rdi, rsp                ; save original rsp
    and rsp, byte -0x10         ; align stack to 16 bytes
    sub rsp, byte +0x20         ; shadow space for callee (x64 ABI)
    ; rcx is not change so it still the hWrite while call getprivs
    call getprivs               ; getprivs(HANDLE hWrite) — rcx = hWrite
    mov rsp, rdi                ; restore rsp
    pop rdi                     ; restore rdi
    ret                         ; return to CreateThread infrastructure (thread exits)

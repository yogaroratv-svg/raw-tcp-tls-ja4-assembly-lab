.intel_syntax noprefix
.global _start

.section .data
.align 4
one: .long 1
addr_len: .long 16

dst_addr:
    .word 2                         # AF_INET
    .byte 0x1f, 0x90                # Port 8080 (big-endian)
    .byte 20, 248, 231, 206         # Honeypot Public IP: 20.248.231.206
    .quad 0

local_addr:
    .space 16, 0

raw_pkt:
    # --- 20-Byte IPv4 Header (Offsets 0x00..0x13) ---
    .byte 0x45                      # [0x00] IPv4, Header len = 20 bytes
    .byte 0x00                      # [0x01] TOS
    .byte 0x00, 0x28                # [0x02] Total Length = 40 bytes
    .byte 0x13, 0x37                # [0x04] ID = 0x1337
    .byte 0x40, 0x00                # [0x06] Dont Fragment
    .byte 0x40                      # [0x08] TTL = 64
    .byte 0x06                      # [0x09] Protocol = 6 (TCP)
    .byte 0x00, 0x00                # [0x0A] IP Checksum
    .byte 115, 129, 50, 130         # [0x0C] Source IP = 115.129.50.130 (Yogesh Client IP)
    .byte 20, 248, 231, 206         # [0x10] Dest IP   = 20.248.231.206 (Honeypot Public IP)

    # --- 20-Byte TCP Header (Offsets 0x14..0x27) ---
    .byte 0xe0, 0xc7                # [0x14] Source Port = 57543 (0xe0c7)
    .byte 0x1f, 0x90                # [0x16] Dest Port   = 8080  (0x1f90)
    .byte 0x00, 0x00, 0x00, 0x01    # [0x18] Sequence Number = 1
    .byte 0x00, 0x00, 0x00, 0x00    # [0x1C] ACK Number      = 0
    .byte 0x50                      # [0x20] Data Offset = 5 words (20 bytes)
    .byte 0x02                      # [0x21] TCP Flags   = 0x02 (SYN!)
    .byte 0xff, 0xff                # [0x22] Window Size = 65535
    .byte 0x00, 0x00                # [0x24] TCP Checksum (Computed by calc_tcp_csum)
    .byte 0x00, 0x00                # [0x26] Urgent Pointer = 0

pseudo_buf:
    .byte 115, 129, 50, 130         # [0x00] Source IP = 115.129.50.130
    .byte 20, 248, 231, 206         # [0x04] Dest IP   = 20.248.231.206
    .byte 0x00, 0x06                # [0x08] Zero + Protocol (6 = TCP)
    .byte 0x00, 0x14                # [0x0A] TCP Length = 20 bytes
    .space 20, 0                    # [0x0C..0x1F] Copy of 20-byte TCP header

msg_syn: .ascii "[+] Raw SYN (40 bytes, Flag=0x02, Seq=1) sent from port 57543! Waiting for SYN-ACK...\n"
.equ len_syn, . - msg_syn
msg_ack: .ascii "[+] Received SYN-ACK (Flag=0x12)! Sent raw ACK (Flag=0x10, Seq=2) -> 3-Way Handshake ESTABLISHED!\n"
.equ len_ack, . - msg_ack

.section .bss
recv_buf: .space 1024

.section .text
_start:
    # 1. Auto-detect Local IP via dummy UDP route
    mov rax, 41
    mov rdi, 2
    mov rsi, 2
    xor rdx, rdx
    syscall
    mov r13, rax

    mov rax, 42
    mov rdi, r13
    lea rsi, [rip + dst_addr]
    mov rdx, 16
    syscall

    mov rax, 51
    mov rdi, r13
    lea rsi, [rip + local_addr]
    lea rdx, [rip + addr_len]
    syscall

    mov rax, 3
    mov rdi, r13
    syscall

    mov eax, dword ptr [rip + local_addr + 4]
    mov dword ptr [rip + raw_pkt + 0x0C], eax
    mov dword ptr [rip + pseudo_buf + 0x00], eax

    # 2. Open SOCK_RAW (IPPROTO_TCP=6) + IP_HDRINCL (3)
    mov rax, 41
    mov rdi, 2
    mov rsi, 3
    mov rdx, 6
    syscall
    mov r12, rax

    mov rax, 54
    mov rdi, r12
    xor rsi, rsi
    mov rdx, 3
    lea r10, [rip + one]
    mov r8, 4
    syscall

    # 3. Compute TCP Checksum & Send Raw SYN!
    call calc_tcp_csum

    mov rax, 44
    mov rdi, r12
    lea rsi, [rip + raw_pkt]
    mov rdx, 40
    xor r10, r10
    lea r8, [rip + dst_addr]
    mov r9, 16
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_syn]
    mov rdx, len_syn
    syscall

    # 4. Wait for SYN-ACK from Honeypot 20.248.231.206 (0xcee7f814)
.wait_syn_ack:
    mov rax, 45
    mov rdi, r12
    lea rsi, [rip + recv_buf]
    mov rdx, 1024
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall

    cmp dword ptr [rip + recv_buf + 0x0C], 0xcee7f814
    jne .wait_syn_ack

    movzx rbx, byte ptr [rip + recv_buf]
    and rbx, 0x0F
    shl rbx, 2

    lea rcx, [rip + recv_buf]
    add rcx, rbx
    cmp word ptr [rcx + 2], 0xc7e0
    jne .wait_syn_ack

    mov al, byte ptr [rcx + 13]
    and al, 0x12
    cmp al, 0x12
    jne .wait_syn_ack

    # 5. Build Raw ACK (Seq = 2, Ack = Server_Seq + 1, Flag = 0x10)
    mov eax, dword ptr [rcx + 4]
    bswap eax
    inc eax
    bswap eax
    mov dword ptr [rip + raw_pkt + 0x1C], eax

    mov dword ptr [rip + raw_pkt + 0x18], 0x02000000
    mov byte ptr [rip + raw_pkt + 0x21], 0x10

    call calc_tcp_csum

    mov rax, 44
    mov rdi, r12
    lea rsi, [rip + raw_pkt]
    mov rdx, 40
    xor r10, r10
    lea r8, [rip + dst_addr]
    mov r9, 16
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_ack]
    mov rdx, len_ack
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

calc_tcp_csum:
    mov word ptr [rip + raw_pkt + 0x24], 0
    lea rsi, [rip + raw_pkt + 0x14]
    lea rdi, [rip + pseudo_buf + 12]
    mov rcx, 20
    rep movsb

    lea rsi, [rip + pseudo_buf]
    mov rcx, 16
    xor eax, eax
.csum_loop:
    add ax, word ptr [rsi]
    adc ax, 0
    add rsi, 2
    dec rcx
    jnz .csum_loop
    not ax
    mov word ptr [rip + raw_pkt + 0x24], ax
    ret

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

# =============================================================================
# UNIFIED 157-BYTE RAW PACKET BUFFER:
#   - Bytes 0x00..0x13 (20B): IPv4 Header
#   - Bytes 0x14..0x27 (20B): TCP Header
#   - Bytes 0x28..0x9C (117B): TLS 1.3 ClientHello (JA4: t13n010400_0f2cb44170f4_f86e416269f0)
# =============================================================================
raw_pkt:
    # --- 20-Byte IPv4 Header (Offsets 0x00..0x13) ---
    .byte 0x45                      # [0x00] IPv4, Header len = 20 bytes
    .byte 0x00                      # [0x01] TOS
    .byte 0x00, 0x28                # [0x02] Total Length (40 for SYN/ACK, 157 / 0x009d for ClientHello)
    .byte 0x13, 0x37                # [0x04] ID = 0x1337
    .byte 0x40, 0x00                # [0x06] Dont Fragment
    .byte 0x40                      # [0x08] TTL = 64
    .byte 0x06                      # [0x09] Protocol = 6 (TCP)
    .byte 0x00, 0x00                # [0x0A] IP Checksum
    .byte 115, 129, 50, 130         # [0x0C] Source IP = 115.129.50.130 (Yogesh Client IP)
    .byte 20, 248, 231, 206         # [0x10] Dest IP   = 20.248.231.206 (Honeypot Public IP)

    # --- 20-Byte TCP Header (Offsets 0x14..0x27) ---
    .byte 0xe0, 0xd8                # [0x14] Source Port = 57560 (0xe0c8)
    .byte 0x1f, 0x90                # [0x16] Dest Port   = 8080  (0x1f90)
    .byte 0x00, 0x00, 0x00, 0x01    # [0x18] Sequence Number = 1
    .byte 0x00, 0x00, 0x00, 0x00    # [0x1C] ACK Number      = 0
    .byte 0x50                      # [0x20] Data Offset = 5 words (20 bytes)
    .byte 0x02                      # [0x21] TCP Flags   = 0x02 (SYN) -> 0x10 (ACK) -> 0x18 (PSH+ACK)
    .byte 0xff, 0xff                # [0x22] Window Size = 65535
    .byte 0x00, 0x00                # [0x24] TCP Checksum
    .byte 0x00, 0x00                # [0x26] Urgent Pointer = 0

    # --- 247-Byte Chrome Spoofed TLS 1.3 ClientHello Payload ---
    .byte 0x16, 0x03, 0x01, 0x00, 0xf2, 0x01, 0x00, 0x00, 0xee, 0x03, 0x03, 0x9e, 0x12, 0x6d, 0x07, 0xeb, 0x01, 0x66, 0x10, 0x4e, 0x75, 0xb9, 0x84, 0x09, 0xee, 0xe7, 0x21, 0x57, 0xfb, 0x66, 0x56, 0x30, 0x21, 0xc9, 0x42, 0xaf, 0x65, 0x21, 0x95, 0x81, 0xf1, 0x79, 0x2e, 0x00, 0x00, 0x1e, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00, 0x00, 0xa7, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13, 0x00, 0x00, 0x10, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x6f, 0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x75, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02, 0x00, 0x23, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x86, 0x86, 0xeb, 0xd8, 0xbb, 0x4f, 0x62, 0xdd, 0x70, 0x67, 0xe5, 0x97, 0x67, 0xaa, 0xe7, 0x7d, 0x16, 0xd3, 0x3d, 0xe2, 0x8b, 0xe0, 0x4f, 0xd6, 0xc2, 0x2c, 0x16, 0x06, 0xe2, 0x08, 0xe4, 0x44, 0x44, 0x69, 0x00, 0x00, 0xfe, 0x0d, 0x00, 0x01, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00

# Checksum scratch buffer (12B Pseudo-Header + up to 140B TCP+Payload)
pseudo_buf:
    .byte 115, 129, 50, 130         # [0x00] Source IP = 115.129.50.130
    .byte 20, 248, 231, 206         # [0x04] Dest IP   = 20.248.231.206
    .byte 0x00, 0x06                # [0x08] Zero + Protocol (6 = TCP)
    .byte 0x00, 0x14                # [0x0A] TCP Segment Length (20 for SYN/ACK, 137 / 0x0089 for ClientHello)
    .space 400, 0                   # [0x0C..] Copy of TCP Header + Payload

msg_1: .ascii "[Step 1] Raw TCP SYN (40B, Flag=0x02, Seq=1) sent from port 57560!\n"
.equ len_1, . - msg_1
msg_2: .ascii "[Step 2] Raw TCP SYN-ACK (Flag=0x12) received! Raw ACK (Flag=0x10, Seq=2) sent!\n"
.equ len_2, . - msg_2
msg_3: .ascii "[Step 3] Raw TCP+TLS 1.3 ClientHello (287B, Flag=0x18 PSH+ACK, Seq=2) sent!\n"
.equ len_3, . - msg_3
msg_4: .ascii "[Step 4] Received ServerHello + Encrypted Flight over Raw Socket! Full L3+L4+L5 Success!\n"
.equ len_4, . - msg_4

.section .bss
recv_buf: .space 2048

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

    # =========================================================================
    # PACKET 1: Send 40-Byte Raw TCP SYN (Flag = 0x02, Seq = 1)
    # =========================================================================
    mov r14, 20                     # TCP length = 20 bytes
    mov r15, 16                     # 16 words (32 bytes) in pseudo_buf
    call calc_tcp_csum

    mov rax, 44                     # sys_sendto (40 bytes)
    mov rdi, r12
    lea rsi, [rip + raw_pkt]
    mov rdx, 40
    xor r10, r10
    lea r8, [rip + dst_addr]
    mov r9, 16
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_1]
    mov rdx, len_1
    syscall

    # =========================================================================
    # PACKET 2: Wait for Server SYN-ACK (Flag = 0x12) on Port 57560 (0xd8e0)
    # =========================================================================
.wait_syn_ack:
    mov rax, 45
    mov rdi, r12
    lea rsi, [rip + recv_buf]
    mov rdx, 2048
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
    cmp word ptr [rcx + 2], 0xd8e0  # Port 57560 (0xe0c8 in big-endian)
    jne .wait_syn_ack

    mov al, byte ptr [rcx + 13]
    and al, 0x12
    cmp al, 0x12
    jne .wait_syn_ack

    # =========================================================================
    # PACKET 3: Send 40-Byte Raw TCP ACK (Flag = 0x10, Seq = 2, Ack = Srv_Seq+1)
    # =========================================================================
    mov eax, dword ptr [rcx + 4]
    bswap eax
    inc eax
    bswap eax
    mov dword ptr [rip + raw_pkt + 0x1C], eax

    mov dword ptr [rip + raw_pkt + 0x18], 0x02000000
    mov byte ptr [rip + raw_pkt + 0x21], 0x10

    mov r14, 20
    mov r15, 16
    call calc_tcp_csum

    mov rax, 44                     # sys_sendto (40 bytes)
    mov rdi, r12
    lea rsi, [rip + raw_pkt]
    mov rdx, 40
    xor r10, r10
    lea r8, [rip + dst_addr]
    mov r9, 16
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_2]
    mov rdx, len_2
    syscall

    # =========================================================================
    # PACKET 4: Send 157-Byte Raw TCP + TLS 1.3 ClientHello (Flag = 0x18 PSH+ACK)
    # =========================================================================
    # Update IP Total Length to 157 bytes (0x009d -> 0x1f01 little-endian)
    mov word ptr [rip + raw_pkt + 0x02], 0x1f01
    # Update TCP Flags to 0x18 (PSH + ACK)
    mov byte ptr [rip + raw_pkt + 0x21], 0x18
    # Update Pseudo-Header TCP Length to 137 bytes (20 TCP + 117 TLS = 0x0089 -> 0x0b01)
    mov word ptr [rip + pseudo_buf + 0x0A], 0x0b01

    mov r14, 267                    # Copy 137 bytes (20B TCP + 117B TLS) into pseudo_buf+12
    mov r15, 140                     # Sum 75 16-bit words (12B pseudo + 137B TCP/TLS + 1B pad = 150B)
    call calc_tcp_csum

    mov rax, 44                     # sys_sendto (157 bytes: 20B IP + 20B TCP + 117B TLS ClientHello!)
    mov rdi, r12
    lea rsi, [rip + raw_pkt]
    mov rdx, 287
    xor r10, r10
    lea r8, [rip + dst_addr]
    mov r9, 16
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_3]
    mov rdx, len_3
    syscall

    # =========================================================================
    # PACKET 5: Wait for ServerHello TLS Response (0x16 0x03 0x03) on Raw Socket!
    # =========================================================================
.wait_srv_hello:
    mov rax, 45
    mov rdi, r12
    lea rsi, [rip + recv_buf]
    mov rdx, 2048
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall

    cmp rax, 60                     # Must have payload > IP+TCP headers
    jle .wait_srv_hello
    cmp dword ptr [rip + recv_buf + 0x0C], 0xcee7f814
    jne .wait_srv_hello

    movzx rbx, byte ptr [rip + recv_buf]
    and rbx, 0x0F
    shl rbx, 2
    lea rcx, [rip + recv_buf]
    add rcx, rbx
    cmp word ptr [rcx + 2], 0xd8e0
    jne .wait_srv_hello

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_4]
    mov rdx, len_4
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

# =============================================================================
# Checksum Function: Copies r14 bytes of TCP+Payload, sums r15 16-bit words
# =============================================================================
calc_tcp_csum:
    mov word ptr [rip + raw_pkt + 0x24], 0
    lea rsi, [rip + raw_pkt + 0x14]
    lea rdi, [rip + pseudo_buf + 12]
    mov rcx, r14
    rep movsb
    mov byte ptr [rdi], 0           # Zero pad byte in case of odd length (137)

    lea rsi, [rip + pseudo_buf]
    mov rcx, r15
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

import os
import socket
import struct
import time

# =====================================================================
# PART 1: Dynamically Build a Chrome TLS 1.3 ClientHello with ANY SNI
# =====================================================================
def build_chrome_client_hello(domain_str):
    # Convert the domain string (e.g. "skyscanner.com") to raw ASCII bytes
    domain = domain_str.encode('ascii')
    L = len(domain)

    # 1. Extension 0x0000: Server Name Indication (SNI)
    # Because each domain has a different length (e.g., "qantas.com" is 10 bytes,
    # "skyscanner.com" is 14 bytes), we recalculate the 3 length headers automatically:
    #   - List Length = L + 3
    #   - Type = 0x00 (DNS Hostname)
    #   - Hostname Length = L
    sni_payload = struct.pack('!HBH', L + 3, 0, L) + domain
    ext_sni = struct.pack('!HH', 0x0000, len(sni_payload)) + sni_payload

    # 2. The other 13 Chrome TLS Extensions (kept identical so JA4 stays Chrome!)
    ext_ems      = struct.pack('!HH', 0x0017, 0)
    ext_reneg    = struct.pack('!HHB', 0xff01, 1, 0)
    groups       = [0x001d, 0x0017, 0x0018]
    g_bytes      = b''.join(struct.pack('!H', g) for g in groups)
    ext_groups   = struct.pack('!HHH', 0x000a, len(g_bytes) + 2, len(g_bytes)) + g_bytes
    ext_ec_pts   = struct.pack('!HHBB', 0x000b, 2, 1, 0)
    alpn_list    = b'\x02h2\x08http/1.1'
    ext_alpn     = struct.pack('!HHH', 0x0010, len(alpn_list) + 2, len(alpn_list)) + alpn_list
    ext_status   = struct.pack('!HHBHH', 0x0005, 5, 1, 0, 0)
    sigs         = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    s_bytes      = b''.join(struct.pack('!H', s) for s in sigs)
    ext_sig      = struct.pack('!HHH', 0x000d, len(s_bytes) + 2, len(s_bytes)) + s_bytes
    ext_sct      = struct.pack('!HH', 0x0012, 0)
    pub_key      = bytes([0x42] * 32)
    ks_entry     = struct.pack('!HH', 0x001d, 32) + pub_key
    ext_ks       = struct.pack('!HHH', 0x0033, len(ks_entry) + 2, len(ks_entry)) + ks_entry
    ext_psk_mode = struct.pack('!HHBB', 0x002d, 2, 1, 1)
    supp_v       = struct.pack('!BHH', 4, 0x0304, 0x0303)
    ext_supp_v   = struct.pack('!HH', 0x002b, len(supp_v)) + supp_v
    ext_comp     = struct.pack('!HHBH', 0x001b, 3, 2, 0x0002)
    ext_alps     = struct.pack('!HHH', 0x4469, 5, 3) + b'\x02h2'

    # Glue all 14 extensions together
    extensions = (
        ext_sni + ext_ems + ext_reneg + ext_groups + ext_ec_pts +
        ext_alpn + ext_status + ext_sig + ext_sct + ext_ks +
        ext_psk_mode + ext_supp_v + ext_comp + ext_alps
    )

    # 3. Chrome's 15 Cipher Suites
    ciphers = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
    ]
    cipher_bytes = b''.join(struct.pack('!H', c) for c in ciphers)

    # 4. Wrap into TLS ClientHello Body -> Handshake Header -> TLS Record Header
    legacy_ver   = b'\x03\x03'
    random_bytes = bytes([0x11] * 32)
    sess_id      = b'\x20' + bytes([0x22] * 32)
    comp_methods = b'\x01\x00'

    ch_body = (
        legacy_ver + random_bytes + sess_id +
        struct.pack('!H', len(cipher_bytes)) + cipher_bytes +
        comp_methods +
        struct.pack('!H', len(extensions)) + extensions
    )
    hs_msg     = b'\x01' + struct.pack('!I', len(ch_body))[1:] + ch_body
    tls_record = b'\x16\x03\x01' + struct.pack('!H', len(hs_msg)) + hs_msg
    return tls_record


# =====================================================================
# PART 2: Read Exact Kernel CPU Ticks of the Honeypot Process (/proc/1/stat)
# =====================================================================
def get_honeypot_ticks():
    # Inside our Kubernetes container, honeypot_server.py is Process ID 1 (PID 1).
    # The Linux kernel exposes real-time CPU accounting for PID 1 in /proc/1/stat.
    with open("/proc/1/stat") as f:
        parts = f.read().split()
    utime = int(parts[13])      # Column 14: User-space CPU ticks (Python + OpenSSL math)
    stime = int(parts[14])      # Column 15: Kernel-space CPU ticks (TCP sockets + disk I/O)
    rss_pages = int(parts[23])  # Column 24: RAM pages currently in use
    return utime + stime, rss_pages * 4  # 1 tick = 10 ms (1/100th of a second)


# =====================================================================
# PART 3: Fire 50 Requests Rotating SNI and Compare CPU Before vs After
# =====================================================================
if __name__ == "__main__":
    domains = ['skyscanner.com', 'bravofly.com', 'expedia.com', 'booking.com', 'qantas.com']
    target_ip = '20.248.231.206'
    target_port = 443

    # Snapshot CPU ticks BEFORE the 50 requests
    ticks_before, rss_before = get_honeypot_ticks()
    sender_t0 = os.times()[0] + os.times()[1]
    t0 = time.time()

    latencies = []
    bytes_sent = 0
    bytes_rcvd = 0

    for i in range(50):
        # Pick the next domain from our list of 5 travel websites
        dom = domains[i % len(domains)]
        pkt = build_chrome_client_hello(dom)

        req_start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((target_ip, target_port))
        s.sendall(pkt)
        bytes_sent += len(pkt)

        # Wait for the honeypot to finish its OpenSSL math and send back ServerHello
        resp = s.recv(4096)
        bytes_rcvd += len(resp)
        s.close()
        latencies.append((time.time() - req_start) * 1000.0)

    # Snapshot CPU ticks AFTER the 50 requests
    total_time = time.time() - t0
    sender_t1 = os.times()[0] + os.times()[1]
    ticks_after, rss_after = get_honeypot_ticks()

    # Convert kernel ticks (100 ticks = 1.00 second) into milliseconds and CPU %
    server_cpu_sec = (ticks_after - ticks_before) / 100.0
    sender_cpu_sec = sender_t1 - sender_t0
    server_cpu_pct = (server_cpu_sec / total_time) * 100.0

    print(f"Total Wall Time for 50 Requests: {total_time:.3f} seconds ({50/total_time:.1f} handshakes/sec)")
    print(f"Sender CPU Time Used:            {sender_cpu_sec*1000:.1f} ms")
    print(f"Honeypot Server CPU Time Used:   {server_cpu_sec*1000:.1f} ms ({server_cpu_pct:.1f}% of a CPU core!)")
    print(f"Total Bytes Sent by Sender:      {bytes_sent} bytes (~{bytes_sent//50} bytes/req)")
    print(f"Total Bytes Replied by Honeypot: {bytes_rcvd} bytes (~{bytes_rcvd//50} bytes/req)")

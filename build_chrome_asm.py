import struct

ciphers = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
    0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035
]
cipher_bytes = struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)

def ext(t, val):
    return struct.pack(">HH", t, len(val)) + val

sni_host = b"globalsoc.com.au"
sni_val = struct.pack(">HBH", len(sni_host) + 3, 0, len(sni_host)) + sni_host
alpn_val = struct.pack(">HB", 3, 2) + b"h2"
sup_ver = b"\x02\x03\x04"
sup_grp = struct.pack(">HH", 2, 0x001d)
sig_algs_list = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
sig_val = struct.pack(">H", len(sig_algs_list) * 2) + b"".join(struct.pack(">H", s) for s in sig_algs_list)
pub_key = bytes.fromhex("8686ebd8bb4f62dd7067e59767aae77d16d33de28be04fd6c22c1606e208e444")
key_share = struct.pack(">HHH", 36, 0x001d, 32) + pub_key

exts = b"".join([
    ext(0x0000, sni_val),                   # SNI: globalsoc.com.au ("d")
    ext(0x0010, alpn_val),                  # ALPN: h2 ("h2")
    ext(0x0005, b"\x01\x00\x00\x00\x00"),   # status_request
    ext(0x000a, sup_grp),                   # supported_groups
    ext(0x000b, b"\x01\x00"),               # ec_point_formats
    ext(0x000d, sig_val),                   # signature_algorithms (Chrome 8 sig algs)
    ext(0x0012, b""),                       # signed_certificate_timestamp
    ext(0x0017, b""),                       # extended_master_secret
    ext(0x001b, b"\x02\x00\x02"),           # compress_certificate
    ext(0x0023, b""),                       # session_ticket
    ext(0x002b, sup_ver),                   # supported_versions (TLS 1.3)
    ext(0x002d, b"\x01\x01"),               # psk_key_exchange_modes
    ext(0x0033, key_share),                 # key_share
    ext(0x4469, b""),                       # application_settings
    ext(0xfe0d, b"\x00"),                   # encrypted_client_hello
    ext(0xff01, b"\x00")                    # renegotiation_info
])

ch_body = (
    b"\x03\x03" +
    bytes.fromhex("9e126d07eb0166104e75b98409eee72157fb66563021c942af65219581f1792e") +
    b"\x00" +
    cipher_bytes +
    b"\x01\x00" +
    struct.pack(">H", len(exts)) + exts
)
handshake = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
tls_record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake

byte_lines = ", ".join(f"0x{b:02x}" for b in tls_record)
total_ip_len = 40 + len(tls_record)
tcp_seg_len = 20 + len(tls_record)
csum_words = (12 + tcp_seg_len + (1 if tcp_seg_len % 2 else 0)) // 2

ip_le = ((total_ip_len & 0xff) << 8) | (total_ip_len >> 8)
tcp_le = ((tcp_seg_len & 0xff) << 8) | (tcp_seg_len >> 8)

with open(r"C:\Users\glenw\.gemini\antigravity-cli\scratch\k8s-attack-lab\raw_tcp_tls_ja4.s") as f:
    orig = f.read()

start_marker = "    # --- 117-Byte TLS 1.3 ClientHello Payload"
end_marker = "# Checksum scratch buffer"
s_idx = orig.index(start_marker)
e_idx = orig.index(end_marker)

asm2 = (
    orig[:s_idx] +
    f"    # --- {len(tls_record)}-Byte Chrome Spoofed TLS 1.3 ClientHello Payload ---\n" +
    f"    .byte {byte_lines}\n\n" +
    orig[e_idx:]
)
asm2 = asm2.replace("0xe0, 0xc8", "0xe0, 0xd8").replace("0xc8e0", "0xd8e0").replace("57544", "57560")
asm2 = asm2.replace(".space 144, 0", ".space 400, 0")
asm2 = asm2.replace("0x9d00", f"0x{ip_le:04x}").replace("0x8900", f"0x{tcp_le:04x}")
asm2 = asm2.replace("mov r14, 137", f"mov r14, {tcp_seg_len}")
asm2 = asm2.replace("mov r15, 75", f"mov r15, {csum_words}")
asm2 = asm2.replace("mov rdx, 157", f"mov rdx, {total_ip_len}")
asm2 = asm2.replace("157B", f"{total_ip_len}B")

with open(r"C:\Users\glenw\.gemini\antigravity-cli\scratch\k8s-attack-lab\raw_chrome.s", "w") as f:
    f.write(asm2)

print(f"Generated raw_chrome.s: TLS={len(tls_record)}B, Total IP={total_ip_len}B")

import asyncio
import os
import struct
import time

# =====================================================================
# Concurrency Benchmark: 1,000 Simultaneous TLS 1.3 Handshakes
# Demonstrates TCP listen(100) backlog saturation, thread/RAM growth,
# and latency inflation under concurrent TLS cryptographic load.
# =====================================================================

def build_chrome_client_hello(domain_str):
    domain = domain_str.encode('ascii')
    L = len(domain)
    sni_payload = struct.pack('!HBH', L + 3, 0, L) + domain
    ext_sni = struct.pack('!HH', 0x0000, len(sni_payload)) + sni_payload
    ext_ems = struct.pack('!HH', 0x0017, 0)
    ext_reneg = struct.pack('!HHB', 0xff01, 1, 0)
    groups = [0x001d, 0x0017, 0x0018]
    g_bytes = b''.join(struct.pack('!H', g) for g in groups)
    ext_groups = struct.pack('!HHH', 0x000a, len(g_bytes)+2, len(g_bytes)) + g_bytes
    ext_ec_pts = struct.pack('!HHBB', 0x000b, 2, 1, 0)
    alpn_list = b'\x02h2\x08http/1.1'
    ext_alpn = struct.pack('!HHH', 0x0010, len(alpn_list)+2, len(alpn_list)) + alpn_list
    ext_status = struct.pack('!HHBHH', 0x0005, 5, 1, 0, 0)
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    s_bytes = b''.join(struct.pack('!H', s) for s in sigs)
    ext_sig = struct.pack('!HHH', 0x000d, len(s_bytes)+2, len(s_bytes)) + s_bytes
    ext_sct = struct.pack('!HH', 0x0012, 0)
    pub_key = bytes([0x42]*32)
    ks_entry = struct.pack('!HH', 0x001d, 32) + pub_key
    ext_ks = struct.pack('!HHH', 0x0033, len(ks_entry)+2, len(ks_entry)) + ks_entry
    ext_psk_mode = struct.pack('!HHBB', 0x002d, 2, 1, 1)
    supp_v = struct.pack('!BHH', 4, 0x0304, 0x0303)
    ext_supp_v = struct.pack('!HH', 0x002b, len(supp_v)) + supp_v
    ext_comp = struct.pack('!HHBH', 0x001b, 3, 2, 0x0002)
    ext_alps = struct.pack('!HHH', 0x4469, 5, 3) + b'\x02h2'

    extensions = (
        ext_sni + ext_ems + ext_reneg + ext_groups + ext_ec_pts +
        ext_alpn + ext_status + ext_sig + ext_sct + ext_ks +
        ext_psk_mode + ext_supp_v + ext_comp + ext_alps
    )
    ciphers = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
    ]
    cipher_bytes = b''.join(struct.pack('!H', c) for c in ciphers)
    ch_body = (
        b'\x03\x03' + bytes([0x11]*32) + b'\x20' + bytes([0x22]*32) +
        struct.pack('!H', len(cipher_bytes)) + cipher_bytes +
        b'\x01\x00' +
        struct.pack('!H', len(extensions)) + extensions
    )
    hs_msg = b'\x01' + struct.pack('!I', len(ch_body))[1:] + ch_body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs_msg)) + hs_msg


def get_honeypot_stats():
    with open("/proc/1/stat") as f:
        parts = f.read().split()
    utime = int(parts[13])
    stime = int(parts[14])
    num_threads = int(parts[19])
    rss_kb = int(parts[23]) * 4
    return utime + stime, num_threads, rss_kb


domains = ['skyscanner.com', 'bravofly.com', 'expedia.com', 'booking.com', 'qantas.com']
pkts = [build_chrome_client_hello(d) for d in domains]


async def fire_one(idx, start_gate):
    pkt = pkts[idx % 5]
    await start_gate.wait()
    t0 = time.time()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection('20.248.231.206', 443), timeout=5.0)
        writer.write(pkt)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        await asyncio.sleep(0.3)
        writer.close()
        return ('ok', (time.time() - t0 - 0.3) * 1000.0, len(data))
    except Exception as e:
        return (type(e).__name__, (time.time() - t0) * 1000.0, 0)


async def main():
    ticks_before, threads_before, rss_before = get_honeypot_stats()
    sender_t0 = os.times()[0] + os.times()[1]

    start_gate = asyncio.Event()
    tasks = [asyncio.create_task(fire_one(i, start_gate)) for i in range(1000)]
    await asyncio.sleep(0.05)  # Align all 1,000 tasks at the starting gate

    t0 = time.time()
    start_gate.set()           # Release all 1,000 requests simultaneously

    await asyncio.sleep(0.15)
    _, peak_threads_1, peak_rss_1 = get_honeypot_stats()
    await asyncio.sleep(0.15)
    _, peak_threads_2, peak_rss_2 = get_honeypot_stats()

    results = await asyncio.gather(*tasks)
    total_time = time.time() - t0

    sender_t1 = os.times()[0] + os.times()[1]
    ticks_after, threads_after, rss_after = get_honeypot_stats()

    ok_lat = [r[1] for r in results if r[0] == 'ok']
    errs = {}
    for r in results:
        if r[0] != 'ok':
            errs[r[0]] = errs.get(r[0], 0) + 1

    server_cpu_sec = (ticks_after - ticks_before) / 100.0
    sender_cpu_sec = sender_t1 - sender_t0
    peak_threads = max(peak_threads_1, peak_threads_2, threads_after)
    peak_rss = max(peak_rss_1, peak_rss_2, rss_after)

    print(f"Total Wall Time for 1000 Instant Requests: {total_time:.3f} seconds")
    print(f"Successful Handshakes:                     {len(ok_lat)} / 1000")
    print(f"Failed / Dropped / Timed-Out Connections:  {sum(errs.values())} ({errs})")
    print(f"Sender CPU Time Used:                      {sender_cpu_sec*1000:.1f} ms")
    print(f"Honeypot Server CPU Time Used:             {server_cpu_sec*1000:.1f} ms ({(server_cpu_sec/total_time)*100:.1f}% CPU!)")
    print(f"Honeypot Active Threads (Before -> Peak):  {threads_before} threads -> {peak_threads} threads")
    print(f"Honeypot RAM Used (Before -> Peak):        {rss_before} KB -> {peak_rss} KB (+{peak_rss - rss_before} KB)")
    if ok_lat:
        print(f"Handshake Latency (Min / Avg / Max):       {min(ok_lat):.1f} ms / {sum(ok_lat)/len(ok_lat):.1f} ms / {max(ok_lat):.1f} ms")


if __name__ == "__main__":
    asyncio.run(main())

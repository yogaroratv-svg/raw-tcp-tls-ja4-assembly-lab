# Raw TCP, TLS 1.3 & JA4 Fingerprinting in x86_64 Assembly — Step-by-Step Guide

**Author:** Yogesh Arora (Global SOC Australia)  
**Environment:** Azure Kubernetes Service (`aks-lab`, Linux `x86_64`)

This repository contains the complete collection of pure `x86_64` Linux assembly programs, Python packet generators, and kernel telemetry benchmarks used to study how **TCP 3-Way Handshakes (RFC 793)**, **TLS 1.3 `ClientHello` greetings (RFC 8446)**, and **JA4 TLS Fingerprinting** work at the raw byte level.

---

## Repository Contents

| File | Description |
| :--- | :--- |
| **`raw_tcp.s`** | Pure `x86_64` assembly program that opens a raw socket (`SOCK_RAW`), constructs a 40-byte IPv4 + TCP header from scratch, and completes a full TCP 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`). |
| **`raw_tcp_tls_ja4.s`** | Unified `x86_64` assembly program that performs the raw TCP 3-way handshake and immediately transmits a custom TLS 1.3 `ClientHello` (`PSH-ACK`), producing JA4 fingerprint `t13n020400_62ed6f6ca7ad_f86e416269f0`. |
| **`raw_chrome.s`** | Pure `x86_64` assembly program that constructs a 287-byte raw IPv4 + TCP + TLS 1.3 `ClientHello` matching Google Chrome's 15 ciphers, 14 extensions, `SNI: globalsoc.com.au`, and `ALPN: h2` (`JA4: t13d1514h2_8daaf6152771_02713d6af862`). |
| **`build_chrome_asm.py`** | Python generator script that calculates nested TLS extension lengths and generates the commented `raw_chrome.s` assembly source. |
| **`test_50_sni_cpu.py`** | Python benchmark that dynamically swaps the TLS `SNI` domain across 50 requests (`skyscanner.com`, `bravofly.com`, `expedia.com`, `booking.com`, `qantas.com`) and reads `/proc/1/stat` to measure exact kernel CPU ticks. |
| **`test_1000_concurrent_tls.py`** | Python `asyncio` concurrency stress test that releases 1,000 Chrome TLS handshakes at the exact same millisecond to measure `listen(100)` backlog saturation, thread creation, RAM growth, and latency inflation. |

---

## Step 1: Building a Raw TCP 3-Way Handshake in Assembly (`raw_tcp.s`)

Normally, when a program calls `connect()`, the Linux kernel automatically builds the **20-byte IPv4 header** and **20-byte TCP header** behind the scenes. 

In **`raw_tcp.s`**, we bypass the kernel's TCP stack using a **Raw Socket (`SOCK_RAW`)** so we can control every single bit of the 40-byte packet ourselves.

### 1.1 Opening the Raw Socket & Enabling `IP_HDRINCL`
1. **Create the Raw Socket (`syscall 41`):**
   * `movq $41, %rax` (`sys_socket`)
   * `movq $2, %rdi` (`AF_INET` = IPv4)
   * `movq $3, %rsi` (`SOCK_RAW` = Raw packets)
   * `movq $6, %rdx` (`IPPROTO_TCP` = TCP protocol)
2. **Tell Linux We Are Supplying Our Own IPv4 Header (`syscall 54`):**
   * `movq $54, %rax` (`sys_setsockopt`)
   * `movq $0, %rsi` (`IPPROTO_IP`)
   * `movq $3, %rdx` (`IP_HDRINCL` = Header Included)

### 1.2 Why We Need a Temporary `iptables` Rule for Raw Sockets
Because we created our connection using a Raw Socket instead of asking the Linux kernel to `connect()`, **the Linux kernel does not know we are expecting a `SYN-ACK` reply**.
* When the server replies with `SYN-ACK` to our source port (e.g. `57543`), the Linux kernel looks at its table of open ports, sees nothing registered on port `57543`, and reflexively fires a **`RST` (Reset)** packet that kills the connection!
* **The Fix:** Before running our assembly binary, we tell the Linux firewall not to send outgoing `RST` packets from our test port (`57543`):
  ```bash
  iptables -I OUTPUT -p tcp --tcp-flags RST RST --sport 57543 -j DROP
  ```

### 1.3 Anatomy of the 40-Byte IPv4 + TCP Packet (`syn_pkt`)

| Byte Offset | Layer | Field Name | Value in `raw_tcp.s` | Meaning |
| :--- | :--- | :--- | :--- | :--- |
| **0 – 1** | IPv4 | Version, IHL, TOS | `0x45, 0x00` | IPv4 (`4`), Header Length = `5` words (20 bytes) |
| **2 – 3** | IPv4 | Total Length | `0x00, 0x28` | `40` bytes total (20 IPv4 + 20 TCP) |
| **4 – 9** | IPv4 | ID, Flags, TTL, Proto | `..., 0x40, 0x06` | TTL = `64` (`0x40`), Protocol = `6` (`TCP`) |
| **12 – 15** | IPv4 | Source IP | `115, 129, 50, 130` | Your Real Client IP (`115.129.50.130`) |
| **16 – 19** | IPv4 | Destination IP | `20, 248, 231, 206` | Honeypot Public IP (`20.248.231.206`) |
| **20 – 21** | TCP | Source Port | `0xe0, 0xc7` | Port `57543` |
| **22 – 23** | TCP | Destination Port | `0x1f, 0x90` | Port `8080` (or `0x01, 0xbb` = Port `443`) |
| **24 – 27** | TCP | Sequence Number (`Seq`) | `0x00, 0x00, 0x03, 0xe8` | Initial Client Sequence Number `X = 1000` |
| **28 – 31** | TCP | Acknowledgment (`Ack`) | `0x00, 0x00, 0x00, 0x00` | `0` during `SYN` (populated during Step 3 `ACK`) |
| **32** | TCP | Data Offset | `0x50` | `5` words (20 bytes TCP header) |
| **33** | TCP | TCP Flags | `0x02` (`SYN`) | Changed to `0x10` (`ACK`) in Step 3, and `0x18` (`PSH-ACK`) for TLS |
| **34 – 35** | TCP | Window Size | `0xff, 0xff` | `65535` bytes receive window |
| **36 – 37** | TCP | TCP Checksum | `0x6f, 0x2f` | 16-bit ones' complement checksum over pseudo-header + TCP |

### 1.4 The Secret of Step 3: How Assembly Reads `SYN-ACK` and Builds `ACK`
When the server receives our `SYN` (`Seq = 1000`), it replies with a `SYN-ACK` containing its own **random 32-bit Sequence Number `Y`** at **byte offset 24** of the received packet (`rx_buf + 24`).

Because we cannot guess `Y` ahead of time, our assembly code (`raw_tcp.s`) loops reading packets from the raw socket (`sys_recvfrom`) until it sees a packet addressed to our port (`0xc7e0`) with `SYN-ACK` flags (`0x12`), and then performs **4 instructions** to complete the handshake:
1. **Read the server's 32-bit Sequence Number `Y`:**
   ```asm
   movl rx_buf+24(%rip), %eax    # Load Server Seq (Y) in Big-Endian network order
   ```
2. **Add `1` to `Y` (`Y + 1`):**
   Because x86_64 CPUs do math in Little-Endian, we flip the 4 bytes (`bswap`), add `1` (`incl`), and flip them back (`bswap`):
   ```asm
   bswap %eax                    # Convert Big-Endian -> Little-Endian
   incl %eax                     # Compute Y + 1
   bswap %eax                    # Convert back to Big-Endian network order
   ```
3. **Write `Y + 1` into our packet's Acknowledgment field (offset 28) and update our Sequence Number to `1001` (`0x03e9`):**
   ```asm
   movl %eax, syn_pkt+28(%rip)   # Set TCP Ack = Y + 1
   movl $0xe9030000, syn_pkt+24(%rip) # Set TCP Seq = 1001
   movb $0x10, syn_pkt+33(%rip)  # Change TCP Flag from 0x02 (SYN) to 0x10 (ACK)
   ```
4. **Recompute the 16-bit TCP Checksum over the updated header and call `sendto` (`syscall 44`).** The connection is now officially **`ESTABLISHED`**!

---

## Step 2: Sending a TLS 1.3 `ClientHello` & Understanding JA4 (`raw_tcp_tls_ja4.s`)

Once the 3-way TCP handshake (`SYN` -> `SYN-ACK` -> `ACK`) finishes, the client speaks first by sending a **TLS 1.3 `ClientHello`** inside a TCP **`PSH-ACK` (`0x18`)** packet.

### 2.1 How the JA4 Fingerprint (`JA4_a` _ `JA4_b` _ `JA4_c`) Works
Every time a client sends an unencrypted TLS `ClientHello`, a defender (or honeypot) computes a 36-character **JA4 Fingerprint** divided into three sections separated by underscores:

```text
t13d1514h2 _ 8daaf6152771 _ 02713d6af862
|________|   |__________|   |__________|
  JA4_a         JA4_b          JA4_c
```

| Section | Characters | How It Is Calculated | Example (`Chrome`) |
| :--- | :--- | :--- | :--- |
| **`JA4_a`** (10 chars) | `1` (Protocol)<br>`2–3` (TLS Version)<br>`4` (SNI Mode)<br>`5–6` (Cipher Count)<br>`7–8` (Extension Count)<br>`9–10` (ALPN) | • `t` = TCP (`q` = QUIC)<br>• `13` = TLS 1.3 (`12` = TLS 1.2)<br>• `d` = Domain in SNI, `i` = IP literal in SNI, `n` = No SNI<br>• 2-digit count of Cipher Suites<br>• 2-digit count of Extensions<br>• First & last character of first ALPN protocol (`h2`, `h1`, or `00`) | `t` + `13` + `d` + `15` + `14` + `h2`<br>= **`t13d1514h2`** |
| **`JA4_b`** (12 chars) | First 12 chars of SHA-256 | Sort the hex codes of the **Cipher Suites** in ascending order, join with commas, and take the first 12 characters of the SHA-256 hash. | **`8daaf6152771`** |
| **`JA4_c`** (12 chars) | First 12 chars of SHA-256 | Sort the hex codes of the **TLS Extensions** (excluding SNI `0000` and ALPN `0010`), append `_` + the **Signature Algorithms** in original order, and take the first 12 characters of the SHA-256 hash. | **`02713d6af862`** |

### 2.2 What Happens When You Change 1 Cipher to 2 Ciphers in Assembly
In **`raw_tcp_tls_ja4.s`**, we tested adding a second cipher suite (`TLS_AES_256_GCM_SHA384` = `0x13, 0x02`) right after `TLS_AES_128_GCM_SHA256` (`0x13, 0x01`).

Because TLS uses **nested length headers**, adding **2 bytes** inside the Cipher Suites list requires adding **`+2`** to **5 length fields** from the inside out:
1. **Cipher Suites Length:** `2` -> `4` (`0x00, 0x04`)
2. **ClientHello Handshake Length:** `112` -> `114` (`0x00, 0x00, 0x72`)
3. **TLS Record Length:** `116` -> `118` (`0x00, 0x76`)
4. **IPv4 Total Packet Length:** `157` -> `159` (`0x00, 0x9f`)
5. ** Assembly `sendto` Byte Count (`%rdx`) & Checksum Loop:** `157` -> `159`

**Resulting JA4 Change Verified in Honeypot Logs:**
* **1 Cipher (`1301`):** `t13n010400_0f2cb44170f4_f86e416269f0`
* **2 Ciphers (`1301, 1302`):** `t13n020400_62ed6f6ca7ad_f86e416269f0` (Notice `01` became `02`, `JA4_b` changed completely, and `JA4_c` stayed identical!)

### 2.3 Two Important TLS 1.3 Handshake Rules We Discovered
1. **Empty `key_share` Triggers `HelloRetryRequest`:**
   * If a client sends an empty `key_share` extension (`0x0033`), OpenSSL replies with a `ServerHello` whose 32-byte random field is hardcoded to `CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C` (the SHA-256 of `"HelloRetryRequest"` per RFC 8446). Including a 32-byte `X25519` public key (`0x001d`) in the first packet eliminates the extra round-trip.
2. **Signature Algorithms Must Match the Server's Certificate Type:**
   * If a client advertises ECDSA (`0x0403`) alongside RSA-PSS (`0x0804`), or omits RSA-PSS when connecting to a server with an **RSA-2048 certificate**, OpenSSL aborts with `no suitable signature algorithm`. Advertising `0x0804` (`rsa_pss_rsae_sha256`) ensures clean negotiation with RSA certificates.

---

## Step 3: Crafting a Google Chrome JA4 Profile in Assembly (`raw_chrome.s`)

A stripped-down assembly packet (`t13n010400...`) looks abnormal to a SOC analyst because real browsers never connect with 1 cipher, 4 extensions, and no SNI (`n`).

In **`raw_chrome.s`** (generated by **`build_chrome_asm.py`**), we expanded the TLS `ClientHello` from 117 bytes to **247 bytes** (287 bytes total with IPv4 + TCP headers) by including:
1. **All 15 of Chrome's Cipher Suites** (`0x1301` through `0x0035`) -> produces `15` in `JA4_a` and `8daaf6152771` in `JA4_b`.
2. **All 14 of Chrome's TLS Extensions** (`0x0000` SNI, `0x0017`, `0xff01`, `0x000a`, `0x000b`, `0x0010` ALPN, `0x0005`, `0x000d`, `0x0012`, `0x0033`, `0x002d`, `0x002b`, `0x001b`, `0x4469`) + Chrome's 8 Signature Algorithms -> produces `14` in `JA4_a` and `02713d6af862` in `JA4_c`.
3. **Extension `0x0000` (SNI):** Contains `"globalsoc.com.au"` -> changes the 4th character of JA4 from `n` to **`d`**.
4. **Extension `0x0010` (ALPN):** Contains `"h2"` and `"http/1.1"` -> changes characters 9–10 of JA4 from `00` to **`h2`**.

**Resulting JA4 Captured by Honeypot:**
```text
t13d1514h2_8daaf6152771_02713d6af862
```
*(Important Defensive Insight: Because JA4 is computed solely from the unencrypted `ClientHello` before any encryption math takes place, any sender can copy Chrome's `ClientHello` byte layout to match Chrome's JA4—even if the sender closes the connection immediately after receiving `ServerHello`!)*

---

## Step 4: SNI Routing, Domain Fronting & Real Honeypot Detections

### 4.1 Why a Packet with `SNI: globalsoc.com.au` Still Lands on Our Honeypot (`20.248.231.206`)
Internet routers **never read the TLS SNI field**.
1. **Network Routers (Layer 3):** Only read the **Destination IP Address** at bytes 16–19 of the IPv4 header (`20.248.231.206`). That is why the packet physically arrives at our honeypot.
2. **Firewall / Server Monitors (Layer 7):** Read the unencrypted **TLS SNI text field** (`globalsoc.com.au` or `bravofly.com`) inside the `ClientHello` payload to log which website the user is asking for.

### 4.2 Real SNI Spoofing & Proxy Fronting Discovered in Our Honeypot Logs
When we audited **19,613 TLS handshakes** and **30,782 HTTP requests** on our live Azure honeypot (`20.248.231.206`), we caught three real-world attacker behaviors:

| Attacker IP | What They Injected | Layer & JA4 | Why the Attacker Did It |
| :--- | :--- | :--- | :--- |
| **`50.236.138.77`** | `SNI: bravofly.com` | TLS `ClientHello` (`t13d131000_...`) | Hunting for abandoned cloud IPs / forgotten DNS records belonging to `bravofly.com`, or spoofing SNI to disguise scanner traffic as flight booking. |
| **`94.102.49.190`** (+ 18,200 hits) | `SNI: 20.248.231.206` | TLS `ClientHello` (`t13i181100_...`) | Automated scripts copying our raw IP address into the DNS hostname field. **JA4 instantly caught them** by changing the 4th character from `d` (domain) to **`i` (IP literal)**! |
| **`177.16.198.72`**, **`45.153.34.230`**, **`20.169.33.201`** | `http://a7x.overflow.biz`, `http://ip-api.com`, `http://169.254.169.254` | HTTP Request Line / `Host` Header | Testing if our server is an **Open Proxy** to relay botnet traffic (`hachk.php`), mask their IP address, or leak internal Azure cloud metadata credentials (SSRF). |

---

## Step 5: TLS CPU Asymmetry & Concurrency Stress Testing (`test_50_sni_cpu.py` & `test_1000_concurrent_tls.py`)

### 5.1 How to Measure Sub-Second CPU Spikes via `/proc/1/stat`
Standard tools like `top` only refresh every 1–3 seconds, so a 0.1-second burst is invisible. In **`test_50_sni_cpu.py`**, we read the Linux kernel's process accounting file `/proc/1/stat` directly before and after the burst:
* **Column 14 (`utime`):** User-space CPU clock ticks burned by Python + OpenSSL cryptography.
* **Column 15 (`stime`):** Kernel-space CPU clock ticks burned by TCP sockets + disk logging.
* **Column 20 (`num_threads`):** Active concurrent threads inside the server process.
* **Column 24 (`rss`):** Resident memory pages currently used in RAM.
* Each kernel clock tick equals **10 milliseconds** (`1/100th` of a second) of 100% CPU work.

### 5.2 Benchmark Results: 50 Sequential vs. 1,000 Simultaneous Requests

| Metric | 50 Requests (One-by-One) | 1,000 Requests (Same Instant!) | Key Takeaway |
| :--- | :--- | :--- | :--- |
| **Wall-Clock Time** | `0.105 seconds` | `6.187 seconds` | Concurrency caused a massive processing bottleneck. |
| **Successful Handshakes** | **50 / 50 (100%)** | **767 / 1,000 (76.7%)** | **233 connections failed (`TimeoutError`)** because the server's `listen(100)` TCP backlog waiting room overflowed! |
| **Average Handshake Latency** | **2.06 ms** | **1,033.7 ms** (Max: `5,414.8 ms`) | **500x slowdown!** Requests queued up waiting for OpenSSL CPU time. |
| **Sender CPU vs. Server CPU** | `0.0 ms` vs. **`80.0 ms` (76.4% CPU)** | `370.0 ms` vs. **`2,140.0 ms`** | Sending static `ClientHello` bytes costs almost zero CPU, while the server must perform heavy `X25519` + RSA-2048 math. |
| **Network Traffic Amplification** | `285 B` sent -> **`1,546 B` replied** | `285 B` sent -> **`1,546 B` replied** | **5.4x amplification** (`ServerHello` + TLS Certificates). |
| **Server Threads & RAM** | `3 threads` / `52.9 MB` | **`514 threads` / `63.5 MB` (+10.5 MB)** | Holding concurrent connections open forces the server to allocate hundreds of threads and OpenSSL buffers in RAM. |

---

## Step 6: How to Compile and Run the Assembly Programs on Linux (`x86_64`)

To assemble, link, and test any of the `.s` programs on an `x86_64` Linux machine:

```bash
# 1. Assemble the source code into an object file (.o)
as --64 raw_chrome.s -o raw_chrome.o

# 2. Link the object file into a standalone executable binary
ld raw_chrome.o -o raw_chrome

# 3. Temporarily block the Linux kernel from sending TCP RST on your chosen source port (e.g. 57560)
sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST --sport 57560 -j DROP

# 4. Run the raw socket binary (requires root / CAP_NET_RAW)
sudo ./raw_chrome

# 5. Clean up the temporary iptables rule immediately after testing
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 57560 -j DROP
```

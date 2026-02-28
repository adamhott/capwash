# capwash

A Rust command-line tool that reads legacy `.pcap` network capture files, redacts sensitive information in-place, writes a clean output `.pcap`, exports every finding as structured JSON into a confidential `sensitive/` directory, and optionally generates a networking acronym reference guide from detected protocols.

The primary use case is preparing network captures for safe sharing — between organizations, for bug reports, security research disclosure, or archival — without leaking PII, credentials, device identities, or network topology.

---

## Build & Install

**Requirements:** Rust 1.70+ (edition 2021)

```bash
cargo build --release
```

The compiled binary is at `target/release/capwash`.

---

## Obtaining and Converting a Test Capture

This tool was developed and tested using Johannes Weber's **"The Ultimate PCAP"**, a comprehensive packet capture containing 90+ network protocols and over 40,000 packets spanning years of real-world network traffic. It is an excellent resource for testing protocol detection, redaction coverage, and acronym identification.

**Download the file from:** [https://weberblog.net/the-ultimate-pcap/](https://weberblog.net/the-ultimate-pcap/)

The downloaded file is named `The Ultimate PCAP v20251206.pcapng` (or similar, depending on the version). This is a `.pcapng` file, but `capwash` requires the legacy `.pcap` format. The file also contains multiple encapsulation types (Ethernet, IEEE 802.3br mPackets, and Linux cooked-mode capture), and legacy `.pcap` only supports a single link type per file.

### Conversion Steps

You will need `tshark` (part of the Wireshark suite) and `editcap` installed. On most systems these come with Wireshark:

```bash
# Linux (Debian/Ubuntu)
sudo apt install tshark

# macOS (Homebrew)
brew install wireshark

# Windows — included with Wireshark installer from https://www.wireshark.org/download.html
```

**Step 1:** Rename the downloaded file for easier handling:

```bash
mv "The Ultimate PCAP v20251206.pcapng" capture.pcapng
```

**Step 2:** Filter to Ethernet frames only (37,634 of ~48,640 packets — this retains all the important protocol data while dropping the 802.3br mPackets and Linux cooked-mode frames that are incompatible with legacy pcap):

```bash
tshark -r capture.pcapng -w ethernet_only.pcapng -Y "frame.encap_type==1"
```

**Step 3:** Convert the filtered single-encapsulation pcapng to legacy pcap, forcing the Ethernet link type:

```bash
editcap -F pcap -T ether ethernet_only.pcapng ultimate-capture.pcap
```

**Step 4:** Verify the conversion succeeded:

```bash
capinfos ultimate-capture.pcap
```

You should see `File encapsulation: Ethernet`, a single link type, and approximately 37,000+ packets.

**Step 5:** Clean up the intermediate file:

```bash
rm ethernet_only.pcapng
```

You are now ready to use `ultimate-capture.pcap` with `capwash`.

> **Troubleshooting:** If `editcap` fails with "can't be written as a pcap file", try using `tcpdump` as an alternative for Step 3:
> ```bash
> tcpdump -r ethernet_only.pcapng -w ultimate-capture.pcap
> ```

---

## Quick Start

**Minimal run** (always-on redactions only):

```bash
cargo run --release -- -i ultimate-capture.pcap -o redacted.pcap
```

This applies all always-on redactions (MAC addresses, private IPs, ARP fields, DNS query and response records, mDNS records, DHCP fields, ICMP embedded IPs, HTTP identity headers, credentials, emails, credit cards, SSNs, UUIDs, and payload scrubbing) without requiring any flags.

---

## Maximum Redaction Command

This command enables every redaction feature, generates the acronym guide, and outputs the summary as JSON:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap \
  -o redacted.pcap \
  --all-ips \
  --strip-timestamps \
  --randomize-ports \
  --redact-tls-sni \
  --zero-tcp-timestamps \
  --normalize-ttl \
  --strip-tcp-options \
  --sensitive-dir ./sensitive \
  --acronym-csv master_networking_acronyms_advanced.csv \
  --report \
  -v
```

No custom `-p` patterns are needed for maximum redaction — all HTTP header scrubbing, DNS response record redaction, and readable payload scrubbing are now built in.

---

## What It Redacts

The tool processes packets layer by layer. Redacted bytes are replaced with `0x00` in protocol headers and payload data, preserving file structure so the output remains a valid `.pcap` readable by Wireshark and tshark. Regex-matched payload data is overwritten with `0x58` (`'X'`), and any remaining readable ASCII runs (≥6 bytes) are zeroed by the catch-all payload scrubber.

### Always-On Redactions

These run on every invocation with no flags required:

| Category | What Is Redacted | Details |
|---|---|---|
| **Ethernet MACs** | `eth.src` and `eth.dst` | Zeroed in every frame's Ethernet header |
| **ARP fields** | Sender/target MAC and IP | Parsed from ARP packet body (not just Ethernet headers) |
| **Private IPv4** | RFC-1918, loopback, link-local | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16` |
| **DNS queries** | QNAME in DNS question section | Standard DNS on UDP port 53 |
| **DNS responses** | All RR names and RDATA in Answer, Authority, and Additional sections | A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV records — hostnames, IPs, mail servers, nameservers, and SOA contact fields are all zeroed. TSIG, OPT, NSEC, RRSIG, DNSKEY, DS records are also zeroed. Unknown record types have their RDATA unconditionally zeroed. |
| **mDNS records** | Names, IPs, MACs in mDNS | UDP port 5353 — PTR, SRV, TXT, A, AAAA record names and RDATA. Catches device names, AirPlay MAC prefixes, and service advertisements |
| **DHCP fields** | Hostname, MACs, IPs in DHCP | UDP ports 67/68 — zeroes `yiaddr`, `chaddr`, Option 12 (hostname), Option 50 (requested IP), Option 54 (server ID), Option 61 (client ID/MAC) |
| **ICMP embedded IPs** | Inner IP header in ICMP errors | ICMP Type 3 (Destination Unreachable) and Type 11 (Time Exceeded) contain a copy of the original IP header — both inner `src` and `dst` IPs are redacted |
| **HTTP identity headers** | `Host`, `User-Agent`, `Server`, `Referer`, `Cookie`, `Set-Cookie`, `Accept-Language`, `X-Forwarded-For`, `X-Real-IP`, `Origin`, `Location` | Built-in regex patterns scrub HTTP headers that leak hostnames, OS fingerprints, locale, session tokens, and proxy chains |
| **HTTP credentials** | `Authorization: Basic`, `Bearer` tokens | Regex scan on TCP payloads |
| **FTP/POP3/IMAP creds** | `PASS`, `USER`, `AUTH PLAIN` commands | Cleartext protocol credential patterns |
| **Tokens & API keys** | `token=`, `api_key=`, `secret=` URL params | Regex scan on all payloads |
| **Email addresses** | RFC-5322 pattern | Any `user@domain.tld` in payloads |
| **Credit card numbers** | Luhn-validated 13–19 digit sequences | Only flagged if the number passes the Luhn checksum |
| **SSNs** | `NNN-NN-NNNN` pattern | U.S. Social Security Number format |
| **UUIDs** | Standard UUID format | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| **Payload scrubbing** | All remaining readable ASCII runs ≥6 bytes in TCP/UDP payloads | Catch-all scrubber that zeros syslog messages, FTP banners, Cisco IOS configs, certificate fields, HTTP bodies, FortiGate logs, Zabbix agent data, printer job commands, and any other surviving text after regex patterns have run |

### Flag-Gated Redactions

Enable these with their respective CLI flags:

| Flag | What It Does | Why It Matters |
|---|---|---|
| `--all-ips` | Redact **all** IPv4/IPv6 addresses, not just private | Removes public IPs that reveal which servers were contacted |
| `--strip-timestamps` | Zero all packet capture timestamps to epoch (`0`) | Prevents timeline reconstruction of user activity |
| `--randomize-ports` | XOR-randomize ephemeral ports (≥ 1024) | Hides OS TCP stack port allocation patterns |
| `--redact-tls-sni` | Zero TLS SNI hostnames in ClientHello | Removes destination hostnames from encrypted connections — critical for hiding browsing history |
| `--zero-tcp-timestamps` | Zero TCP `tsval`/`tsecr` option values | Prevents system uptime fingerprinting via TCP timestamp clock |
| `--normalize-ttl` | Set all IP TTL values to 64 (including VLAN-encapsulated packets) | Hides OS fingerprint (Windows=128, Linux=64, macOS=64) and hop-count topology |
| `--strip-tcp-options` | Replace TCP options area with NOPs (keeps MSS) | Removes Window Scale, SACK, Timestamps — all OS fingerprinting vectors |
| `--acronym-csv <PATH>` | Generate a networking acronym reference guide | Detects protocols observed in the pcap and outputs matching rows from the master CSV |

### VLAN-Encapsulated Packet Processing

Packets with 802.1Q VLAN tags (ethertype `0x8100`, which account for ~43% of traffic in a typical enterprise capture) receive full redaction treatment. The tool unwraps the VLAN tag and processes the inner IPv4 packet with all redaction functions: IP header redaction, TTL normalization, DNS/mDNS/DHCP redaction, ICMP embedded IP redaction, and full payload scanning with regex patterns and the readable ASCII scrubber. Previous versions only redacted the IP header for VLAN-tagged packets — all redaction features now apply equally regardless of encapsulation.

---

## CLI Reference

```
USAGE:
    capwash [OPTIONS] -i <INPUT> -o <OUTPUT>

OPTIONS:
    -i, --input <INPUT>              Input .pcap file path
    -o, --output <OUTPUT>            Output (redacted) .pcap file path
        --all-ips                    Redact ALL IPs (not just private RFC-1918)
        --strip-timestamps           Zero all packet capture timestamps to epoch
        --randomize-ports            XOR-randomize ephemeral ports >= 1024
        --redact-tls-sni             Zero TLS SNI hostnames in ClientHello
        --zero-tcp-timestamps        Zero TCP tsval/tsecr option values
        --normalize-ttl              Set all TTLs to 64
        --strip-tcp-options          Replace TCP fingerprinting options with NOPs
    -p, --pattern <REGEX>            Extra regex to redact from payloads (repeatable)
        --sensitive-dir <DIR>        Output directory for JSON findings [default: sensitive]
        --acronym-csv <PATH>         Path to master networking acronyms CSV
        --report                     Print JSON summary to stdout instead of plain text
    -v, --verbose                    Enable debug logging (logs go to stderr)
    -h, --help                       Print help
    -V, --version                    Print version
```

---

## Feature Flag Examples

### Redact all IP addresses (public and private)

By default, only private/RFC-1918 addresses are redacted. Use `--all-ips` to also zero public IPs, which reveal which external servers and services were contacted:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --all-ips
```

### Strip packet timestamps

Packet capture timestamps reveal exactly when network activity occurred, enabling timeline reconstruction. Zeroing them to epoch removes this information:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --strip-timestamps
```

### Randomize ephemeral ports

Sequential ephemeral port numbers (e.g., 49152, 49153, 49154) fingerprint the operating system's TCP stack port allocation algorithm. XOR-randomization obscures this pattern:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --randomize-ports
```

### Redact TLS Server Name Indication (SNI)

TLS ClientHello packets transmit the destination hostname in plaintext before encryption begins. This exposes full browsing history even on encrypted connections:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --redact-tls-sni
```

### Zero TCP timestamp options

TCP timestamps (`tsval`/`tsecr` in option kind 8) leak the system's uptime clock, allowing remote fingerprinting of when a machine was last rebooted:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --zero-tcp-timestamps
```

### Normalize TTL values

Different operating systems use different default TTL values (Windows=128, Linux/macOS=64). The observed TTL also reveals how many router hops separate the sender from the capture point. Normalizing to 64 removes both signals. This applies to both bare Ethernet frames and VLAN-encapsulated packets:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --normalize-ttl
```

### Strip TCP fingerprinting options

TCP options like Window Scale, SACK Permitted, and Timestamps form a unique OS fingerprint (used by tools like `nmap` and `p0f`). Stripping them replaces the options area with NOPs while preserving MSS so connections remain valid:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --strip-tcp-options
```

### Combine multiple flags

Flags can be freely combined. For example, to redact all IPs, hide browsing history via SNI, and prevent OS fingerprinting:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --all-ips \
  --redact-tls-sni \
  --normalize-ttl \
  --strip-tcp-options \
  --zero-tcp-timestamps
```

### Enable verbose debug logging

Use `-v` to see detailed per-packet processing information. Logs are written to stderr so they don't interfere with `--report` JSON output on stdout:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --all-ips -v
```

### Output redaction summary as JSON

Use `--report` to get machine-readable JSON output instead of the human-readable summary, useful for CI/CD pipelines or automated compliance checks. Logs go to stderr, so stdout contains clean JSON:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --all-ips --report
```

---

## Custom Pattern Examples

The `-p` / `--pattern` flag accepts any valid Rust byte-level regex. It can be repeated to add multiple patterns. These are scanned against every TCP and UDP payload. Matched bytes are overwritten with `0x58` (`'X'`), and any remaining readable ASCII ≥6 bytes is then zeroed by the built-in payload scrubber.

Note that many patterns that previously required custom `-p` flags are now built in (HTTP headers, DNS response records, payload scrubbing). Custom patterns are still useful for targeting specific application-layer data formats.

### Credentials and tokens

```bash
-p "(?i)password[=:\s]+\S+"                     # Password fields in cleartext
-p "(?i)session[_-]?id[=:\s]+[A-Za-z0-9._-]+"  # Session identifiers
```

### Personally Identifiable Information (PII)

```bash
-p "\b\d{2}/\d{2}/\d{4}\b"                                   # Dates of birth (MM/DD/YYYY)
-p "\b\d{3}[ -]?\d{3}[ -]?\d{3}\b"                           # EU national ID patterns
-p "(?i)phone[=:\s]+[+]?\d[\d\s()-]{7,}\b"                   # Phone numbers
```

### Financial data (PCI-DSS)

```bash
-p "\b[A-Z]{2}\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{2}\b"  # IBAN numbers (EU banking)
-p "(?i)cvv[=:\s]+\d{3,4}\b"                   # CVV/CVC codes
-p "(?i)routing[=:\s]+\d{9}\b"                  # US bank routing numbers (ABA)
-p "(?i)account[_-]?num[=:\s]+\d{8,17}\b"      # Bank account numbers
```

### Network identifiers in payloads

```bash
-p "\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b"   # MAC addresses in text (aa:bb:cc:dd:ee:ff)
-p "hostname[=:\s]+[A-Za-z0-9._-]+"            # Hostname fields in cleartext protocols
```

### Software license identifiers

Some applications embed unique license or seat identifiers in HTTP User-Agent strings or payload data. For example, ESET antivirus includes seat and product license IDs in update requests:

```bash
-p "SEAT [A-Za-z0-9]+"                         # ESET seat ID
-p "PLID [A-Za-z0-9-]+"                        # ESET product license ID
-p "UES Update \([^)]+\)"                      # Full ESET User-Agent string
-p "(?i)license[_-]?key[=:\s]+\S+"             # Generic license key fields
-p "(?i)serial[=:\s]+[A-Za-z0-9-]+"            # Serial number fields
-p "(?i)activation[_-]?code[=:\s]+\S+"         # Activation codes
```

### GDPR and EU-specific patterns

```bash
-p "\bDE\d{9}\b"                                # German Tax ID (Steuer-ID)
-p "\b\d{3}[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b"       # French INSEE/NIR number
-p "\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b"       # Belgian national number
-p "(?i)gdpr|dsgvo|datenschutz"                 # GDPR-related keywords in payloads
```

### Healthcare / HIPAA patterns

```bash
-p "\bMRN[=:\s]*\d{6,10}\b"                    # Medical Record Numbers
-p "\bNPI[=:\s]*\d{10}\b"                      # National Provider Identifier
-p "(?i)patient[_-]?id[=:\s]+\S+"              # Patient identifiers
-p "(?i)diagnosis|ICD-\d+"                     # Diagnostic code references
-p "(?i)HL7\|[^\r\n]+"                         # HL7 message segments
```

### Using a wrapper script for complex runs

For maximum redaction with many patterns, you can create a reusable script:

```bash
#!/bin/bash
# redact-maximum.sh — Apply all redactions with full pattern coverage
cargo run --release -- \
  -i ultimate-capture.pcap \
  -o redacted.pcap \
  --all-ips \
  --strip-timestamps \
  --randomize-ports \
  --redact-tls-sni \
  --zero-tcp-timestamps \
  --normalize-ttl \
  --strip-tcp-options \
  --acronym-csv master_networking_acronyms_advanced.csv \
  -p "(?i)password[=:\s]+\S+" \
  -p "(?i)session[_-]?id[=:\s]+[A-Za-z0-9._-]+" \
  -p "SEAT [A-Za-z0-9]+" \
  -p "PLID [A-Za-z0-9-]+" \
  -p "\bMRN[=:\s]*\d{6,10}\b" \
  --report
```

---

## Acronym Guide

When `--acronym-csv` is provided with a path to the master networking acronyms CSV file (`master_networking_acronyms_advanced.csv`), the tool performs protocol detection on every packet using real network-layer observables and generates a reference guide of all protocols observed in the capture.

### How detection works

Rather than naive string matching on raw bytes, the detector identifies protocols from actual packet-level indicators:

- **Ethertypes** — ARP (`0x0806`), VLAN/802.1Q (`0x8100`), MPLS (`0x8847`/`0x8848`), LLDP (`0x88CC`), MACsec (`0x88E5`), 802.1X (`0x888E`)
- **IP protocol numbers** — ICMP (1), IGMPv3 (2), TCP (6), UDP (17), EIGRP (88), OSPF (89), SCTP (132), ESP (50)
- **TCP/UDP port numbers** — DNS (53), DHCP (67/68), HTTP (80), Kerberos (88), NTP (123), BGP (179), SNMP (161/162), LDAP (389), HTTPS (443), RIP (520), LDP (646), NETCONF (830), HSRP (1985), BFD (3784), IPFIX (4739), mDNS (5353), OpenFlow (6653), gRPC (50051), gNMI (57400), and many more
- **Payload signatures** — TLS ClientHello → HTTPS, QUIC initial packets, HTTP method keywords (`GET`, `POST`, `HTTP`)
- **L2 destination MACs** — CDP (`01:00:0c:cc:cc:cc`), STP/RSTP (`01:80:c2:00:00:00`), LLDP (`01:80:c2:00:00:0e`), HSRP (`01:00:5e:00:00:02`)
- **Header fields** — DSCP/TOS non-zero → QoS, IPv6 routing extension header → SRv6

### Master CSV format

The `master_networking_acronyms_advanced.csv` file contains 125 networking acronym entries, each with 10 columns:

```
Acronym,FullName,Description,Category,OSILayer,IANA_Port,CiscoDocLink,PacketIdentifier,WiresharkFilter,VendorProtocol
```

For each acronym detected in the pcap, the tool copies the complete row verbatim from the master CSV into the output guide. Acronyms are deduplicated — each appears at most once, sorted alphabetically.

### Usage

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --acronym-csv master_networking_acronyms_advanced.csv
```

### Output

The guide is written to `acronym-guide/acronym-guide.csv`. For example, processing `ultimate-capture.pcap` might produce a guide containing rows for ARP, BGP, DHCP, DNS, EIGRP, HTTP, HTTPS, ICMP, IP, IS-IS, LAN, MAC, MPLS, NTP, OSPF, QoS, SNMP, STP, TCP, UDP, VLAN, and others — depending on what protocols are present in the pcap capture.

The acronym guide can be combined with any other flags:

```bash
cargo run --release -- \
  -i ultimate-capture.pcap -o redacted.pcap \
  --all-ips --redact-tls-sni --normalize-ttl \
  --acronym-csv master_networking_acronyms_advanced.csv \
  --report
```

---

## Sensitive Directory — Confidential Output

The `sensitive/` directory (or whatever path is specified with `--sensitive-dir`) contains the complete record of every piece of sensitive data that was found and redacted from the capture. **This directory should be treated as confidential and must not be shared publicly.** It contains the original values of redacted data including IP addresses, MAC addresses, hostnames, credentials, and any other PII that was discovered.

Each finding category gets its own subdirectory with a `findings.json` file. An `index.json` at the root provides a summary count per category.

The sensitive directory is intended for:

- **Audit trails** — documenting what was redacted and why, for compliance purposes
- **Forensic review** — allowing authorized personnel to examine what sensitive data existed in the original capture
- **Verification** — confirming the redaction tool found everything it should have

**Do not distribute the `sensitive/` directory with the redacted pcap.** The redacted pcap is presumed safe to share, but open it in Wireshark to confirm; the sensitive directory is not.

---

## Output Structure

After running the maximum redaction command with the acronym guide on `ultimate-capture.pcap`, the project directory looks like this:

```
.
├── Cargo.lock
├── Cargo.toml
├── master_networking_acronyms_advanced.csv
├── README.md
├── src/
│   └── main.rs
├── ultimate-capture.pcap                  # Original input (unchanged)
├── redacted.pcap                          # Redacted output
├── sensitive/                             # ⚠️  CONFIDENTIAL
│   ├── index.json
│   ├── arp_private_ips/
│   │   └── findings.json
│   ├── credentials/
│   │   └── findings.json
│   ├── credit_cards/
│   │   └── findings.json
│   ├── dhcp_fields/
│   │   └── findings.json
│   ├── dns_hostnames/
│   │   └── findings.json
│   ├── email_addresses/
│   │   └── findings.json
│   ├── ephemeral_ports/
│   │   └── findings.json
│   ├── http_headers/
│   │   └── findings.json
│   ├── icmp_embedded_ips/
│   │   └── findings.json
│   ├── ipv4_addresses/
│   │   └── findings.json
│   ├── ipv4_in_payload/
│   │   └── findings.json
│   ├── mac_addresses/
│   │   └── findings.json
│   ├── mdns_addresses/
│   │   └── findings.json
│   ├── mdns_names/
│   │   └── findings.json
│   ├── mdns_txt/
│   │   └── findings.json
│   ├── tcp_fingerprint_options/
│   │   └── findings.json
│   ├── tcp_timestamps/
│   │   └── findings.json
│   ├── tls_sni/
│   │   └── findings.json
│   ├── ttl_values/
│   │   └── findings.json
│   └── uuids/
│       └── findings.json
└── acronym-guide/                         # Created using --acronym-csv
    └── acronym-guide.csv
```

### Finding JSON Format

Each finding is a structured JSON object containing the frame number, timestamps, category, the matched value, raw packet data, and network context. All values shown below are synthetic dummy data and do not represent any real captured information:

```json
{
  "frame_number": 4217,
  "timestamp_sec": 1700000000,
  "timestamp_usec": 123456,
  "category": "dns_hostnames",
  "pattern": "dns_query_name",
  "value": "app.example-corp.internal",
  "raw_hex": "00 1a 2b 3c 4d 5e 00 6f ...",
  "raw_ascii": "..+<M^.o............",
  "context": {
    "src_mac": "00:1a:2b:3c:4d:5e",
    "dst_mac": "00:6f:7a:8b:9c:0d",
    "src_ip": "192.168.10.50",
    "dst_ip": "192.168.10.1",
    "src_port": 51234,
    "dst_port": 53,
    "protocol": "UDP"
  }
}
```

Additional examples of finding types (all values are dummy/synthetic):

**DNS response record finding:**
```json
{
  "frame_number": 4218,
  "timestamp_sec": 1700000000,
  "timestamp_usec": 123500,
  "category": "dns_hostnames",
  "pattern": "dns_ns_rdata",
  "value": "ns1.example-corp.internal",
  "raw_hex": "00 1a 2b 3c 4d 5e 00 6f ...",
  "raw_ascii": "..+<M^.o............",
  "context": {
    "src_mac": "00:6f:7a:8b:9c:0d",
    "dst_mac": "00:1a:2b:3c:4d:5e",
    "src_ip": "192.168.10.1",
    "dst_ip": "192.168.10.50",
    "src_port": 53,
    "dst_port": 51234,
    "protocol": "UDP"
  }
}
```

**HTTP header finding:**
```json
{
  "frame_number": 1516,
  "timestamp_sec": 1700000200,
  "timestamp_usec": 456789,
  "category": "http_headers",
  "pattern": "http_user_agent",
  "value": "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:26.0)",
  "raw_hex": "00 1a 2b 3c 4d 5e 00 6f ...",
  "raw_ascii": "..+<M^.o............",
  "context": {
    "src_mac": "00:1a:2b:3c:4d:5e",
    "dst_mac": "00:6f:7a:8b:9c:0d",
    "src_ip": "10.0.1.100",
    "dst_ip": "203.0.113.50",
    "src_port": 52100,
    "dst_port": 80,
    "protocol": "TCP"
  }
}
```

**MAC address finding:**
```json
{
  "frame_number": 1,
  "timestamp_sec": 1700000000,
  "timestamp_usec": 0,
  "category": "mac_addresses",
  "pattern": "eth_src_mac",
  "value": "00:1a:2b:3c:4d:5e",
  "raw_hex": "00 6f 7a 8b 9c 0d 00 1a 2b 3c 4d 5e 08 06 ...",
  "raw_ascii": ".oz...+<M^..........",
  "context": {
    "src_mac": "00:1a:2b:3c:4d:5e",
    "dst_mac": "00:6f:7a:8b:9c:0d",
    "src_ip": null,
    "dst_ip": null,
    "src_port": null,
    "dst_port": null,
    "protocol": "ARP"
  }
}
```

**TLS SNI finding:**
```json
{
  "frame_number": 8042,
  "timestamp_sec": 1700000500,
  "timestamp_usec": 789012,
  "category": "tls_sni",
  "pattern": "tls_client_hello_sni",
  "value": "api.example-service.com",
  "raw_hex": "00 1a 2b 3c 4d 5e 00 6f 7a 8b 9c 0d 08 00 ...",
  "raw_ascii": "..+<M^.oz...........",
  "context": {
    "src_mac": "00:1a:2b:3c:4d:5e",
    "dst_mac": "00:6f:7a:8b:9c:0d",
    "src_ip": "10.0.1.100",
    "dst_ip": "203.0.113.50",
    "src_port": 52100,
    "dst_port": 443,
    "protocol": "TCP"
  }
}
```

**ICMP embedded IP finding:**
```json
{
  "frame_number": 12500,
  "timestamp_sec": 1700001000,
  "timestamp_usec": 345678,
  "category": "icmp_embedded_ips",
  "pattern": "icmp_embedded_ipv4_src",
  "value": "192.168.1.100",
  "raw_hex": "00 1a 2b 3c 4d 5e 00 6f 7a 8b 9c 0d 08 00 ...",
  "raw_ascii": "..+<M^.oz...........",
  "context": {
    "src_mac": "00:1a:2b:3c:4d:5e",
    "dst_mac": "00:6f:7a:8b:9c:0d",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.1.100",
    "src_port": null,
    "dst_port": null,
    "protocol": "IPv4"
  }
}
```

**DHCP hostname finding:**
```json
{
  "frame_number": 250,
  "timestamp_sec": 1700000100,
  "timestamp_usec": 567890,
  "category": "dhcp_fields",
  "pattern": "dhcp_hostname",
  "value": "DESKTOP-ABCDEF",
  "raw_hex": "ff ff ff ff ff ff 00 1a 2b 3c 4d 5e 08 00 ...",
  "raw_ascii": "......+<M^..........",
  "context": {
    "src_mac": "00:1a:2b:3c:4d:5e",
    "dst_mac": "ff:ff:ff:ff:ff:ff",
    "src_ip": "0.0.0.0",
    "dst_ip": "255.255.255.255",
    "src_port": 68,
    "dst_port": 67,
    "protocol": "UDP"
  }
}
```

---

## Redaction Summary

The tool prints a summary after processing. Use `--report` for JSON output (stdout), or omit it for human-readable plain text. Logs always go to stderr.

```
=== Redaction Summary ===
Total packets:               37634
Packets modified:            35102
IP addresses redacted:       68450
MAC addresses redacted:      75268
ARP fields redacted:         284
DNS hostnames redacted:      4820
mDNS records redacted:       134
DHCP fields redacted:        18
ICMP embedded IPs redacted:  72
TLS SNI redacted:            85
TCP timestamps zeroed:       412
TTLs normalized:             2783
TCP options stripped:        19
HTTP headers redacted:       48
Credentials redacted:        3
Credit cards redacted:       0
SSNs redacted:               0
Emails redacted:             8
Payload bytes scrubbed:      156240
Ports randomized:            28500
Custom pattern matches:      5
─────────────────────────────────────────
Total findings logged:       174534
Acronyms detected:           22
Sensitive dir:               ./sensitive
```

---

## Verified Redaction Results

When run with all flags enabled against the Ultimate PCAP (37,634 packets), an independent audit of the output file confirms complete redaction:

| Check | Result |
|---|---|
| Source MACs zeroed | 37,634 / 37,634 (100%) ✅ |
| Destination MACs zeroed (excl. broadcast) | 100% ✅ |
| Private IPv4 src/dst remaining | 0 ✅ |
| Public IPv4 src/dst remaining | 0 ✅ |
| ARP IPs remaining | 0 ✅ |
| Timestamps | All epoch 0 ✅ |
| TTL values | All normalized to 64 ✅ |
| DNS payload readable strings | 0 ✅ |
| TCP payload readable strings (>5 chars) | 0 ✅ |
| UDP payload readable strings (>5 chars) | 0 ✅ |

The output pcap remains structurally valid and loadable in Wireshark, with protocol distribution, packet sizes, port-based traffic profiling, and encapsulation analysis fully preserved for analytical use.

---

## Processing Logic

The tool processes each packet through a deterministic pipeline in this order:

1. **Acronym detection** — If `--acronym-csv` is provided, the original (pre-redaction) bytes are inspected for protocol indicators using ethertypes, IP protocol numbers, port numbers, payload signatures, and destination MACs. Matches are accumulated in a deduplicated set across all packets.

2. **Timestamp stripping** — If `--strip-timestamps`, the packet's capture timestamp is zeroed to epoch.

3. **Ethernet MAC redaction** — Source and destination MAC addresses are always zeroed (`0x00`).

4. **Layer 2 dispatch** by ethertype:
   - `0x0806` (ARP) → Parse and zero sender/target MAC and IP from ARP body
   - `0x0800` (IPv4) → Continue to Layer 3 processing
   - `0x86DD` (IPv6) → Redact private IPv6 addresses (or all with `--all-ips`), mDNS redaction
   - `0x8100` (VLAN/802.1Q) → Unwrap tag, apply full IPv4 processing to inner packet (IP redaction, TTL normalization, DNS/mDNS/DHCP, ICMP, payload scanning)

5. **IPv4 Layer 3 processing:**
   - mDNS record redaction (always on, UDP port 5353) — names, A/AAAA/PTR/SRV/TXT RDATA
   - DHCP field redaction (always on, UDP ports 67/68) — fixed fields + options
   - DNS redaction (always on, UDP port 53) — question section QNAMEs + all Answer/Authority/Additional RR names and RDATA (A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, and all other types)
   - IP header redaction — private IPs always; all IPs with `--all-ips`
   - ICMP embedded IP redaction (always on) — inner IP headers in Type 3/4/5/11 errors
   - TTL normalization → 64 (with `--normalize-ttl`)

6. **Transport-layer processing:**
   - Port randomization (with `--randomize-ports`)
   - TCP timestamp zeroing (with `--zero-tcp-timestamps`)
   - TCP option stripping (with `--strip-tcp-options`)
   - TLS SNI redaction in ClientHello (with `--redact-tls-sni`)

7. **Payload regex scanning** — All compiled patterns (built-in + custom `-p` patterns) are applied to TCP and UDP payloads. Built-in patterns include HTTP identity headers (`Host`, `User-Agent`, `Server`, `Referer`, `Cookie`, `Set-Cookie`, `Accept-Language`, `X-Forwarded-For`, `X-Real-IP`, `Origin`, `Location`), credentials, tokens, emails, IPs-as-text, UUIDs, SSNs, and credit cards. Matched bytes are overwritten with `0x58` (`'X'`).

8. **Payload scrubbing** — After regex scanning, a catch-all scrubber zeros any remaining runs of printable ASCII ≥6 bytes in TCP and UDP payloads. This eliminates syslog messages, FTP directory listings, Cisco IOS configuration snippets, TLS certificate issuer/subject fields, FortiGate UTM logs, Zabbix agent JSON, printer job control commands, HTTP response bodies, and any other surviving readable text.

9. **Output** — The redacted packet is written to the output `.pcap`. All findings are collected and flushed to the `sensitive/` directory as categorized JSON. The acronym guide is written to `acronym-guide/acronym-guide.csv`.

---

## Known Limitations

- **Legacy `.pcap` only.** The tool does not support `.pcapng` natively. See the conversion steps above for how to convert using `tshark` and `editcap`.
- **TLS certificate subjects cannot be redacted.** TLS server certificates are transmitted in plaintext during the handshake and contain domain names. Modifying them would break the certificate chain's cryptographic signature. Mitigation: the payload scrubber zeros readable ASCII in certificate fields, and `--redact-tls-sni` removes the SNI hostname.
- **IPv6 extension header chains are not fully walked.** The tool handles the common case (next-header directly after the fixed 40-byte IPv6 header) but does not walk chains of multiple extension headers.
- **Fragmented packets** are processed individually; the tool does not reassemble IP fragments before scanning payloads.
- **pcapng multi-encapsulation files** must be filtered to a single encapsulation type before conversion. See the conversion steps above.
- **Payload scrubbing is aggressive.** The catch-all scrubber zeros all readable ASCII runs ≥6 bytes in TCP/UDP payloads. This maximizes privacy but means that some protocol-level text data (e.g., HTTP method lines, SIP headers) will also be zeroed. The pcap remains structurally valid but text-based protocol analysis of the redacted file will show zeroed payloads. For use cases where payload text must be preserved, omit the scrubber by modifying the source.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `pcap-parser` | Parse legacy pcap format (`LegacyPcapReader`) |
| `clap` | CLI argument parsing with derive macros |
| `regex` | Byte-level regex for payload scanning |
| `serde` / `serde_json` | Serialize findings and stats to JSON |
| `anyhow` | Ergonomic error handling |
| `tracing` / `tracing-subscriber` | Structured logging (writes to stderr) |
| `csv` | Read master acronym CSV and write acronym guide |
| `nom` | Parser combinator (transitive dependency of `pcap-parser`) |
| `ipnet` | IP network utilities |

---

## Test Suite

### Unit Tests

Run the built-in Rust unit tests:

```bash
cargo test
```

These cover private IPv4 classification, Luhn credit card validation, MAC address formatting, email redaction, SSN redaction, DNS name parsing (with compression pointers), mDNS A record redaction, DHCP hostname redaction, ICMP embedded IP redaction, TCP timestamp zeroing, and TTL normalization.

### Integration Test Script

`test-commands.sh` is a comprehensive integration test that runs capwash against `ultimate-capture.pcap` and verifies every feature end-to-end. It requires `ultimate-capture.pcap` and `master_networking_acronyms_advanced.csv` in the project root directory (see [Obtaining and Converting a Test Capture](#obtaining-and-converting-a-test-capture) above).

#### Setup and Execution

```bash
chmod +x test-commands.sh
./test-commands.sh
```

The script prints color-coded pass/fail results for each test and a summary at the end. It cleans up all generated files between tests so each run starts fresh.

#### What It Tests

The script runs 80+ individual checks across 15 categories:

- [ ] **Build** — debug and release compilation (`cargo build`, `cargo build --release`)
- [ ] **Unit tests** — `cargo test` passes
- [ ] **Help and version** — `--help` and `--version` flags exit cleanly
- [ ] **Minimal run** — always-on redactions produce `redacted.pcap`, `sensitive/` directory, `index.json`, and finding files for MAC addresses, DNS hostnames, HTTP headers, and IPv4 addresses
- [ ] **Individual flags** — each flag tested in isolation with output validation:
  - [ ] `--all-ips` — redacts all IP addresses (not just RFC-1918)
  - [ ] `--strip-timestamps` — normalizes packet timestamps to epoch
  - [ ] `--randomize-ports` — randomizes ephemeral ports, creates `ephemeral_ports/findings.json`
  - [ ] `--redact-tls-sni` — redacts TLS Server Name Indication, creates `tls_sni/findings.json`
  - [ ] `--zero-tcp-timestamps` — zeros TCP timestamp options, creates `tcp_timestamps/findings.json`
  - [ ] `--normalize-ttl` — normalizes TTL to 64 (including VLAN-encapsulated packets), creates `ttl_values/findings.json`
  - [ ] `--strip-tcp-options` — strips fingerprintable TCP options, creates `tcp_fingerprint_options/findings.json`
- [ ] **Acronym guide** — `--acronym-csv` generates `acronym-guide/acronym-guide.csv` with detected protocols (header + data rows)
- [ ] **Custom patterns** — `-p` flag with single regex, multiple regexes, IPv4 patterns, UUID patterns, and ESET license identifiers
- [ ] **Custom sensitive directory** — `--sensitive-dir` writes findings to a user-specified path
- [ ] **Report mode** — `--report` outputs valid JSON to stdout (validated with `jq`, `python3`, or structural check)
- [ ] **Verbose mode** — `-v` enables debug logging to stderr without errors
- [ ] **All flags combined** — every flag at once, verifies all finding categories exist including: `arp_private_ips`, `credentials`, `credit_cards`, `dhcp_fields`, `dns_hostnames`, `email_addresses`, `ephemeral_ports`, `http_headers`, `icmp_embedded_ips`, `ipv4_addresses`, `ipv4_in_payload`, `mac_addresses`, `mdns_addresses`, `mdns_names`, `mdns_txt`, `tcp_fingerprint_options`, `tcp_timestamps`, `tls_sni`, `ttl_values`, `uuids`
- [ ] **Maximum redaction** — all flags + report mode in a single invocation
- [ ] **Wireshark validation** — uses `capinfos` and `tshark` (if installed) to confirm the output is a valid pcap, all MACs are zeroed, and no private IPs remain in IP headers
- [ ] **Error handling** — missing input file, missing arguments, missing `-o` flag, and invalid acronym CSV path all exit non-zero
- [ ] **Idempotency** — redacting an already-redacted file produces valid output without errors

#### Optional Dependencies

The Wireshark validation tests require `capinfos` and `tshark`. If these are not installed, those tests are skipped gracefully. All other tests run with only Rust and standard Unix tools.

---

## Test Capture Credit

The test capture used during development is **"The Ultimate PCAP"** by Johannes Weber, available at [https://weberblog.net/the-ultimate-pcap/](https://weberblog.net/the-ultimate-pcap/). It contains 90+ different protocols and over 40,000 packets spanning captures from 2009 to 2025, making it an ideal comprehensive test file for a redaction tool targeting broad protocol coverage.

---
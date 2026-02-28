use anyhow::{Context, Result};
use clap::Parser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(author, version, about = "Redact PII, credentials, and network fingerprints from legacy .pcap captures — exports structured JSON findings and an optional protocol acronym guide.")]
struct Args {
    /// Input .pcap file
    #[arg(short, long)]
    input: PathBuf,

    /// Output (redacted) .pcap file
    #[arg(short, long)]
    output: PathBuf,

    /// Redact ALL IP addresses (not just private/RFC-1918)
    #[arg(long, default_value_t = false)]
    all_ips: bool,

    /// Normalize all packet timestamps to 0 (epoch)
    #[arg(long, default_value_t = false)]
    strip_timestamps: bool,

    /// Randomize ephemeral source/dest ports (>= 1024)
    #[arg(long, default_value_t = false)]
    randomize_ports: bool,

    /// Redact TLS SNI (Server Name Indication) from ClientHello handshakes
    #[arg(long, default_value_t = false)]
    redact_tls_sni: bool,

    /// Zero TCP timestamp option values (tsval/tsecr) to prevent uptime fingerprinting
    #[arg(long, default_value_t = false)]
    zero_tcp_timestamps: bool,

    /// Normalize all IP TTL values to 64 to prevent OS fingerprinting
    #[arg(long, default_value_t = false)]
    normalize_ttl: bool,

    /// Strip TCP options that enable OS fingerprinting (window scale, SACK, timestamps)
    #[arg(long, default_value_t = false)]
    strip_tcp_options: bool,

    /// Extra regex pattern(s) to redact from payloads (repeatable)
    #[arg(long = "pattern", short = 'p')]
    patterns: Vec<String>,

    /// Directory to write sensitive-data JSON files
    #[arg(long, default_value = "sensitive")]
    sensitive_dir: PathBuf,

    /// Print redaction summary as JSON to stdout
    #[arg(long, default_value_t = false)]
    report: bool,

    /// Enable debug logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Path to the master networking acronyms CSV file for generating an acronym guide
    #[arg(long)]
    acronym_csv: Option<PathBuf>,
}

// ─── Finding record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Finding {
    frame_number:   u64,
    timestamp_sec:  u32,
    timestamp_usec: u32,
    category:       String,
    pattern:        String,
    value:          String,
    raw_hex:        String,
    raw_ascii:      String,
    context:        FindingContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FindingContext {
    src_mac:  Option<String>,
    dst_mac:  Option<String>,
    src_ip:   Option<String>,
    dst_ip:   Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Option<String>,
}

// ─── Stats ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize)]
struct RedactionStats {
    total_packets:              u64,
    packets_modified:           u64,
    ip_addresses_redacted:      u64,
    mac_addresses_redacted:     u64,
    arp_redacted:               u64,
    dns_hostnames_redacted:     u64,
    mdns_records_redacted:      u64,
    dhcp_fields_redacted:       u64,
    icmp_embedded_ips_redacted: u64,
    tls_sni_redacted:           u64,
    tcp_timestamps_zeroed:      u64,
    ttls_normalized:            u64,
    tcp_options_stripped:       u64,
    credentials_redacted:       u64,
    credit_cards_redacted:      u64,
    ssns_redacted:              u64,
    emails_redacted:            u64,
    http_headers_redacted:      u64,
    payload_bytes_scrubbed:     u64,
    ports_randomized:           u64,
    custom_pattern_matches:     u64,
    findings_total:             u64,
    acronyms_detected:          u64,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn is_private_ipv4(a: u8, b: u8) -> bool {
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a == 127
        || (a == 169 && b == 254)
        || a == 0
}

fn is_private_ipv6(b: &[u8; 16]) -> bool {
    (b[..15].iter().all(|&x| x == 0) && b[15] == 1)
        || (b[0] & 0xfe == 0xfc)
        || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
        || (b[..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff)
}

fn fmt_mac(b: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5])
}

fn fmt_ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn fmt_ipv6(b: &[u8]) -> String {
    let mut parts = Vec::new();
    for i in (0..16).step_by(2) {
        parts.push(format!("{:02x}{:02x}", b[i], b[i+1]));
    }
    parts.join(":")
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn to_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

fn luhn_valid(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) { return false; }
    let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
        let n = d as u32;
        if i % 2 == 1 { let x = n * 2; if x > 9 { x - 9 } else { x } } else { n }
    }).sum();
    sum % 10 == 0
}

fn extract_context(raw: &[u8]) -> FindingContext {
    let mut ctx = FindingContext {
        src_mac: None, dst_mac: None,
        src_ip: None, dst_ip: None,
        src_port: None, dst_port: None,
        protocol: None,
    };
    if raw.len() < 14 { return ctx; }
    ctx.dst_mac = Some(fmt_mac(&raw[0..6]));
    ctx.src_mac = Some(fmt_mac(&raw[6..12]));
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let ip_off = match ethertype {
        0x0800 | 0x86DD => 14,
        0x8100 if raw.len() >= 18 => 18,
        0x0806 => { ctx.protocol = Some("ARP".into()); return ctx; }
        _ => return ctx,
    };
    if ethertype == 0x0800 && raw.len() >= ip_off + 20 {
        ctx.protocol = Some("IPv4".into());
        ctx.src_ip   = Some(fmt_ipv4(&raw[ip_off+12..ip_off+16]));
        ctx.dst_ip   = Some(fmt_ipv4(&raw[ip_off+16..ip_off+20]));
        let ihl    = ((raw[ip_off] & 0x0f) as usize) * 4;
        let proto  = raw[ip_off + 9];
        let t_off  = ip_off + ihl;
        match proto {
            6 if raw.len() >= t_off + 4 => {
                ctx.protocol = Some("TCP".into());
                ctx.src_port = Some(u16::from_be_bytes([raw[t_off],   raw[t_off+1]]));
                ctx.dst_port = Some(u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]));
            }
            17 if raw.len() >= t_off + 4 => {
                ctx.protocol = Some("UDP".into());
                ctx.src_port = Some(u16::from_be_bytes([raw[t_off],   raw[t_off+1]]));
                ctx.dst_port = Some(u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]));
            }
            _ => {}
        }
    } else if ethertype == 0x86DD {
        ctx.protocol = Some("IPv6".into());
    }
    ctx
}

// ─── Acronym detection ────────────────────────────────────────────────────────
//
// Protocol detection: identify protocols from real packet-level
// indicators (ethertypes, IP protocol numbers, UDP/TCP port numbers, payload
// signatures) rather than naive string matching on raw bytes.
//
// Each row in the master CSV is loaded.  Build a mapping from concrete
// network-layer observables → acronym strings.  During packet processing we
// collect a **HashSet** of matched acronyms (no duplicates).  After
// processing we write the matching rows to acronym-guide/acronym-guide.csv.

/// One row from the master CSV, kept verbatim so we can copy it to the output.
#[derive(Debug, Clone)]
struct AcronymRow {
    acronym:           String,
    raw_fields:        Vec<String>,   // all 10 columns, for verbatim output
}

/// Detects which acronyms are observed in the pcap based on packet fields.
struct AcronymDetector {
    /// Every row from the master CSV, keyed by uppercase acronym.
    rows: HashMap<String, AcronymRow>,

    // ── lookup tables built from the CSV + domain knowledge ──

    /// Ethertype → set of acronyms  (e.g. 0x0806 → ARP, 0x8100 → VLAN, 0x8847 → MPLS)
    ethertype_map: HashMap<u16, Vec<String>>,

    /// IP protocol number → set of acronyms  (e.g. 1→ICMP, 6→TCP, 17→UDP, 88→EIGRP, 89→OSPF)
    ip_proto_map: HashMap<u8, Vec<String>>,

    /// TCP or UDP port → set of acronyms  (e.g. 53→DNS, 67/68→DHCP, 80→HTTP, 443→HTTPS…)
    port_map: HashMap<u16, Vec<String>>,
}

impl AcronymDetector {
    fn load(csv_path: &Path) -> Result<Self> {
        let mut rows = HashMap::new();
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_path(csv_path)
            .with_context(|| format!("Cannot open acronym CSV {:?}", csv_path))?;

        for result in rdr.records() {
            let record = result?;
            let fields: Vec<String> = record.iter().map(|f| f.to_string()).collect();
            if fields.is_empty() { continue; }
            let acronym = fields[0].trim().to_string();
            if acronym.is_empty() { continue; }
            rows.insert(acronym.to_uppercase(), AcronymRow {
                acronym: acronym.clone(),
                raw_fields: fields,
            });
        }

        // ── Build ethertype map ──────────────────────────────────────────
        let mut ethertype_map: HashMap<u16, Vec<String>> = HashMap::new();
        // Standard ethertypes we can observe directly
        let ether_pairs: &[(u16, &str)] = &[
            (0x0806, "ARP"),
            (0x8100, "VLAN"),        // 802.1Q tag
            (0x8847, "MPLS"),        // MPLS unicast
            (0x8848, "MPLS"),        // MPLS multicast
            (0x88CC, "LLDP"),
            (0x88A8, "VLAN"),        // QinQ / PBB
            (0x88E5, "MACsec"),
            (0x8902, "LACP"),        // Slow protocols (LACP/MARKER)
            (0x893B, "VXLAN-GPE"),   // VXLAN with GPE
        ];
        for &(et, acr) in ether_pairs {
            if rows.contains_key(&acr.to_uppercase()) {
                ethertype_map.entry(et).or_default().push(acr.to_string());
            }
        }

        // ── Build IP protocol map ────────────────────────────────────────
        let mut ip_proto_map: HashMap<u8, Vec<String>> = HashMap::new();
        let proto_pairs: &[(u8, &str)] = &[
            (1,   "ICMP"),
            (2,   "IGMPv3"),
            (6,   "TCP"),
            (17,  "UDP"),
            (47,  "ERSPAN"),    // GRE (ERSPAN rides inside GRE)
            (50,  "ESP"),       // IPsec ESP
            (88,  "EIGRP"),
            (89,  "OSPF"),
            (103, "PIM-SSM"),   // PIM
            (115, "IS-IS"),     // L2TP / IS-IS over IP (rare)
            (132, "SCTP"),
        ];
        for &(p, acr) in proto_pairs {
            if rows.contains_key(&acr.to_uppercase()) {
                ip_proto_map.entry(p).or_default().push(acr.to_string());
            }
        }

        // ── Build port map ───────────────────────────────────────────────
        let mut port_map: HashMap<u16, Vec<String>> = HashMap::new();
        let port_pairs: &[(u16, &str)] = &[
            (22,    "IP"),        // SSH — general IP indicator
            (25,    "ESA"),       // SMTP / email security
            (53,    "DNS"),
            (67,    "DHCP"),
            (68,    "DHCP"),
            (80,    "HTTP"),
            (88,    "Kerberos"),
            (89,    "OSPF"),      // OSPF sometimes on well-known port
            (123,   "NTP"),
            (161,   "SNMP"),
            (162,   "SNMP"),      // SNMP trap
            (179,   "BGP"),
            (319,   "PTP"),
            (320,   "PTP"),
            (389,   "LDAP"),
            (443,   "HTTPS"),
            (520,   "RIP"),
            (646,   "LDP"),       // also GMPLS
            (830,   "NETCONF"),
            (862,   "TWAMP"),
            (1812,  "ISE"),       // RADIUS auth
            (1813,  "ISE"),       // RADIUS accounting
            (1985,  "HSRP"),
            (2152,  "GTP"),       // GTP-U
            (2123,  "GTP"),       // GTP-C
            (3222,  "GLBP"),
            (3784,  "BFD"),
            (3868,  "Diameter"),
            (4341,  "SDA"),       // LISP / SDA
            (4739,  "IPFIX"),
            (5353,  "DNS"),       // mDNS (also DNS family)
            (6653,  "OpenFlow"),
            (8472,  "OTV"),       // also VXLAN
            (12346, "SD-WAN"),
            (50051, "gRPC"),
            (57400, "gNMI"),
        ];
        for &(p, acr) in port_pairs {
            if rows.contains_key(&acr.to_uppercase()) {
                port_map.entry(p).or_default().push(acr.to_string());
            }
        }
        // LDP/GMPLS share port 646
        if rows.contains_key("GMPLS") {
            port_map.entry(646).or_default().push("GMPLS".to_string());
        }
        // LISP also on 4341
        if rows.contains_key("LISP") {
            port_map.entry(4341).or_default().push("LISP".to_string());
        }

        info!("Loaded {} acronym entries from CSV", rows.len());

        Ok(Self { rows, ethertype_map, ip_proto_map, port_map })
    }

    /// Given a single packet's raw bytes, return the set of acronym keys detected.
    fn detect(&self, raw: &[u8]) -> HashSet<String> {
        let mut found = HashSet::new();

        if raw.len() < 14 { return found; }

        let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

        // ── Always detected: Ethernet → MAC ─────────────────────────────
        found.insert("MAC".to_string());
        found.insert("LAN".to_string());

        // ── Ethertype-based detection ────────────────────────────────────
        if let Some(acrs) = self.ethertype_map.get(&ethertype) {
            for a in acrs { found.insert(a.to_uppercase()); }
        }

        // Handle 802.1Q VLAN tag — inner ethertype
        let (ip_off, real_ethertype) = if ethertype == 0x8100 && raw.len() >= 18 {
            found.insert("VLAN".to_string());
            let inner = u16::from_be_bytes([raw[16], raw[17]]);
            if let Some(acrs) = self.ethertype_map.get(&inner) {
                for a in acrs { found.insert(a.to_uppercase()); }
            }
            (18usize, inner)
        } else {
            (14usize, ethertype)
        };

        // ── 802.1X / EAPOL detection ────────────────────────────────────
        if ethertype == 0x888E {
            found.insert("802.1X".to_string());
        }

        // ── IPv4 processing ──────────────────────────────────────────────
        if real_ethertype == 0x0800 && raw.len() >= ip_off + 20 {
            found.insert("IP".to_string());

            let ihl   = ((raw[ip_off] & 0x0f) as usize) * 4;
            let proto = raw[ip_off + 9];

            // IP protocol number detection
            if let Some(acrs) = self.ip_proto_map.get(&proto) {
                for a in acrs { found.insert(a.to_uppercase()); }
            }

            // Check DSCP/TOS for QoS markings
            let tos = raw[ip_off + 1];
            if tos != 0 {
                found.insert("QOS".to_string());
            }

            let t_off = ip_off + ihl;

            // ── TCP / UDP port-based detection ───────────────────────────
            if (proto == 6 || proto == 17) && raw.len() >= t_off + 4 {
                let src_port = u16::from_be_bytes([raw[t_off], raw[t_off+1]]);
                let dst_port = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);

                for port in [src_port, dst_port] {
                    if let Some(acrs) = self.port_map.get(&port) {
                        for a in acrs { found.insert(a.to_uppercase()); }
                    }
                }

                // ── Deep payload inspection for specific signatures ──────

                let payload_off = if proto == 6 {
                    // TCP: need data offset
                    if raw.len() >= t_off + 13 {
                        let doff = ((raw[t_off + 12] >> 4) as usize) * 4;
                        t_off + doff
                    } else { raw.len() }
                } else {
                    t_off + 8  // UDP header is 8 bytes
                };

                if payload_off < raw.len() {
                    let payload = &raw[payload_off..];

                    // TLS ClientHello → HTTPS (content_type 0x16, handshake type 0x01)
                    if payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01 {
                        found.insert("HTTPS".to_string());
                    }

                    // QUIC: UDP with long-header initial packet (first bit set, version field)
                    if proto == 17 && payload.len() >= 5 && (payload[0] & 0x80) != 0 {
                        // QUIC version is at bytes 1-4; version 0 is version negotiation
                        let ver = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        if ver == 0x00000001 || ver == 0x6b3343cf || (ver & 0x0f0f0f0f) == 0x0a0a0a0a || ver == 0xff000000 | 29 || ver == 0 {
                            found.insert("QUIC".to_string());
                        }
                    }

                    // HTTP: look for method keywords at start of TCP payload
                    if proto == 6 && payload.len() >= 4 {
                        let p4 = &payload[..4.min(payload.len())];
                        if p4 == b"GET " || p4 == b"POST" || p4 == b"PUT " || p4 == b"HTTP" || p4 == b"HEAD" || p4 == b"DELE" {
                            found.insert("HTTP".to_string());
                        }
                    }

                    // CDP: dst MAC 01:00:0c:cc:cc:cc
                    if raw.len() >= 6 && raw[0..6] == [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc] {
                        found.insert("CDP".to_string());
                    }

                    // STP: dst MAC 01:80:c2:00:00:00
                    if raw.len() >= 6 && raw[0..6] == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00] {
                        found.insert("STP".to_string());
                        found.insert("RSTP".to_string());  // RSTP uses same dest
                    }
                }
            }

            // ── ICMP sub-type analysis ───────────────────────────────────
            if proto == 1 && raw.len() >= t_off + 1 {
                found.insert("ICMP".to_string());
            }
        }

        // ── IPv6 processing ──────────────────────────────────────────────
        if real_ethertype == 0x86DD && raw.len() >= ip_off + 40 {
            found.insert("IP".to_string());

            let next_header = raw[ip_off + 6];

            if let Some(acrs) = self.ip_proto_map.get(&next_header) {
                for a in acrs { found.insert(a.to_uppercase()); }
            }

            // SRv6: routing extension header (next_header == 43)
            if next_header == 43 {
                found.insert("SRV6".to_string());
            }

            // Check for UDP/TCP in IPv6
            let t_off = ip_off + 40; // simplified — doesn't walk extension headers
            if (next_header == 6 || next_header == 17) && raw.len() >= t_off + 4 {
                let src_port = u16::from_be_bytes([raw[t_off], raw[t_off+1]]);
                let dst_port = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                for port in [src_port, dst_port] {
                    if let Some(acrs) = self.port_map.get(&port) {
                        for a in acrs { found.insert(a.to_uppercase()); }
                    }
                }
            }
        }

        // ── L2 protocol detection from dst MAC alone ─────────────────────
        if raw.len() >= 6 {
            // LLDP: dst 01:80:c2:00:00:0e
            if raw[0..6] == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e] {
                found.insert("LLDP".to_string());
            }
            // CDP: dst 01:00:0c:cc:cc:cc
            if raw[0..6] == [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc] {
                found.insert("CDP".to_string());
            }
            // STP/RSTP: dst 01:80:c2:00:00:00
            if raw[0..6] == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00] {
                found.insert("STP".to_string());
                found.insert("RSTP".to_string());
            }
            // HSRP: dst 01:00:5e:00:00:02 (HSRPv1 multicast)
            if raw[0..6] == [0x01, 0x00, 0x5e, 0x00, 0x00, 0x02] {
                found.insert("HSRP".to_string());
                found.insert("FHRP".to_string());
            }
            // GLBP: dst 01:00:5e:00:00:66
            if raw[0..6] == [0x01, 0x00, 0x5e, 0x00, 0x00, 0x66] {
                found.insert("GLBP".to_string());
                found.insert("FHRP".to_string());
            }
        }

        // Only return acronyms that exist in our CSV
        found.into_iter()
            .filter(|a| self.rows.contains_key(&a.to_uppercase()))
            .collect()
    }
}

/// Write the acronym guide CSV — only rows whose acronym was detected, no duplicates.
fn write_acronym_guide(
    detected: &HashSet<String>,
    detector: &AcronymDetector,
    output_base: &Path,
    header_line: &str,
) -> Result<()> {
    let guide_dir = output_base.join("acronym-guide");
    fs::create_dir_all(&guide_dir)?;
    let guide_path = guide_dir.join("acronym-guide.csv");

    let mut wtr = csv::WriterBuilder::new().from_path(&guide_path)?;

    // Write header
    let hdr_fields: Vec<&str> = header_line.split(',').collect();
    wtr.write_record(&hdr_fields)?;

    // Collect and sort matching rows alphabetically for a clean output
    let mut matched_rows: Vec<&AcronymRow> = detected.iter()
        .filter_map(|acr| detector.rows.get(&acr.to_uppercase()))
        .collect();
    matched_rows.sort_by(|a, b| a.acronym.to_uppercase().cmp(&b.acronym.to_uppercase()));
    // Dedup by acronym (HashSet already handles this, but belt-and-suspenders)
    matched_rows.dedup_by(|a, b| a.acronym.to_uppercase() == b.acronym.to_uppercase());

    for row in &matched_rows {
        wtr.write_record(&row.raw_fields)?;
    }
    wtr.flush()?;

    info!("Wrote {} acronym entries → {:?}", matched_rows.len(), guide_path);
    Ok(())
}

/// Read the header line from the master CSV.
fn read_csv_header(csv_path: &Path) -> Result<String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(csv_path)?;
    let headers = rdr.headers()?.clone();
    Ok(headers.iter().collect::<Vec<_>>().join(","))
}

// ─── Payload redactor ─────────────────────────────────────────────────────────

struct NamedPattern { category: String, label: String, re: Regex }

struct PayloadRedactor { patterns: Vec<NamedPattern> }

impl PayloadRedactor {
    fn new(extra: &[String]) -> Result<Self> {
        let mut patterns = vec![

            NamedPattern { category: "credentials".into(),        label: "http_basic_auth".into(),       re: Regex::new(r"(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+")? },
            NamedPattern { category: "credentials".into(),        label: "bearer_token".into(),           re: Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9._\-]+")? },
            NamedPattern { category: "credentials".into(),        label: "ftp_pop3_imap_pass".into(),     re: Regex::new(r"(?i)(PASS\s+|USER\s+|AUTH\s+PLAIN\s+)(\S+)")? },
            NamedPattern { category: "credentials".into(),        label: "telnet_password".into(),        re: Regex::new(r"(?i)(password:\s*)(\S+)")? },
            NamedPattern { category: "authorization_header".into(), label: "authorization_header".into(), re: Regex::new(r"(?i)Authorization:[^\r\n]+")? },
            NamedPattern { category: "tokens".into(),             label: "token_param".into(),            re: Regex::new(r"(?i)token=[A-Za-z0-9._\-]+")? },
            NamedPattern { category: "api_keys".into(),           label: "api_key_param".into(),          re: Regex::new(r"(?i)api[_\-]?key[=:\s]+[A-Za-z0-9._\-]+")? },
            NamedPattern { category: "secrets".into(),            label: "secret_param".into(),           re: Regex::new(r"(?i)secret[=:\s]+[A-Za-z0-9._\-]+")? },
            NamedPattern { category: "email_addresses".into(),    label: "email".into(),                  re: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")? },
            NamedPattern { category: "ipv4_in_payload".into(),    label: "ipv4_address".into(),           re: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")? },
            NamedPattern { category: "uuids".into(),              label: "uuid".into(),                   re: Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")? },
            NamedPattern { category: "passport_numbers".into(),   label: "passport".into(),               re: Regex::new(r"\b[A-Z]{2}\d{6}[A-Z]?\b")? },
            NamedPattern { category: "ssn".into(),                label: "ssn".into(),                    re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")? },
            NamedPattern { category: "credit_cards".into(),       label: "credit_card_candidate".into(),  re: Regex::new(r"\b\d[\d\- ]{11,17}\d\b")? },
            NamedPattern { category: "http_headers".into(),       label: "http_host".into(),              re: Regex::new(r"(?i)Host:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_user_agent".into(),        re: Regex::new(r"(?i)User-Agent:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_server".into(),            re: Regex::new(r"(?i)Server:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_referer".into(),           re: Regex::new(r"(?i)Referer:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_cookie".into(),            re: Regex::new(r"(?i)Cookie:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_set_cookie".into(),        re: Regex::new(r"(?i)Set-Cookie:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_accept_language".into(),   re: Regex::new(r"(?i)Accept-Language:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_x_forwarded_for".into(),   re: Regex::new(r"(?i)X-Forwarded-For:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_x_real_ip".into(),         re: Regex::new(r"(?i)X-Real-IP:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_origin".into(),            re: Regex::new(r"(?i)Origin:\s*[^\r\n]+")? },
            NamedPattern { category: "http_headers".into(),       label: "http_location".into(),          re: Regex::new(r"(?i)Location:\s*[^\r\n]+")? }
        ];
        for p in extra {
            let safe_label = p.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_')
                .take(40).collect::<String>();
            patterns.push(NamedPattern {
                category: "custom_patterns".into(),
                label: safe_label,
                re: Regex::new(p).with_context(|| format!("Invalid pattern: {p}"))?,
            });
        }
        Ok(Self { patterns })
    }

    fn scan_and_redact(
        &self, data: &mut Vec<u8>,
        frame_num: u64, ts_sec: u32, ts_usec: u32,
        raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>,
    ) {
        let ctx = extract_context(raw_orig);
        for np in &self.patterns {
            let is_cc = np.label == "credit_card_candidate";
            let matches: Vec<(usize, usize, String)> = np.re
                .find_iter(data.as_slice())
                .filter_map(|m| {
                    if is_cc {
                        let digits: Vec<u8> = data[m.start()..m.end()]
                            .iter().filter(|&&b| b.is_ascii_digit()).map(|&b| b - b'0').collect();
                        if !luhn_valid(&digits) { return None; }
                    }
                    Some((m.start(), m.end(), String::from_utf8_lossy(&data[m.start()..m.end()]).to_string()))
                })
                .collect();
            if matches.is_empty() { continue; }
            let category = if is_cc { "credit_cards".to_string() } else { np.category.clone() };
            for (_s, _e, val) in &matches {
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: category.clone(), pattern: np.label.clone(), value: val.clone(),
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
            }
            let count = matches.len() as u64;
            match np.category.as_str() {
                "credentials" | "authorization_header" => stats.credentials_redacted += count,
                "email_addresses" => stats.emails_redacted += count,
                "ssn"             => stats.ssns_redacted += count,
                "credit_cards"    => stats.credit_cards_redacted += count,
                "http_headers"    => stats.http_headers_redacted += count,
                _                 => stats.custom_pattern_matches += count,
            }
            stats.findings_total += count;
            for (s, e, _) in matches { data[s..e].fill(b'X'); }
        }
    }
}

// ─── Payload scrubbing — zero all readable ASCII runs ─────────────────────────
//
// After regex-based redaction, any remaining runs of printable ASCII (≥6 bytes)
// in TCP/UDP payloads are zeroed. This catches syslog messages, FTP banners,
// Cisco IOS configs, certificate fields, HTTP bodies, and anything else the
// targeted patterns missed.
//
// Preserves: binary protocol data, short tokens (<6 bytes), already-zeroed regions.

fn scrub_readable_payload(
    data: &mut [u8],
    stats: &mut RedactionStats,
) {
    let min_run = 6;
    let mut i = 0;
    while i < data.len() {
        if data[i] >= 0x20 && data[i] <= 0x7e {
            let start = i;
            while i < data.len() && data[i] >= 0x20 && data[i] <= 0x7e {
                i += 1;
            }
            let run_len = i - start;
            if run_len >= min_run {
                // Don't count runs that are already all 'X' (already redacted by regex)
                let all_x = data[start..i].iter().all(|&b| b == b'X');
                if !all_x {
                    data[start..i].fill(0);
                    stats.payload_bytes_scrubbed += run_len as u64;
                }
            }
        } else {
            i += 1;
        }
    }
}

// ─── MAC / ARP / DNS ──────────────────────────────────────────────────────────

fn redact_mac(data: &mut [u8], off: usize, frame_num: u64, ts_sec: u32, ts_usec: u32,
    label: &str, raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < off + 6 { return; }
    let mac = fmt_mac(&data[off..off+6]);
    if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" { return; }
    findings.push(Finding {
        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
        category: "mac_addresses".into(), pattern: label.into(), value: mac,
        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig),
        context: extract_context(raw_orig),
    });
    data[off..off+6].fill(0);
    stats.mac_addresses_redacted += 1;
    stats.findings_total += 1;
}

fn redact_ethernet_macs(data: &mut Vec<u8>, frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < 12 { return; }
    redact_mac(data, 0, frame_num, ts_sec, ts_usec, "eth_dst_mac", raw_orig, stats, findings);
    redact_mac(data, 6, frame_num, ts_sec, ts_usec, "eth_src_mac", raw_orig, stats, findings);
}

fn redact_arp(data: &mut Vec<u8>, frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    let base = 14;
    if data.len() < base + 28 { return; }
    let ctx = extract_context(raw_orig);

    let sha_off = base + 8;
    let sha = fmt_mac(&data[sha_off..sha_off+6]);
    if sha != "00:00:00:00:00:00" {
        findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "mac_addresses".into(), pattern: "arp_sender_mac".into(), value: sha,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
        data[sha_off..sha_off+6].fill(0);
        stats.mac_addresses_redacted += 1; stats.findings_total += 1;
    }

    let spa_off = base + 14;
    let spa = fmt_ipv4(&data[spa_off..spa_off+4]);
    findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
        category: "arp_private_ips".into(), pattern: "arp_sender_ip".into(), value: spa,
        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
    data[spa_off..spa_off+4].fill(0);
    stats.arp_redacted += 1; stats.findings_total += 1;

    let tha_off = base + 18;
    let tha = fmt_mac(&data[tha_off..tha_off+6]);
    if tha != "00:00:00:00:00:00" {
        findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "mac_addresses".into(), pattern: "arp_target_mac".into(), value: tha,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
        data[tha_off..tha_off+6].fill(0);
        stats.mac_addresses_redacted += 1; stats.findings_total += 1;
    }

    let tpa_off = base + 24;
    let tpa = fmt_ipv4(&data[tpa_off..tpa_off+4]);
    findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
        category: "arp_private_ips".into(), pattern: "arp_target_ip".into(), value: tpa,
        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
    data[tpa_off..tpa_off+4].fill(0);
    stats.arp_redacted += 1; stats.findings_total += 1;
}

fn redact_dns(data: &mut Vec<u8>, ip_off: usize, frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < ip_off + 20 { return; }
    let ihl    = ((data[ip_off] & 0x0f) as usize) * 4;
    let proto  = data[ip_off + 9];
    if proto != 17 { return; }
    let udp_off = ip_off + ihl;
    if data.len() < udp_off + 8 { return; }
    let src_port = u16::from_be_bytes([data[udp_off],   data[udp_off+1]]);
    let dst_port = u16::from_be_bytes([data[udp_off+2], data[udp_off+3]]);
    if dst_port != 53 && src_port != 53 { return; }
    let dns_off = udp_off + 8;
    if data.len() < dns_off + 12 { return; }

    let qdcount = u16::from_be_bytes([data[dns_off+4],  data[dns_off+5]])  as usize;
    let ancount = u16::from_be_bytes([data[dns_off+6],  data[dns_off+7]])  as usize;
    let nscount = u16::from_be_bytes([data[dns_off+8],  data[dns_off+9]])  as usize;
    let arcount = u16::from_be_bytes([data[dns_off+10], data[dns_off+11]]) as usize;

    let ctx = extract_context(raw_orig);
    let mut pos = dns_off + 12;

    // ── Question section ──
    for _ in 0..qdcount {
        if pos >= data.len() { return; }
        let (hostname, consumed) = read_dns_name(data, dns_off, pos);
        if !hostname.is_empty() {
            findings.push(Finding {
                frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                category: "dns_hostnames".into(), pattern: "dns_query_name".into(), value: hostname,
                raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
            });
            zero_dns_name_inline(data, pos);
            stats.dns_hostnames_redacted += 1;
            stats.findings_total += 1;
        }
        pos += consumed;
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() { return; }
    }

    // ── Answer + Authority + Additional sections ──
    let total_rr = ancount + nscount + arcount;
    for _ in 0..total_rr {
        if pos >= data.len() { return; }

        // Read and redact the RR owner name
        let (rr_name, name_consumed) = read_dns_name(data, dns_off, pos);
        if !rr_name.is_empty() {
            findings.push(Finding {
                frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                category: "dns_hostnames".into(), pattern: "dns_rr_name".into(), value: rr_name,
                raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
            });
            zero_dns_name_inline(data, pos);
            stats.dns_hostnames_redacted += 1;
            stats.findings_total += 1;
        }
        pos += name_consumed;

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if pos + 10 > data.len() { return; }
        let rr_type  = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        let rdata_off = pos + 10;
        let rdata_end = rdata_off + rdlength;

        if rdata_end > data.len() { return; }

        match rr_type {
            // A record (IPv4) — 4 bytes
            1 if rdlength == 4 => {
                let ip = fmt_ipv4(&data[rdata_off..rdata_off + 4]);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dns_hostnames".into(), pattern: "dns_a_rdata".into(), value: ip,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[rdata_off..rdata_off + 4].fill(0);
                stats.dns_hostnames_redacted += 1;
                stats.findings_total += 1;
            }
            // AAAA record (IPv6) — 16 bytes
            28 if rdlength == 16 => {
                let ip = fmt_ipv6(&data[rdata_off..rdata_off + 16]);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dns_hostnames".into(), pattern: "dns_aaaa_rdata".into(), value: ip,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[rdata_off..rdata_off + 16].fill(0);
                stats.dns_hostnames_redacted += 1;
                stats.findings_total += 1;
            }
            // NS record — RDATA is a single DNS name
            2 => {
                let (ns_name, _) = read_dns_name(data, dns_off, rdata_off);
                if !ns_name.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "dns_hostnames".into(), pattern: "dns_ns_rdata".into(), value: ns_name,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[rdata_off..rdata_end].fill(0);
                    stats.dns_hostnames_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // CNAME record — RDATA is a single DNS name
            5 => {
                let (cname, _) = read_dns_name(data, dns_off, rdata_off);
                if !cname.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "dns_hostnames".into(), pattern: "dns_cname_rdata".into(), value: cname,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[rdata_off..rdata_end].fill(0);
                    stats.dns_hostnames_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // SOA record — MNAME + RNAME + 5x u32
            6 if rdlength > 0 => {
                let (mname, mname_consumed) = read_dns_name(data, dns_off, rdata_off);
                let rname_off = rdata_off + mname_consumed;
                let (rname, _) = if rname_off < rdata_end {
                    read_dns_name(data, dns_off, rname_off)
                } else {
                    (String::new(), 0)
                };
                let soa_val = if rname.is_empty() { mname.clone() } else { format!("{} {}", mname, rname) };
                if !soa_val.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "dns_hostnames".into(), pattern: "dns_soa_rdata".into(), value: soa_val,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[rdata_off..rdata_end].fill(0);
                    stats.dns_hostnames_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // PTR record — RDATA is a single DNS name
            12 => {
                let (ptr_name, _) = read_dns_name(data, dns_off, rdata_off);
                if !ptr_name.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "dns_hostnames".into(), pattern: "dns_ptr_rdata".into(), value: ptr_name,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[rdata_off..rdata_end].fill(0);
                    stats.dns_hostnames_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // MX record — preference(2) + exchange name
            15 if rdlength > 2 => {
                let exchange_off = rdata_off + 2;
                let (mx_name, _) = read_dns_name(data, dns_off, exchange_off);
                if !mx_name.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "dns_hostnames".into(), pattern: "dns_mx_rdata".into(), value: mx_name,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[rdata_off..rdata_end].fill(0);
                    stats.dns_hostnames_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // TXT record — SPF, DKIM, DMARC, verification tokens
            16 if rdlength > 0 => {
                let txt_val = String::from_utf8_lossy(&data[rdata_off..rdata_end]).to_string();
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dns_hostnames".into(), pattern: "dns_txt_rdata".into(), value: txt_val,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[rdata_off..rdata_end].fill(0);
                stats.dns_hostnames_redacted += 1;
                stats.findings_total += 1;
            }
            // SRV record — priority(2) + weight(2) + port(2) + target name
            33 if rdlength > 6 => {
                let target_off = rdata_off + 6;
                let (srv_target, _) = read_dns_name(data, dns_off, target_off);
                if !srv_target.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "dns_hostnames".into(), pattern: "dns_srv_rdata".into(), value: srv_target,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[rdata_off..rdata_end].fill(0);
                    stats.dns_hostnames_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // TSIG (250), OPT (41), NSEC (47), RRSIG (46), DNSKEY (48), DS (43)
            41 | 43 | 46 | 47 | 48 | 250 => {
                if rdlength > 0 {
                    data[rdata_off..rdata_end].fill(0);
                }
            }
            // Any other type — zero all RDATA unconditionally
            _ => {
                if rdlength > 0 {
                    data[rdata_off..rdata_end].fill(0);
                }
            }
        }

        pos = rdata_end;
    }
}

// ─── mDNS redaction  ───────────────────────────────────────
//
// mDNS = UDP port 5353, standard DNS wire format.
// Unlike regular DNS, mDNS responses carry Answer/Authority/Additional sections
// containing PTR, SRV, TXT, A, AAAA records with device names, MACs, and IPs.
//
// We process ALL sections (Questions + Answers + Authority + Additional) and
// zero Name fields + RDATA for PTR/SRV/TXT/A/AAAA record types.

/// Read a DNS name starting at `pos` within `data`, returning the decoded name
/// string and the number of bytes consumed from the current position.
/// Handles both label sequences and compression pointers (0xC0).
fn read_dns_name(data: &[u8], dns_start: usize, start_pos: usize) -> (String, usize) {
    let mut parts: Vec<String> = Vec::new();
    let mut pos = start_pos;
    let mut bytes_consumed = 0;
    let mut followed_pointer = false;

    loop {
        if pos >= data.len() { break; }
        let len = data[pos] as usize;

        if len == 0 {
            // End of name
            if !followed_pointer { bytes_consumed += 1; }
            break;
        }

        if len & 0xc0 == 0xc0 {
            // Compression pointer
            if pos + 1 >= data.len() { break; }
            if !followed_pointer {
                bytes_consumed += 2;
                followed_pointer = true;
            }
            let ptr = (((len & 0x3f) as usize) << 8) | (data[pos + 1] as usize);
            pos = dns_start + ptr;
            continue;
        }

        if pos + 1 + len > data.len() { break; }
        parts.push(String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]).to_string());
        if !followed_pointer { bytes_consumed += 1 + len; }
        pos += 1 + len;
    }

    (parts.join("."), bytes_consumed)
}

/// Zero out a DNS name in the wire data starting at `pos`.
/// Only zeros inline labels (not compressed pointer targets, since those
/// may be shared with other records).
fn zero_dns_name_inline(data: &mut [u8], start_pos: usize) -> usize {
    let mut pos = start_pos;
    let mut bytes_zeroed = 0;

    loop {
        if pos >= data.len() { break; }
        let len = data[pos] as usize;

        if len == 0 {
            data[pos] = 0;
            bytes_zeroed += 1;
            break;
        }

        if len & 0xc0 == 0xc0 {
            // Compression pointer — zero the two pointer bytes
            if pos + 1 < data.len() {
                data[pos] = 0;
                data[pos + 1] = 0;
                bytes_zeroed += 2;
            }
            break;
        }

        if pos + 1 + len > data.len() { break; }
        // Zero the length byte and label data
        for i in pos..pos + 1 + len {
            data[i] = 0;
        }
        bytes_zeroed += 1 + len;
        pos += 1 + len;
    }

    bytes_zeroed
}

fn redact_mdns(
    data: &mut Vec<u8>, ip_off: usize, is_ipv6: bool,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>,
) {
    // Determine UDP header offset
    let udp_off = if is_ipv6 {
        ip_off + 40 // Fixed IPv6 header (no extension header handling for now)
    } else {
        if data.len() < ip_off + 20 { return; }
        let ihl = ((data[ip_off] & 0x0f) as usize) * 4;
        ip_off + ihl
    };

    if data.len() < udp_off + 8 { return; }
    let src_port = u16::from_be_bytes([data[udp_off], data[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_off + 2], data[udp_off + 3]]);

    // mDNS uses port 5353
    if src_port != 5353 && dst_port != 5353 { return; }

    let dns_off = udp_off + 8;
    if data.len() < dns_off + 12 { return; }

    let qdcount = u16::from_be_bytes([data[dns_off + 4], data[dns_off + 5]]) as usize;
    let ancount = u16::from_be_bytes([data[dns_off + 6], data[dns_off + 7]]) as usize;
    let nscount = u16::from_be_bytes([data[dns_off + 8], data[dns_off + 9]]) as usize;
    let arcount = u16::from_be_bytes([data[dns_off + 10], data[dns_off + 11]]) as usize;

    let ctx = extract_context(raw_orig);
    let mut pos = dns_off + 12;

    // ── Process Question section ──
    for _ in 0..qdcount {
        if pos >= data.len() { return; }
        let (name, consumed) = read_dns_name(data, dns_off, pos);
        if !name.is_empty() {
            findings.push(Finding {
                frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                category: "mdns_names".into(), pattern: "mdns_question_name".into(), value: name,
                raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
            });
            zero_dns_name_inline(data, pos);
            stats.mdns_records_redacted += 1;
            stats.findings_total += 1;
        }
        pos += consumed;
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() { return; }
    }

    // ── Process Answer + Authority + Additional sections ──
    let total_rr = ancount + nscount + arcount;
    for _ in 0..total_rr {
        if pos >= data.len() { return; }

        // Read and redact the RR name
        let (name, name_consumed) = read_dns_name(data, dns_off, pos);
        if !name.is_empty() {
            findings.push(Finding {
                frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                category: "mdns_names".into(), pattern: "mdns_rr_name".into(), value: name.clone(),
                raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
            });
            zero_dns_name_inline(data, pos);
            stats.mdns_records_redacted += 1;
            stats.findings_total += 1;
        }
        pos += name_consumed;

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if pos + 10 > data.len() { return; }
        let rr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        let rdata_off = pos + 10;
        let rdata_end = rdata_off + rdlength;

        if rdata_end > data.len() { return; }

        match rr_type {
            // A record (IPv4 address) — 4 bytes
            1 if rdlength == 4 => {
                let ip = fmt_ipv4(&data[rdata_off..rdata_off + 4]);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "mdns_addresses".into(), pattern: "mdns_a_record".into(), value: ip,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[rdata_off..rdata_off + 4].fill(0);
                stats.mdns_records_redacted += 1;
                stats.findings_total += 1;
            }
            // AAAA record (IPv6 address) — 16 bytes
            28 if rdlength == 16 => {
                let ip = fmt_ipv6(&data[rdata_off..rdata_off + 16]);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "mdns_addresses".into(), pattern: "mdns_aaaa_record".into(), value: ip,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[rdata_off..rdata_off + 16].fill(0);
                stats.mdns_records_redacted += 1;
                stats.findings_total += 1;
            }
            // PTR record — RDATA is a DNS name (pointer target)
            12 => {
                let (ptr_name, _) = read_dns_name(data, dns_off, rdata_off);
                if !ptr_name.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "mdns_names".into(), pattern: "mdns_ptr_rdata".into(), value: ptr_name,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    zero_dns_name_inline(data, rdata_off);
                    stats.mdns_records_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // SRV record — priority(2) + weight(2) + port(2) + target name
            33 if rdlength > 6 => {
                let target_off = rdata_off + 6;
                let (srv_target, _) = read_dns_name(data, dns_off, target_off);
                if !srv_target.is_empty() {
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "mdns_names".into(), pattern: "mdns_srv_target".into(), value: srv_target,
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    zero_dns_name_inline(data, target_off);
                    stats.mdns_records_redacted += 1;
                    stats.findings_total += 1;
                }
            }
            // TXT record — zero entire RDATA (may contain MACs, UUIDs, device metadata)
            16 if rdlength > 0 => {
                let txt_val = String::from_utf8_lossy(&data[rdata_off..rdata_end]).to_string();
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "mdns_txt".into(), pattern: "mdns_txt_rdata".into(), value: txt_val,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[rdata_off..rdata_end].fill(0);
                stats.mdns_records_redacted += 1;
                stats.findings_total += 1;
            }
            // NSEC (47) and OPT (41) — zero RDATA to remove any metadata
            41 | 47 => {
                data[rdata_off..rdata_end].fill(0);
            }
            _ => {}
        }

        pos = rdata_end;
    }
}

// ─── DHCP redaction  ────────────────────────────────────────
//
// DHCP = UDP ports 67 (server) / 68 (client).
// Fixed header is 236 bytes, followed by 4-byte magic cookie (0x63825363),
// then variable-length options.
//
// Fixed fields to zero (offsets relative to UDP payload / DHCP start):
//   ciaddr: bytes 12-15    (client IP address)
//   yiaddr: bytes 16-19    (your/assigned IP)
//   siaddr: bytes 20-23    (server IP)
//   giaddr: bytes 24-27    (relay agent IP)
//   chaddr: bytes 28-43    (client hardware address, first 6 = MAC)
//
// Options to redact (after byte 240):
//   Option 12 = Host Name (zero the string)
//   Option 50 = Requested IP Address (4 bytes)
//   Option 54 = Server Identifier (4 bytes)
//   Option 61 = Client Identifier (type byte + MAC/DUID)

fn redact_dhcp(
    data: &mut Vec<u8>, ip_off: usize,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>,
) {
    if data.len() < ip_off + 20 { return; }
    let ihl = ((data[ip_off] & 0x0f) as usize) * 4;
    let udp_off = ip_off + ihl;
    if data.len() < udp_off + 8 { return; }

    let src_port = u16::from_be_bytes([data[udp_off], data[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_off + 2], data[udp_off + 3]]);

    // DHCP uses ports 67 (server) and 68 (client)
    if (src_port != 67 && src_port != 68) && (dst_port != 67 && dst_port != 68) { return; }

    let dhcp_off = udp_off + 8; // Start of DHCP payload
    // Need at least 240 bytes for fixed header + magic cookie
    if data.len() < dhcp_off + 240 { return; }

    // Verify DHCP magic cookie at offset 236
    let cookie = u32::from_be_bytes([
        data[dhcp_off + 236], data[dhcp_off + 237],
        data[dhcp_off + 238], data[dhcp_off + 239],
    ]);
    if cookie != 0x63825363 { return; }

    let ctx = extract_context(raw_orig);

    // ── Redact fixed fields ──

    // ciaddr (client IP) at offset 12
    let ci_off = dhcp_off + 12;
    if data[ci_off..ci_off + 4] != [0, 0, 0, 0] {
        let ip = fmt_ipv4(&data[ci_off..ci_off + 4]);
        findings.push(Finding {
            frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "dhcp_fields".into(), pattern: "dhcp_ciaddr".into(), value: ip,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
        });
        data[ci_off..ci_off + 4].fill(0);
        stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
    }

    // yiaddr (assigned IP) at offset 16
    let yi_off = dhcp_off + 16;
    if data[yi_off..yi_off + 4] != [0, 0, 0, 0] {
        let ip = fmt_ipv4(&data[yi_off..yi_off + 4]);
        findings.push(Finding {
            frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "dhcp_fields".into(), pattern: "dhcp_yiaddr".into(), value: ip,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
        });
        data[yi_off..yi_off + 4].fill(0);
        stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
    }

    // siaddr (server IP) at offset 20
    let si_off = dhcp_off + 20;
    if data[si_off..si_off + 4] != [0, 0, 0, 0] {
        let ip = fmt_ipv4(&data[si_off..si_off + 4]);
        findings.push(Finding {
            frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "dhcp_fields".into(), pattern: "dhcp_siaddr".into(), value: ip,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
        });
        data[si_off..si_off + 4].fill(0);
        stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
    }

    // giaddr (relay agent IP) at offset 24
    let gi_off = dhcp_off + 24;
    if data[gi_off..gi_off + 4] != [0, 0, 0, 0] {
        let ip = fmt_ipv4(&data[gi_off..gi_off + 4]);
        findings.push(Finding {
            frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "dhcp_fields".into(), pattern: "dhcp_giaddr".into(), value: ip,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
        });
        data[gi_off..gi_off + 4].fill(0);
        stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
    }

    // chaddr (client hardware address) at offset 28, 16 bytes (first 6 = MAC)
    let ch_off = dhcp_off + 28;
    let mac = fmt_mac(&data[ch_off..ch_off + 6]);
    if mac != "00:00:00:00:00:00" {
        findings.push(Finding {
            frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "dhcp_fields".into(), pattern: "dhcp_chaddr".into(), value: mac,
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
        });
        data[ch_off..ch_off + 16].fill(0); // Zero all 16 bytes of chaddr field
        stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
    }

    // ── Redact DHCP options ──
    let mut opt_pos = dhcp_off + 240; // Past magic cookie

    while opt_pos < data.len() {
        let opt_code = data[opt_pos];

        // End option
        if opt_code == 255 { break; }
        // Pad option
        if opt_code == 0 { opt_pos += 1; continue; }

        if opt_pos + 1 >= data.len() { break; }
        let opt_len = data[opt_pos + 1] as usize;
        let opt_data_start = opt_pos + 2;
        let opt_data_end = opt_data_start + opt_len;

        if opt_data_end > data.len() { break; }

        match opt_code {
            // Option 12: Host Name
            12 => {
                let hostname = String::from_utf8_lossy(&data[opt_data_start..opt_data_end]).to_string();
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dhcp_fields".into(), pattern: "dhcp_hostname".into(), value: hostname,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[opt_data_start..opt_data_end].fill(0);
                stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
            }
            // Option 50: Requested IP Address (4 bytes)
            50 if opt_len == 4 => {
                let ip = fmt_ipv4(&data[opt_data_start..opt_data_start + 4]);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dhcp_fields".into(), pattern: "dhcp_requested_ip".into(), value: ip,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[opt_data_start..opt_data_start + 4].fill(0);
                stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
            }
            // Option 54: Server Identifier (4 bytes)
            54 if opt_len == 4 => {
                let ip = fmt_ipv4(&data[opt_data_start..opt_data_start + 4]);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dhcp_fields".into(), pattern: "dhcp_server_id".into(), value: ip,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[opt_data_start..opt_data_start + 4].fill(0);
                stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
            }
            // Option 61: Client Identifier (type byte + identifier)
            61 if opt_len >= 2 => {
                let id_bytes = &data[opt_data_start..opt_data_end];
                let val = to_hex(id_bytes);
                findings.push(Finding {
                    frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                    category: "dhcp_fields".into(), pattern: "dhcp_client_id".into(), value: val,
                    raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                });
                data[opt_data_start..opt_data_end].fill(0);
                stats.dhcp_fields_redacted += 1; stats.findings_total += 1;
            }
            _ => {}
        }

        opt_pos = opt_data_end;
    }
}

// ─── ICMP embedded IP redaction ────────────────────────────
//
// ICMP error messages (Type 3 = Destination Unreachable, Type 11 = Time Exceeded)
// include the original IP header + first 8 bytes of transport as payload per RFC 792.
// The outer IP header gets redacted, but the embedded copy does not.
//
// Layout: [outer IP header] [ICMP header (8 bytes)] [embedded IP header + 8 bytes]
// The embedded IP header starts at: ip_off + outer_ihl + 8

fn redact_icmp_embedded_ip(
    data: &mut [u8], ip_off: usize, all_ips: bool,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>,
) {
    if data.len() < ip_off + 20 { return; }
    let ihl = ((data[ip_off] & 0x0f) as usize) * 4;
    let proto = data[ip_off + 9];

    // Only process ICMP (protocol 1)
    if proto != 1 { return; }

    let icmp_off = ip_off + ihl;
    if data.len() < icmp_off + 8 { return; }

    let icmp_type = data[icmp_off];

    // Only process error types that embed the original IP header:
    // Type 3 = Destination Unreachable
    // Type 11 = Time Exceeded
    // Type 4 = Source Quench (deprecated but may appear)
    // Type 5 = Redirect
    if icmp_type != 3 && icmp_type != 11 && icmp_type != 4 && icmp_type != 5 { return; }

    // The embedded IP header starts after the 8-byte ICMP header
    let embedded_ip_off = icmp_off + 8;
    if data.len() < embedded_ip_off + 20 { return; }

    // Verify it looks like an IPv4 header (version nibble = 4)
    let version = (data[embedded_ip_off] >> 4) & 0x0f;
    if version != 4 { return; }

    let ctx = extract_context(raw_orig);

    // Redact src and dst IPs in the embedded header
    for (label, off) in [
        ("icmp_embedded_ipv4_src", embedded_ip_off + 12),
        ("icmp_embedded_ipv4_dst", embedded_ip_off + 16),
    ] {
        if data.len() < off + 4 { continue; }
        let (a, b) = (data[off], data[off + 1]);
        if is_private_ipv4(a, b) || all_ips {
            let ip = fmt_ipv4(&data[off..off + 4]);
            findings.push(Finding {
                frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                category: "icmp_embedded_ips".into(), pattern: label.into(), value: ip,
                raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
            });
            data[off..off + 4].fill(0);
            stats.icmp_embedded_ips_redacted += 1;
            stats.findings_total += 1;
        }
    }
}

// ─── TLS SNI redaction ────────────────────────────────────────────────────────

fn redact_tls_sni(
    data: &mut Vec<u8>,
    tcp_payload_off: usize,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>,
) {
    let p = tcp_payload_off;

    if data.len() < p + 44 { return; }

    if data[p] != 0x16 { return; }
    let record_len = u16::from_be_bytes([data[p+3], data[p+4]]) as usize;
    if data.len() < p + 5 + record_len { return; }
    if data[p+5] != 0x01 { return; }

    let mut pos = p + 5 + 4 + 2 + 32;

    if pos >= data.len() { return; }
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;

    if pos + 2 > data.len() { return; }
    let cs_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > data.len() { return; }
    let cm_len = data[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > data.len() { return; }
    let ext_total = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(data.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos+1]]);
        let ext_len  = u16::from_be_bytes([data[pos+2], data[pos+3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            if pos + 5 <= ext_end {
                let name_type = data[pos + 2];
                if name_type == 0x00 {
                    let name_len = u16::from_be_bytes([data[pos+3], data[pos+4]]) as usize;
                    let name_start = pos + 5;
                    let name_end   = name_start + name_len;
                    if name_end <= data.len() {
                        let sni = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
                        let ctx = extract_context(raw_orig);
                        findings.push(Finding {
                            frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                            category: "tls_sni".into(), pattern: "tls_client_hello_sni".into(),
                            value: sni,
                            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig),
                            context: ctx,
                        });
                        data[name_start..name_end].fill(0);
                        stats.tls_sni_redacted += 1;
                        stats.findings_total += 1;
                    }
                }
            }
            pos += ext_len;
        } else {
            pos += ext_len;
        }
    }
}

// ─── TCP options processing ───────────────────────────────────────────────────

fn zero_tcp_option_timestamps(data: &mut Vec<u8>, tcp_off: usize,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>) -> bool
{
    if data.len() < tcp_off + 13 { return false; }
    let data_offset = ((data[tcp_off + 12] >> 4) as usize) * 4;
    if data_offset < 20 || data.len() < tcp_off + data_offset { return false; }

    let opts_start = tcp_off + 20;
    let opts_end   = tcp_off + data_offset;
    let mut pos    = opts_start;
    let mut found  = false;
    let ctx = extract_context(raw_orig);

    while pos < opts_end {
        match data[pos] {
            0 => break,
            1 => { pos += 1; }
            kind => {
                if pos + 1 >= opts_end { break; }
                let len = data[pos + 1] as usize;
                if len < 2 || pos + len > opts_end { break; }
                if kind == 8 && len == 10 {
                    let tsval = u32::from_be_bytes([data[pos+2],data[pos+3],data[pos+4],data[pos+5]]);
                    let tsecr = u32::from_be_bytes([data[pos+6],data[pos+7],data[pos+8],data[pos+9]]);
                    findings.push(Finding {
                        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                        category: "tcp_timestamps".into(), pattern: "tcp_tsval_tsecr".into(),
                        value: format!("tsval={} tsecr={}", tsval, tsecr),
                        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone(),
                    });
                    data[pos+2..pos+10].fill(0);
                    stats.tcp_timestamps_zeroed += 1;
                    stats.findings_total += 1;
                    found = true;
                }
                pos += len;
            }
        }
    }
    found
}

fn strip_tcp_fingerprint_options(data: &mut Vec<u8>, tcp_off: usize,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < tcp_off + 13 { return; }
    let data_offset = ((data[tcp_off + 12] >> 4) as usize) * 4;
    if data_offset <= 20 || data.len() < tcp_off + data_offset { return; }

    let opts_start = tcp_off + 20;
    let opts_end   = tcp_off + data_offset;

    let mut opts_found: Vec<String> = Vec::new();
    let mut pos = opts_start;
    while pos < opts_end {
        match data[pos] {
            0 => break,
            1 => { pos += 1; }
            kind => {
                if pos + 1 >= opts_end { break; }
                let len = data[pos + 1] as usize;
                if len < 2 || pos + len > opts_end { break; }
                match kind {
                    2 => opts_found.push("MSS".into()),
                    3 => opts_found.push("WinScale".into()),
                    4 => opts_found.push("SACK_permitted".into()),
                    5 => opts_found.push("SACK".into()),
                    8 => opts_found.push("Timestamps".into()),
                    _ => opts_found.push(format!("opt_{}", kind)),
                }
                pos += len;
            }
        }
    }

    if opts_found.len() <= 1 { return; }

    let ctx = extract_context(raw_orig);
    findings.push(Finding {
        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
        category: "tcp_fingerprint_options".into(), pattern: "tcp_options".into(),
        value: opts_found.join(", "),
        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx,
    });

    data[opts_start..opts_end].fill(0x01);
    stats.tcp_options_stripped += 1;
    stats.findings_total += 1;
}

// ─── IP header redaction ──────────────────────────────────────────────────────

fn redact_ipv4_header(data: &mut [u8], ip_off: usize, all_ips: bool,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < ip_off + 20 { return; }
    let ihl = ((data[ip_off] & 0x0f) as usize) * 4;
    if ihl < 20 { return; }
    let ctx = extract_context(raw_orig);
    for (label, off) in [("ipv4_src", ip_off+12), ("ipv4_dst", ip_off+16)] {
        if data.len() < off + 4 { continue; }
        let (a, b) = (data[off], data[off+1]);
        if is_private_ipv4(a, b) || all_ips {
            let ip = fmt_ipv4(&data[off..off+4]);
            findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
                category: "ipv4_addresses".into(), pattern: label.into(), value: ip,
                raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
            data[off..off+4].fill(0);
            stats.ip_addresses_redacted += 1; stats.findings_total += 1;
        }
    }
}

fn normalize_ttl(data: &mut Vec<u8>, ip_off: usize,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < ip_off + 9 { return; }
    let ttl = data[ip_off + 8];
    if ttl == 64 { return; }
    let ctx = extract_context(raw_orig);
    findings.push(Finding {
        frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
        category: "ttl_values".into(), pattern: "ip_ttl".into(),
        value: format!("{}", ttl),
        raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx,
    });
    data[ip_off + 8] = 64;
    stats.ttls_normalized += 1;
    stats.findings_total += 1;
}

fn redact_ipv6_header(data: &mut [u8], ip_off: usize, all_ips: bool, stats: &mut RedactionStats) {
    if data.len() < ip_off + 40 { return; }
    for off in [ip_off+8, ip_off+24] {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[off..off+16]);
        if is_private_ipv6(&addr) || all_ips {
            data[off..off+16].fill(0);
            stats.ip_addresses_redacted += 1;
        }
    }
}

// ─── Port randomization ───────────────────────────────────────────────────────

fn pseudo_random_port(p: u16) -> u16 {
    let s = p ^ 0xA5C3;
    if s < 1024 { s + 1024 } else { s }
}

fn randomize_ports(data: &mut Vec<u8>, ip_off: usize,
    frame_num: u64, ts_sec: u32, ts_usec: u32,
    raw_orig: &[u8], stats: &mut RedactionStats, findings: &mut Vec<Finding>)
{
    if data.len() < ip_off + 20 { return; }
    let ihl   = ((data[ip_off] & 0x0f) as usize) * 4;
    let proto = data[ip_off + 9];
    let t_off = ip_off + ihl;
    if proto != 6 && proto != 17 { return; }
    if data.len() < t_off + 4 { return; }
    let src = u16::from_be_bytes([data[t_off],   data[t_off+1]]);
    let dst = u16::from_be_bytes([data[t_off+2], data[t_off+3]]);
    let ctx = extract_context(raw_orig);

    if src >= 1024 {
        findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "ephemeral_ports".into(), pattern: "src_port".into(), value: format!("{}", src),
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
        let b = pseudo_random_port(src).to_be_bytes();
        data[t_off] = b[0]; data[t_off+1] = b[1];
        stats.ports_randomized += 1; stats.findings_total += 1;
    }
    if dst >= 1024 {
        findings.push(Finding { frame_number: frame_num, timestamp_sec: ts_sec, timestamp_usec: ts_usec,
            category: "ephemeral_ports".into(), pattern: "dst_port".into(), value: format!("{}", dst),
            raw_hex: to_hex(raw_orig), raw_ascii: to_ascii(raw_orig), context: ctx.clone() });
        let b = pseudo_random_port(dst).to_be_bytes();
        data[t_off+2] = b[0]; data[t_off+3] = b[1];
        stats.ports_randomized += 1; stats.findings_total += 1;
    }
}

// ─── Per-packet processing ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn process_packet(
    raw: &mut Vec<u8>,
    redactor:             &PayloadRedactor,
    all_ips:              bool,
    strip_timestamps:     bool,
    randomize_ports_flag: bool,
    redact_tls_sni_flag:  bool,
    zero_tcp_ts_flag:     bool,
    normalize_ttl_flag:   bool,
    strip_tcp_opts_flag:  bool,
    frame_num:            u64,
    ts_sec:               &mut u32,
    ts_usec:              &mut u32,
    stats:                &mut RedactionStats,
    findings:             &mut Vec<Finding>,
    acronym_detector:     Option<&AcronymDetector>,
    detected_acronyms:    &mut HashSet<String>,
) -> bool {
    let raw_orig = raw.clone();
    let before   = raw.clone();

    // ── Acronym detection (before any redaction modifies the bytes) ───
    if let Some(detector) = acronym_detector {
        let found = detector.detect(&raw_orig);
        for acr in found {
            detected_acronyms.insert(acr);
        }
    }

    if strip_timestamps { *ts_sec = 0; *ts_usec = 0; }

    if raw.len() < 14 { return false; }

    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

    // Always: redact Ethernet MACs
    redact_ethernet_macs(raw, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);

    match ethertype {
        0x0806 => {
            redact_arp(raw, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
        }
        0x0800 => {
            let ip_off = 14;

            // mDNS redaction (always on) — must run BEFORE regular DNS to handle port 5353
            redact_mdns(raw, ip_off, false, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);

            // DHCP redaction (always on)
            redact_dhcp(raw, ip_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);

            // DNS hostname redaction (always on)
            redact_dns(raw, ip_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);

            // IP header
            redact_ipv4_header(raw, ip_off, all_ips, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);

            // ICMP embedded IP redaction (always on)
            redact_icmp_embedded_ip(raw, ip_off, all_ips, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);

            // TTL normalization
            if normalize_ttl_flag {
                normalize_ttl(raw, ip_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
            }
            // Transport-layer processing
            if raw.len() > ip_off + 9 {
                let ihl   = ((raw[ip_off] & 0x0f) as usize) * 4;
                let proto = raw[ip_off + 9];
                let t_off = ip_off + ihl;

                if proto == 6 && raw.len() >= t_off + 20 {
                    // TCP
                    let doff = ((raw[t_off + 12] >> 4) as usize) * 4;
                    let payload_off = t_off + doff;

                    if randomize_ports_flag {
                        randomize_ports(raw, ip_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                    }
                    if zero_tcp_ts_flag {
                        zero_tcp_option_timestamps(raw, t_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                    }
                    if strip_tcp_opts_flag {
                        strip_tcp_fingerprint_options(raw, t_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                    }
                    if redact_tls_sni_flag && payload_off < raw.len() {
                        redact_tls_sni(raw, payload_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                    }
                    // Payload regex scan + readable ASCII scrub
                    if payload_off < raw.len() {
                        let mut payload = raw[payload_off..].to_vec();
                        redactor.scan_and_redact(&mut payload, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                        scrub_readable_payload(&mut payload, stats);
                        raw[payload_off..].copy_from_slice(&payload);
                    }
                } else if proto == 17 {
                    // UDP payload
                    let payload_off = t_off + 8;
                    if randomize_ports_flag {
                        randomize_ports(raw, ip_off, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                    }
                    if payload_off < raw.len() {
                        let mut payload = raw[payload_off..].to_vec();
                        redactor.scan_and_redact(&mut payload, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                        scrub_readable_payload(&mut payload, stats);
                        raw[payload_off..].copy_from_slice(&payload);
                    }
                }
            }
        }
        0x86DD => {
            let ip_off = 14;
            // mDNS over IPv6 (always on)
            redact_mdns(raw, ip_off, true, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
            redact_ipv6_header(raw, ip_off, all_ips, stats);
        }
        0x8100 if raw.len() >= 18 => {
            let inner = u16::from_be_bytes([raw[16], raw[17]]);
            if inner == 0x0800 {
                redact_ipv4_header(raw, 18, all_ips, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                if normalize_ttl_flag {
                    normalize_ttl(raw, 18, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                }
                // DNS/DHCP/mDNS/ICMP redaction for VLAN-encapsulated IPv4
                redact_mdns(raw, 18, false, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                redact_dhcp(raw, 18, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                redact_dns(raw, 18, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                redact_icmp_embedded_ip(raw, 18, all_ips, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                // Payload scanning for VLAN-encapsulated packets
                if raw.len() > 18 + 9 {
                    let ihl   = ((raw[18] & 0x0f) as usize) * 4;
                    let proto = raw[18 + 9];
                    let t_off = 18 + ihl;
                    if proto == 6 && raw.len() >= t_off + 20 {
                        let doff = ((raw[t_off + 12] >> 4) as usize) * 4;
                        let payload_off = t_off + doff;
                        if payload_off < raw.len() {
                            let mut payload = raw[payload_off..].to_vec();
                            redactor.scan_and_redact(&mut payload, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                            scrub_readable_payload(&mut payload, stats);
                            raw[payload_off..].copy_from_slice(&payload);
                        }
                    } else if proto == 17 && raw.len() >= t_off + 8 {
                        let payload_off = t_off + 8;
                        if payload_off < raw.len() {
                            let mut payload = raw[payload_off..].to_vec();
                            redactor.scan_and_redact(&mut payload, frame_num, *ts_sec, *ts_usec, &raw_orig, stats, findings);
                            scrub_readable_payload(&mut payload, stats);
                            raw[payload_off..].copy_from_slice(&payload);
                        }
                    }
                }
            }
        }
        _ => {}
    }

    *raw != before
}

// ─── pcap I/O ─────────────────────────────────────────────────────────────────

fn write_global_header(w: &mut impl Write, hdr: &PcapHeader) -> Result<()> {
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    w.write_all(&hdr.version_major.to_le_bytes())?;
    w.write_all(&hdr.version_minor.to_le_bytes())?;
    w.write_all(&hdr.thiszone.to_le_bytes())?;
    w.write_all(&hdr.sigfigs.to_le_bytes())?;
    w.write_all(&hdr.snaplen.to_le_bytes())?;
    w.write_all(&(hdr.network.0 as u32).to_le_bytes())?;
    Ok(())
}

fn write_packet(w: &mut impl Write, ts_sec: u32, ts_usec: u32, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    w.write_all(&ts_sec.to_le_bytes())?;
    w.write_all(&ts_usec.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(data)?;
    Ok(())
}

// ─── Sensitive directory ──────────────────────────────────────────────────────

fn write_sensitive_dir(findings: &[Finding], sensitive_dir: &Path) -> Result<()> {
    fs::create_dir_all(sensitive_dir)?;
    let mut by_category: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings { by_category.entry(f.category.clone()).or_default().push(f); }
    for (category, items) in &by_category {
        let cat_dir = sensitive_dir.join(category);
        fs::create_dir_all(&cat_dir)?;
        let out_path = cat_dir.join("findings.json");
        fs::write(&out_path, serde_json::to_string_pretty(items)?)?;
        info!("  wrote {} findings → {}", items.len(), out_path.display());
    }
    let index: HashMap<&String, usize> = by_category.iter().map(|(k, v)| (k, v.len())).collect();
    fs::write(sensitive_dir.join("index.json"), serde_json::to_string_pretty(&index)?)?;
    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();
    let log_level = if args.verbose { tracing::Level::DEBUG } else { tracing::Level::INFO };
    tracing_subscriber::fmt().with_max_level(log_level).with_target(false).with_writer(std::io::stderr).init();

    info!("Opening {:?}", args.input);
    let file     = File::open(&args.input).with_context(|| format!("Cannot open {:?}", args.input))?;
    let out_file = File::create(&args.output).with_context(|| format!("Cannot create {:?}", args.output))?;
    let mut writer   = BufWriter::new(out_file);
    let redactor     = PayloadRedactor::new(&args.patterns)?;
    let mut stats    = RedactionStats::default();
    let mut findings: Vec<Finding> = Vec::new();
    let mut detected_acronyms: HashSet<String> = HashSet::new();

    // Load acronym CSV if provided
    let acronym_detector = if let Some(ref csv_path) = args.acronym_csv {
        Some(AcronymDetector::load(csv_path)?)
    } else {
        None
    };
    let csv_header = if let Some(ref csv_path) = args.acronym_csv {
        Some(read_csv_header(csv_path)?)
    } else {
        None
    };
    let mut reader   = LegacyPcapReader::new(65536, BufReader::new(file))
                           .context("Not a valid legacy pcap file")?;
    let mut header_written = false;
    let mut frame_num: u64 = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let pkt: Option<(u32, u32, Vec<u8>)> = match block {
                    PcapBlockOwned::LegacyHeader(ref hdr) => {
                        if !header_written {
                            write_global_header(&mut writer, hdr)?;
                            header_written = true;
                        }
                        None
                    }
                    PcapBlockOwned::Legacy(ref pkt) => {
                        frame_num += 1;
                        Some((pkt.ts_sec, pkt.ts_usec, pkt.data.to_vec()))
                    }
                    PcapBlockOwned::NG(_) => {
                        warn!("pcapng block encountered – only legacy pcap supported");
                        None
                    }
                };
                drop(block);
                reader.consume(offset);

                if let Some((mut ts_sec, mut ts_usec, mut raw)) = pkt {
                    stats.total_packets += 1;
                    let modified = process_packet(
                        &mut raw, &redactor,
                        args.all_ips, args.strip_timestamps, args.randomize_ports,
                        args.redact_tls_sni, args.zero_tcp_timestamps,
                        args.normalize_ttl, args.strip_tcp_options,
                        frame_num, &mut ts_sec, &mut ts_usec,
                        &mut stats, &mut findings,
                        acronym_detector.as_ref(),
                        &mut detected_acronyms,
                    );
                    if modified { stats.packets_modified += 1; }
                    write_packet(&mut writer, ts_sec, ts_usec, &raw)?;
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                if let Err(e) = reader.refill() {
                    return Err(anyhow::anyhow!("refill error: {:?}", e));
                }
            }
            Err(e) => return Err(anyhow::anyhow!("pcap parse error: {:?}", e)),
        }
    }

    writer.flush()?;
    info!("Writing sensitive data directory → {:?}", args.sensitive_dir);
    write_sensitive_dir(&findings, &args.sensitive_dir)?;

    // Write acronym guide if CSV was provided
    if let (Some(detector), Some(ref header)) = (&acronym_detector, &csv_header) {
        stats.acronyms_detected = detected_acronyms.len() as u64;
        let output_base = args.output.parent().unwrap_or(Path::new("."));
        write_acronym_guide(&detected_acronyms, detector, output_base, header)?;
        info!("Acronyms detected: {}", detected_acronyms.len());
    }

    if args.report {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        println!("=== Redaction Summary ===");
        println!("Total packets:               {}", stats.total_packets);
        println!("Packets modified:            {}", stats.packets_modified);
        println!("IP addresses redacted:       {}", stats.ip_addresses_redacted);
        println!("MAC addresses redacted:      {}", stats.mac_addresses_redacted);
        println!("ARP fields redacted:         {}", stats.arp_redacted);
        println!("DNS hostnames redacted:      {}", stats.dns_hostnames_redacted);
        println!("mDNS records redacted:       {}", stats.mdns_records_redacted);
        println!("DHCP fields redacted:        {}", stats.dhcp_fields_redacted);
        println!("ICMP embedded IPs redacted:  {}", stats.icmp_embedded_ips_redacted);
        println!("TLS SNI redacted:            {}", stats.tls_sni_redacted);
        println!("TCP timestamps zeroed:       {}", stats.tcp_timestamps_zeroed);
        println!("TTLs normalized:             {}", stats.ttls_normalized);
        println!("TCP options stripped:        {}", stats.tcp_options_stripped);
        println!("HTTP headers redacted:       {}", stats.http_headers_redacted);
        println!("Credentials redacted:        {}", stats.credentials_redacted);
        println!("Credit cards redacted:       {}", stats.credit_cards_redacted);
        println!("SSNs redacted:               {}", stats.ssns_redacted);
        println!("Emails redacted:             {}", stats.emails_redacted);
        println!("Payload bytes scrubbed:      {}", stats.payload_bytes_scrubbed);
        println!("Ports randomized:            {}", stats.ports_randomized);
        println!("Custom pattern matches:      {}", stats.custom_pattern_matches);
        println!("─────────────────────────────────────────");
        println!("Total findings logged:       {}", stats.findings_total);
        println!("Acronyms detected:           {}", stats.acronyms_detected);
        println!("Sensitive dir:               {}", args.sensitive_dir.display());
    }

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn private_ipv4()    { assert!(is_private_ipv4(10,0)); assert!(is_private_ipv4(192,168)); assert!(!is_private_ipv4(8,8)); }
    #[test] fn luhn_valid_visa() { let d: Vec<u8> = "4532015112830366".chars().map(|c|c as u8-b'0').collect(); assert!(luhn_valid(&d)); }
    #[test] fn luhn_invalid()    { let d: Vec<u8> = "1234567890123456".chars().map(|c|c as u8-b'0').collect(); assert!(!luhn_valid(&d)); }
    #[test] fn mac_format()      { assert_eq!(fmt_mac(&[0x76,0x9b,0xe8,0xe1,0xde,0x43]), "76:9b:e8:e1:de:43"); }

    #[test]
    fn redact_email_payload() {
        let r = PayloadRedactor::new(&[]).unwrap();
        let mut s = RedactionStats::default(); let mut f = Vec::new();
        let mut p = b"From: alice@example.com\r\n".to_vec(); let orig = p.clone();
        r.scan_and_redact(&mut p, 1, 0, 0, &orig, &mut s, &mut f);
        assert_eq!(s.emails_redacted, 1);
        assert_eq!(f[0].category, "email_addresses");
    }

    #[test]
    fn redact_ssn() {
        let r = PayloadRedactor::new(&[]).unwrap();
        let mut s = RedactionStats::default(); let mut f = Vec::new();
        let mut p = b"SSN: 123-45-6789".to_vec(); let orig = p.clone();
        r.scan_and_redact(&mut p, 1, 0, 0, &orig, &mut s, &mut f);
        assert_eq!(s.ssns_redacted, 1);
    }

    #[test]
    fn tcp_timestamp_zeroing() {
        let mut data = vec![0u8; 60];
        data[12] = 0x80;
        data[20] = 0x01; data[21] = 0x01;
        data[22] = 0x08; data[23] = 0x0a;
        data[24] = 0x00; data[25] = 0x01; data[26] = 0x02; data[27] = 0x03;
        data[28] = 0x04; data[29] = 0x05; data[30] = 0x06; data[31] = 0x07;

        let raw_orig = data.clone();
        let mut stats = RedactionStats::default();
        let mut findings = Vec::new();
        zero_tcp_option_timestamps(&mut data, 0, 1, 0, 0, &raw_orig, &mut stats, &mut findings);
        assert_eq!(stats.tcp_timestamps_zeroed, 1);
        assert_eq!(&data[24..32], &[0u8; 8]);
        assert_eq!(findings[0].category, "tcp_timestamps");
    }

    #[test]
    fn ttl_normalization() {
        let mut data = vec![0u8; 20];
        data[0] = 0x45;
        data[8] = 128;
        let raw_orig = data.clone();
        let mut stats = RedactionStats::default();
        let mut findings = Vec::new();
        normalize_ttl(&mut data, 0, 1, 0, 0, &raw_orig, &mut stats, &mut findings);
        assert_eq!(data[8], 64);
        assert_eq!(stats.ttls_normalized, 1);
        assert_eq!(findings[0].value, "128");
    }

    // ── mDNS redaction test ──

    #[test]
    fn mdns_a_record_redaction() {
        // Build a minimal mDNS response packet:
        // Ethernet (14) + IPv4 header (20) + UDP header (8) + DNS header (12) + 1 Answer RR
        //
        // The answer RR has:
        //   Name: \x04test\x05local\x00  (test.local)
        //   Type: A (1)
        //   Class: 0x8001 (cache flush + IN)
        //   TTL: 120
        //   RDLENGTH: 4
        //   RDATA: 192.168.1.100

        let mut pkt = vec![0u8; 14 + 20 + 8 + 12 + 12 + 10 + 4]; // = 80 bytes

        // Ethernet header (14 bytes) — ethertype = IPv4
        pkt[12] = 0x08; pkt[13] = 0x00;

        // IPv4 header (20 bytes) at offset 14
        pkt[14] = 0x45; // version=4, IHL=5
        pkt[14 + 9] = 17; // protocol = UDP

        // UDP header (8 bytes) at offset 34
        // src_port = 5353
        pkt[34] = 0x14; pkt[35] = 0xe9;
        // dst_port = 5353
        pkt[36] = 0x14; pkt[37] = 0xe9;

        // DNS header (12 bytes) at offset 42
        // qdcount = 0, ancount = 1, nscount = 0, arcount = 0
        pkt[42 + 6] = 0; pkt[42 + 7] = 1; // ancount = 1

        // Answer RR at offset 54
        let rr_off = 54;
        // Name: \x04test\x05local\x00 = 12 bytes
        pkt[rr_off]     = 4;
        pkt[rr_off + 1] = b't'; pkt[rr_off + 2] = b'e'; pkt[rr_off + 3] = b's'; pkt[rr_off + 4] = b't';
        pkt[rr_off + 5] = 5;
        pkt[rr_off + 6] = b'l'; pkt[rr_off + 7] = b'o'; pkt[rr_off + 8] = b'c'; pkt[rr_off + 9] = b'a'; pkt[rr_off + 10] = b'l';
        pkt[rr_off + 11] = 0; // end of name

        // TYPE = A (1)
        pkt[rr_off + 12] = 0; pkt[rr_off + 13] = 1;
        // CLASS = 0x8001
        pkt[rr_off + 14] = 0x80; pkt[rr_off + 15] = 0x01;
        // TTL = 120
        pkt[rr_off + 16] = 0; pkt[rr_off + 17] = 0; pkt[rr_off + 18] = 0; pkt[rr_off + 19] = 120;
        // RDLENGTH = 4
        pkt[rr_off + 20] = 0; pkt[rr_off + 21] = 4;
        // RDATA = 192.168.1.100
        pkt[rr_off + 22] = 192; pkt[rr_off + 23] = 168; pkt[rr_off + 24] = 1; pkt[rr_off + 25] = 100;

        let raw_orig = pkt.clone();
        let mut stats = RedactionStats::default();
        let mut findings = Vec::new();

        redact_mdns(&mut pkt, 14, false, 1, 0, 0, &raw_orig, &mut stats, &mut findings);

        // Should have redacted the RR name + A record IP
        assert!(stats.mdns_records_redacted >= 2,
            "Expected at least 2 mDNS redactions, got {}", stats.mdns_records_redacted);

        // The A record IP should be zeroed
        assert_eq!(&pkt[rr_off + 22..rr_off + 26], &[0, 0, 0, 0],
            "A record IP was not zeroed");

        // Check finding categories
        let name_findings: Vec<_> = findings.iter().filter(|f| f.category == "mdns_names").collect();
        let addr_findings: Vec<_> = findings.iter().filter(|f| f.category == "mdns_addresses").collect();
        assert!(!name_findings.is_empty(), "Should have mDNS name findings");
        assert!(!addr_findings.is_empty(), "Should have mDNS address findings");
        assert_eq!(addr_findings[0].value, "192.168.1.100");
    }

    // ── DHCP redaction test ──

    #[test]
    fn dhcp_hostname_redaction() {
        // Build a minimal DHCP Discover packet:
        // Ethernet (14) + IPv4 (20) + UDP (8) + DHCP (240 fixed + options)
        let mut pkt = vec![0u8; 14 + 20 + 8 + 240 + 20]; // enough for fixed + some options

        // Ethernet header — ethertype = IPv4
        pkt[12] = 0x08; pkt[13] = 0x00;

        // IPv4 header at offset 14
        pkt[14] = 0x45; // version=4, IHL=5
        pkt[14 + 9] = 17; // protocol = UDP

        // UDP header at offset 34
        // src_port = 68 (client)
        pkt[34] = 0; pkt[35] = 68;
        // dst_port = 67 (server)
        pkt[36] = 0; pkt[37] = 67;

        let dhcp_off = 42; // UDP payload start

        // yiaddr at offset 16 within DHCP = 192.168.1.50
        pkt[dhcp_off + 16] = 192; pkt[dhcp_off + 17] = 168;
        pkt[dhcp_off + 18] = 1;   pkt[dhcp_off + 19] = 50;

        // chaddr at offset 28 within DHCP = AA:BB:CC:DD:EE:FF
        pkt[dhcp_off + 28] = 0xAA; pkt[dhcp_off + 29] = 0xBB; pkt[dhcp_off + 30] = 0xCC;
        pkt[dhcp_off + 31] = 0xDD; pkt[dhcp_off + 32] = 0xEE; pkt[dhcp_off + 33] = 0xFF;

        // Magic cookie at offset 236
        pkt[dhcp_off + 236] = 0x63; pkt[dhcp_off + 237] = 0x82;
        pkt[dhcp_off + 238] = 0x53; pkt[dhcp_off + 239] = 0x63;

        // Option 12 (hostname) starting at offset 240
        let opt_off = dhcp_off + 240;
        pkt[opt_off] = 12;      // option code
        pkt[opt_off + 1] = 7;   // length
        // "MyHost\0" but without null, just "MyHostX"
        pkt[opt_off + 2] = b'M'; pkt[opt_off + 3] = b'y'; pkt[opt_off + 4] = b'H';
        pkt[opt_off + 5] = b'o'; pkt[opt_off + 6] = b's'; pkt[opt_off + 7] = b't';
        pkt[opt_off + 8] = b'!';

        // End option
        pkt[opt_off + 9] = 255;

        let raw_orig = pkt.clone();
        let mut stats = RedactionStats::default();
        let mut findings = Vec::new();

        redact_dhcp(&mut pkt, 14, 1, 0, 0, &raw_orig, &mut stats, &mut findings);

        // yiaddr should be zeroed
        assert_eq!(&pkt[dhcp_off + 16..dhcp_off + 20], &[0, 0, 0, 0],
            "yiaddr not zeroed");

        // chaddr should be zeroed
        assert_eq!(&pkt[dhcp_off + 28..dhcp_off + 34], &[0; 6],
            "chaddr MAC not zeroed");

        // Option 12 hostname should be zeroed
        assert_eq!(&pkt[opt_off + 2..opt_off + 9], &[0; 7],
            "hostname option not zeroed");

        // Check stats
        assert!(stats.dhcp_fields_redacted >= 3,
            "Expected at least 3 DHCP redactions (yiaddr + chaddr + hostname), got {}", stats.dhcp_fields_redacted);

        // Check findings
        let hostname_findings: Vec<_> = findings.iter()
            .filter(|f| f.pattern == "dhcp_hostname").collect();
        assert_eq!(hostname_findings.len(), 1);
        assert_eq!(hostname_findings[0].value, "MyHost!");
    }

    // ── ICMP embedded IP redaction test ──

    #[test]
    fn icmp_embedded_ip_redaction() {
        // Build a minimal ICMP Destination Unreachable packet:
        // Ethernet (14) + Outer IPv4 (20) + ICMP header (8) + Embedded IPv4 (20) + 8 transport bytes
        let mut pkt = vec![0u8; 14 + 20 + 8 + 20 + 8]; // = 70 bytes

        // Ethernet header — ethertype = IPv4
        pkt[12] = 0x08; pkt[13] = 0x00;

        // Outer IPv4 header at offset 14
        pkt[14] = 0x45; // version=4, IHL=5
        pkt[14 + 9] = 1; // protocol = ICMP
        // Outer src IP = 10.0.0.1
        pkt[14 + 12] = 10; pkt[14 + 13] = 0; pkt[14 + 14] = 0; pkt[14 + 15] = 1;
        // Outer dst IP = 10.0.0.2
        pkt[14 + 16] = 10; pkt[14 + 17] = 0; pkt[14 + 18] = 0; pkt[14 + 19] = 2;

        // ICMP header at offset 34
        pkt[34] = 3; // Type = Destination Unreachable
        pkt[35] = 1; // Code = Host Unreachable

        // Embedded IPv4 header at offset 42
        pkt[42] = 0x45; // version=4, IHL=5
        // Embedded src IP = 192.168.1.8
        pkt[42 + 12] = 192; pkt[42 + 13] = 168; pkt[42 + 14] = 1; pkt[42 + 15] = 8;
        // Embedded dst IP = 192.168.1.1
        pkt[42 + 16] = 192; pkt[42 + 17] = 168; pkt[42 + 18] = 1; pkt[42 + 19] = 1;

        let raw_orig = pkt.clone();
        let mut stats = RedactionStats::default();
        let mut findings = Vec::new();

        redact_icmp_embedded_ip(&mut pkt, 14, false, 1, 0, 0, &raw_orig, &mut stats, &mut findings);

        // Embedded src IP should be zeroed
        assert_eq!(&pkt[42 + 12..42 + 16], &[0, 0, 0, 0],
            "Embedded src IP not zeroed");
        // Embedded dst IP should be zeroed
        assert_eq!(&pkt[42 + 16..42 + 20], &[0, 0, 0, 0],
            "Embedded dst IP not zeroed");

        assert_eq!(stats.icmp_embedded_ips_redacted, 2);

        // Check finding values
        let src_finding: Vec<_> = findings.iter()
            .filter(|f| f.pattern == "icmp_embedded_ipv4_src").collect();
        let dst_finding: Vec<_> = findings.iter()
            .filter(|f| f.pattern == "icmp_embedded_ipv4_dst").collect();
        assert_eq!(src_finding[0].value, "192.168.1.8");
        assert_eq!(dst_finding[0].value, "192.168.1.1");
    }

    // ── DNS name parser test ──

    #[test]
    fn dns_name_parsing() {
        // Simple name: \x04test\x05local\x00
        let data: Vec<u8> = vec![4, b't', b'e', b's', b't', 5, b'l', b'o', b'c', b'a', b'l', 0];
        let (name, consumed) = read_dns_name(&data, 0, 0);
        assert_eq!(name, "test.local");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn dns_name_with_compression() {
        // Data: offset 0: \x04test\x05local\x00  (12 bytes)
        //       offset 12: \x03sub\xC0\x00       (pointer to offset 0)
        let mut data: Vec<u8> = vec![4, b't', b'e', b's', b't', 5, b'l', b'o', b'c', b'a', b'l', 0];
        data.extend_from_slice(&[3, b's', b'u', b'b', 0xC0, 0x00]);
        let (name, consumed) = read_dns_name(&data, 0, 12);
        assert_eq!(name, "sub.test.local");
        assert_eq!(consumed, 6); // 1+3 label bytes + 2 pointer bytes
    }
}

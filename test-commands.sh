#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# capwash — Comprehensive Test Commands
# ═══════════════════════════════════════════════════════════════
#
# Run these commands in order to verify all features work correctly.
# Prerequisite: ultimate-capture.pcap and master_networking_acronyms_advanced.csv
# must be in the project root directory.
#
# Usage:
#   chmod +x test-commands.sh
#   ./test-commands.sh
#
# Or run individual sections by copying commands to your terminal.
# ═══════════════════════════════════════════════════════════════

set -e  # Exit on first error

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
BIN="cargo run --release --"

# Helper function to run a test — runs command directly, no eval
run_test() {
    local test_name="$1"
    shift
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}TEST: ${test_name}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    if "$@"; then
        echo -e "${GREEN}✓ PASS: ${test_name}${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ FAIL: ${test_name}${NC}"
        FAIL=$((FAIL + 1))
    fi
}

# Helper to clean up between tests
cleanup() {
    rm -f redacted.pcap
    rm -rf sensitive/
    rm -rf acronym-guide/
}

echo -e "${YELLOW}"
echo "═══════════════════════════════════════════════════════════════"
echo " capwash — Full Test Suite"
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────
# 0. PREREQUISITES
# ─────────────────────────────────────────────────────────────

echo -e "${YELLOW}[0] Checking prerequisites...${NC}"

if [ ! -f "ultimate-capture.pcap" ]; then
    echo -e "${RED}ERROR: ultimate-capture.pcap not found in current directory.${NC}"
    echo "See README.md for conversion steps from The Ultimate PCAP."
    exit 1
fi

if [ ! -f "master_networking_acronyms_advanced.csv" ]; then
    echo -e "${RED}ERROR: master_networking_acronyms_advanced.csv not found.${NC}"
    exit 1
fi

echo -e "${GREEN}Prerequisites OK.${NC}"

# ─────────────────────────────────────────────────────────────
# 1. BUILD
# ─────────────────────────────────────────────────────────────

run_test "Build (debug)" \
    cargo build

run_test "Build (release)" \
    cargo build --release

# ─────────────────────────────────────────────────────────────
# 2. UNIT TESTS
# ─────────────────────────────────────────────────────────────

run_test "Unit tests" \
    cargo test

# ─────────────────────────────────────────────────────────────
# 3. HELP AND VERSION
# ─────────────────────────────────────────────────────────────

run_test "Help flag" \
    $BIN --help

run_test "Version flag" \
    $BIN --version

# ─────────────────────────────────────────────────────────────
# 4. MINIMAL RUN (always-on redactions only)
# ─────────────────────────────────────────────────────────────

cleanup

run_test "Minimal run — always-on redactions only" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap

# Verify output file was created
run_test "Minimal run — output file exists" \
    test -f redacted.pcap

# Verify sensitive directory was created with findings
run_test "Minimal run — sensitive directory created" \
    test -d sensitive

run_test "Minimal run — index.json exists" \
    test -f sensitive/index.json

# Verify key finding categories exist
run_test "Minimal run — mac_addresses findings exist" \
    test -f sensitive/mac_addresses/findings.json

run_test "Minimal run — dns_hostnames findings exist" \
    test -f sensitive/dns_hostnames/findings.json

run_test "Minimal run — ipv4_addresses findings exist" \
    test -f sensitive/ipv4_addresses/findings.json

run_test "Minimal run — http_headers findings exist" \
    test -f sensitive/http_headers/findings.json

cleanup

# ─────────────────────────────────────────────────────────────
# 5. INDIVIDUAL FLAG TESTS
# ─────────────────────────────────────────────────────────────

# -- --all-ips
run_test "Flag: --all-ips" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --all-ips

run_test "Flag: --all-ips — output valid" \
    test -f redacted.pcap
cleanup

# -- --strip-timestamps
run_test "Flag: --strip-timestamps" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --strip-timestamps

run_test "Flag: --strip-timestamps — output valid" \
    test -f redacted.pcap
cleanup

# -- --randomize-ports
run_test "Flag: --randomize-ports" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --randomize-ports

run_test "Flag: --randomize-ports — output valid" \
    test -f redacted.pcap

run_test "Flag: --randomize-ports — ephemeral_ports findings exist" \
    test -f sensitive/ephemeral_ports/findings.json
cleanup

# -- --redact-tls-sni
run_test "Flag: --redact-tls-sni" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --redact-tls-sni

run_test "Flag: --redact-tls-sni — output valid" \
    test -f redacted.pcap

run_test "Flag: --redact-tls-sni — tls_sni findings exist" \
    test -f sensitive/tls_sni/findings.json
cleanup

# -- --zero-tcp-timestamps
run_test "Flag: --zero-tcp-timestamps" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --zero-tcp-timestamps

run_test "Flag: --zero-tcp-timestamps — output valid" \
    test -f redacted.pcap

run_test "Flag: --zero-tcp-timestamps — tcp_timestamps findings exist" \
    test -f sensitive/tcp_timestamps/findings.json
cleanup

# -- --normalize-ttl
run_test "Flag: --normalize-ttl" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --normalize-ttl

run_test "Flag: --normalize-ttl — output valid" \
    test -f redacted.pcap

run_test "Flag: --normalize-ttl — ttl_values findings exist" \
    test -f sensitive/ttl_values/findings.json
cleanup

# -- --strip-tcp-options
run_test "Flag: --strip-tcp-options" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --strip-tcp-options

run_test "Flag: --strip-tcp-options — output valid" \
    test -f redacted.pcap

run_test "Flag: --strip-tcp-options — tcp_fingerprint_options findings exist" \
    test -f sensitive/tcp_fingerprint_options/findings.json
cleanup

# ─────────────────────────────────────────────────────────────
# 6. ACRONYM GUIDE
# ─────────────────────────────────────────────────────────────

run_test "Acronym guide generation" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        --acronym-csv master_networking_acronyms_advanced.csv

run_test "Acronym guide — directory created" \
    test -d acronym-guide

run_test "Acronym guide — CSV file created" \
    test -f acronym-guide/acronym-guide.csv

run_test "Acronym guide — CSV has content (more than header)" \
    test "$(wc -l < acronym-guide/acronym-guide.csv)" -gt 1

echo ""
echo -e "${CYAN}Acronym guide contents:${NC}"
head -5 acronym-guide/acronym-guide.csv
echo "..."
echo "($(wc -l < acronym-guide/acronym-guide.csv) total rows)"
cleanup

# ─────────────────────────────────────────────────────────────
# 7. CUSTOM PATTERNS (-p flag)
# ─────────────────────────────────────────────────────────────

# Single custom pattern — email regex
run_test "Custom pattern — single email regex" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        -p '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
cleanup

# Multiple custom patterns
run_test "Custom patterns — multiple patterns" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        -p 'Bearer [A-Za-z0-9._-]+' \
        -p 'token=[A-Za-z0-9._-]+' \
        -p 'api[_-]?key[=:\s]+[A-Za-z0-9._-]+' \
        -p 'Authorization:[^\r\n]+'
cleanup

# IPv4-in-payload pattern
run_test "Custom pattern — IPv4 in payload" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        -p '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
cleanup

# UUID pattern
run_test "Custom pattern — UUID" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        -p '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
cleanup

# ESET license patterns
run_test "Custom pattern — ESET license identifiers" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        -p 'SEAT [A-Za-z0-9]+' \
        -p 'PLID [A-Za-z0-9-]+' \
        -p 'UES Update \([^)]+\)'
cleanup

# ─────────────────────────────────────────────────────────────
# 8. CUSTOM SENSITIVE DIRECTORY
# ─────────────────────────────────────────────────────────────

run_test "Custom sensitive directory path" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        --sensitive-dir ./my-custom-findings

run_test "Custom sensitive dir — directory created at custom path" \
    test -d my-custom-findings

run_test "Custom sensitive dir — index.json at custom path" \
    test -f my-custom-findings/index.json

rm -rf my-custom-findings/
cleanup

# ─────────────────────────────────────────────────────────────
# 9. REPORT MODE (JSON output)
# ─────────────────────────────────────────────────────────────

run_test "Report mode — JSON summary to stdout" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap --report

# Verify stdout is clean JSON (logs now go to stderr)
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: Report mode — valid JSON output (clean stdout)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
cargo run --release -- -i ultimate-capture.pcap -o redacted.pcap --report > /tmp/capwash_report.json 2>/dev/null
JSON_VALID=false
if command -v jq &> /dev/null; then
    jq . /tmp/capwash_report.json > /dev/null 2>&1 && JSON_VALID=true
elif command -v python3 &> /dev/null; then
    python3 -m json.tool /tmp/capwash_report.json > /dev/null 2>&1 && JSON_VALID=true
else
    if head -1 /tmp/capwash_report.json | grep -q '^{' && \
       grep -q '"total_packets"' /tmp/capwash_report.json; then
        JSON_VALID=true
    fi
fi
if $JSON_VALID; then
    echo -e "${GREEN}✓ PASS: Report mode — valid JSON output (clean stdout)${NC}"
    PASS=$((PASS + 1))
else
    echo "  Debug: first 3 lines of stdout:"
    head -3 /tmp/capwash_report.json
    echo -e "${RED}✗ FAIL: Report mode — valid JSON output (clean stdout)${NC}"
    FAIL=$((FAIL + 1))
fi
rm -f /tmp/capwash_report.json
cleanup

# ─────────────────────────────────────────────────────────────
# 10. VERBOSE MODE
# ─────────────────────────────────────────────────────────────

run_test "Verbose mode — debug logging" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap -v
cleanup

# ─────────────────────────────────────────────────────────────
# 11. ALL FLAGS COMBINED
# ─────────────────────────────────────────────────────────────

run_test "All flags combined — maximum redaction" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        --all-ips \
        --strip-timestamps \
        --randomize-ports \
        --redact-tls-sni \
        --zero-tcp-timestamps \
        --normalize-ttl \
        --strip-tcp-options \
        --sensitive-dir ./sensitive \
        --acronym-csv master_networking_acronyms_advanced.csv

# Verify all expected output directories and files
run_test "All flags — redacted.pcap exists" \
    test -f redacted.pcap

run_test "All flags — sensitive/index.json exists" \
    test -f sensitive/index.json

run_test "All flags — acronym-guide/acronym-guide.csv exists" \
    test -f acronym-guide/acronym-guide.csv

# Verify all expected finding categories from ultimate-capture.pcap
run_test "All flags — arp_private_ips findings" \
    test -f sensitive/arp_private_ips/findings.json

run_test "All flags — credentials findings" \
    test -f sensitive/credentials/findings.json

run_test "All flags — credit_cards findings" \
    test -f sensitive/credit_cards/findings.json

run_test "All flags — dhcp_fields findings" \
    test -f sensitive/dhcp_fields/findings.json

run_test "All flags — dns_hostnames findings" \
    test -f sensitive/dns_hostnames/findings.json

run_test "All flags — email_addresses findings" \
    test -f sensitive/email_addresses/findings.json

run_test "All flags — ephemeral_ports findings" \
    test -f sensitive/ephemeral_ports/findings.json

run_test "All flags — icmp_embedded_ips findings" \
    test -f sensitive/icmp_embedded_ips/findings.json

run_test "All flags — http_headers findings" \
    test -f sensitive/http_headers/findings.json

run_test "All flags — ipv4_addresses findings" \
    test -f sensitive/ipv4_addresses/findings.json

run_test "All flags — ipv4_in_payload findings" \
    test -f sensitive/ipv4_in_payload/findings.json

run_test "All flags — mac_addresses findings" \
    test -f sensitive/mac_addresses/findings.json

run_test "All flags — mdns_addresses findings" \
    test -f sensitive/mdns_addresses/findings.json

run_test "All flags — mdns_names findings" \
    test -f sensitive/mdns_names/findings.json

run_test "All flags — mdns_txt findings" \
    test -f sensitive/mdns_txt/findings.json

run_test "All flags — tcp_fingerprint_options findings" \
    test -f sensitive/tcp_fingerprint_options/findings.json

run_test "All flags — tcp_timestamps findings" \
    test -f sensitive/tcp_timestamps/findings.json

run_test "All flags — tls_sni findings" \
    test -f sensitive/tls_sni/findings.json

run_test "All flags — ttl_values findings" \
    test -f sensitive/ttl_values/findings.json

run_test "All flags — uuids findings" \
    test -f sensitive/uuids/findings.json

cleanup

# ─────────────────────────────────────────────────────────────
# 12. DEEP REDACTION VERIFICATION
# ─────────────────────────────────────────────────────────────

# Verify payload scrubbing is active (payload_bytes_scrubbed > 0)
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: Payload scrubbing — payload_bytes_scrubbed > 0${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
cargo run --release -- -i ultimate-capture.pcap -o redacted.pcap --all-ips --report > /tmp/capwash_deep.json 2>/dev/null
SCRUBBED=$(grep -o '"payload_bytes_scrubbed": *[0-9]*' /tmp/capwash_deep.json | grep -o '[0-9]*$')
if [ -n "$SCRUBBED" ] && [ "$SCRUBBED" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS: Payload scrubbing — payload_bytes_scrubbed = ${SCRUBBED}${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: Payload scrubbing — payload_bytes_scrubbed should be > 0 (got: ${SCRUBBED:-null})${NC}"
    FAIL=$((FAIL + 1))
fi
rm -f /tmp/capwash_deep.json
cleanup

# Verify HTTP headers redaction count > 0
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: HTTP headers — http_headers_redacted > 0${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
cargo run --release -- -i ultimate-capture.pcap -o redacted.pcap --report > /tmp/capwash_http.json 2>/dev/null
HTTP_COUNT=$(grep -o '"http_headers_redacted": *[0-9]*' /tmp/capwash_http.json | grep -o '[0-9]*$')
if [ -n "$HTTP_COUNT" ] && [ "$HTTP_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS: HTTP headers — http_headers_redacted = ${HTTP_COUNT}${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: HTTP headers — http_headers_redacted should be > 0 (got: ${HTTP_COUNT:-null})${NC}"
    FAIL=$((FAIL + 1))
fi
rm -f /tmp/capwash_http.json
cleanup

# Verify DNS response RR redaction — dns_hostnames_redacted should be >> qdcount alone
# With full RR redaction, the count should be well above 1000 (queries alone are ~650)
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: DNS response RRs — dns_hostnames_redacted > 1000${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
cargo run --release -- -i ultimate-capture.pcap -o redacted.pcap --report > /tmp/capwash_dns.json 2>/dev/null
DNS_COUNT=$(grep -o '"dns_hostnames_redacted": *[0-9]*' /tmp/capwash_dns.json | grep -o '[0-9]*$')
if [ -n "$DNS_COUNT" ] && [ "$DNS_COUNT" -gt 1000 ]; then
    echo -e "${GREEN}✓ PASS: DNS response RRs — dns_hostnames_redacted = ${DNS_COUNT}${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: DNS response RRs — dns_hostnames_redacted should be > 1000 (got: ${DNS_COUNT:-null})${NC}"
    FAIL=$((FAIL + 1))
fi
rm -f /tmp/capwash_dns.json
cleanup

# Verify VLAN TTL normalization — ttls_normalized should be > 2500
# (VLAN-tagged packets are ~43% of traffic, many had non-64 TTLs)
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: VLAN TTL normalization — ttls_normalized > 2500${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
cargo run --release -- -i ultimate-capture.pcap -o redacted.pcap --normalize-ttl --report > /tmp/capwash_ttl.json 2>/dev/null
TTL_COUNT=$(grep -o '"ttls_normalized": *[0-9]*' /tmp/capwash_ttl.json | grep -o '[0-9]*$')
if [ -n "$TTL_COUNT" ] && [ "$TTL_COUNT" -gt 2500 ]; then
    echo -e "${GREEN}✓ PASS: VLAN TTL normalization — ttls_normalized = ${TTL_COUNT}${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: VLAN TTL normalization — ttls_normalized should be > 2500 (got: ${TTL_COUNT:-null})${NC}"
    FAIL=$((FAIL + 1))
fi
rm -f /tmp/capwash_ttl.json
cleanup

# ─────────────────────────────────────────────────────────────
# 13. MAXIMUM REDACTION WITH ALL CUSTOM PATTERNS
# ─────────────────────────────────────────────────────────────

run_test "Maximum redaction — all flags + all patterns + report" \
    $BIN -i ultimate-capture.pcap -o redacted.pcap \
        --all-ips \
        --strip-timestamps \
        --randomize-ports \
        --redact-tls-sni \
        --zero-tcp-timestamps \
        --normalize-ttl \
        --strip-tcp-options \
        --sensitive-dir ./sensitive \
        --acronym-csv master_networking_acronyms_advanced.csv \
        -p 'Bearer [A-Za-z0-9._-]+' \
        -p 'token=[A-Za-z0-9._-]+' \
        -p 'api[_-]?key[=:\s]+[A-Za-z0-9._-]+' \
        -p 'secret[=:\s]+[A-Za-z0-9._-]+' \
        -p 'Authorization:[^\r\n]+' \
        -p '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
        -p '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' \
        -p '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
        -p '[A-Z]{2}[0-9]{6}[A-Z]?' \
        -p 'SEAT [A-Za-z0-9]+' \
        -p 'PLID [A-Za-z0-9-]+' \
        -p 'UES Update \([^)]+\)' \
        --report

run_test "Maximum redaction — output file size > 0" \
    test -s redacted.pcap

cleanup

# ─────────────────────────────────────────────────────────────
# 14. OUTPUT VALIDATION WITH WIRESHARK TOOLS
# ─────────────────────────────────────────────────────────────

# These tests require tshark/capinfos (Wireshark CLI tools)
if command -v capinfos &> /dev/null; then

    $BIN -i ultimate-capture.pcap -o redacted.pcap --all-ips --redact-tls-sni 2>/dev/null

    run_test "Wireshark validation — capinfos reads redacted.pcap" \
        capinfos redacted.pcap

    if command -v tshark &> /dev/null; then

        # tshark can parse the file
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}TEST: Wireshark validation — tshark can parse redacted.pcap${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        if tshark -r redacted.pcap -c 10 > /dev/null 2>&1; then
            echo -e "${GREEN}✓ PASS: Wireshark validation — tshark can parse redacted.pcap${NC}"
            PASS=$((PASS + 1))
        else
            echo -e "${RED}✗ FAIL: Wireshark validation — tshark can parse redacted.pcap${NC}"
            FAIL=$((FAIL + 1))
        fi

        # MACs are zeroed
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}TEST: Wireshark validation — MACs are zeroed${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        NON_ZERO_MACS=$(tshark -r redacted.pcap -T fields -e eth.src -c 10 2>/dev/null | grep -v "00:00:00:00:00:00" | head -1)
        if [ -z "$NON_ZERO_MACS" ]; then
            echo -e "${GREEN}✓ PASS: Wireshark validation — MACs are zeroed${NC}"
            PASS=$((PASS + 1))
        else
            echo -e "${RED}✗ FAIL: Wireshark validation — MACs are zeroed (found: ${NON_ZERO_MACS})${NC}"
            FAIL=$((FAIL + 1))
        fi

        # No private IPs remain
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}TEST: Wireshark validation — no private IPs remain in IP headers${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        PRIVATE_IPS=$(tshark -r redacted.pcap \
            -Y "ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16" \
            -T fields -e ip.src -c 1 2>/dev/null)
        if [ -z "$PRIVATE_IPS" ]; then
            echo -e "${GREEN}✓ PASS: Wireshark validation — no private IPs remain in IP headers${NC}"
            PASS=$((PASS + 1))
        else
            echo -e "${RED}✗ FAIL: Wireshark validation — found private IP: ${PRIVATE_IPS}${NC}"
            FAIL=$((FAIL + 1))
        fi
    fi

    cleanup
else
    echo ""
    echo -e "${YELLOW}SKIPPED: Wireshark tools (capinfos/tshark) not found — skipping output validation tests.${NC}"
fi

# ─────────────────────────────────────────────────────────────
# 15. ERROR HANDLING
# ─────────────────────────────────────────────────────────────

# Missing input file
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: Error handling — missing input file exits non-zero${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if ! $BIN -i nonexistent.pcap -o redacted.pcap 2>/dev/null; then
    echo -e "${GREEN}✓ PASS: Error handling — missing input file exits non-zero${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: Error handling — missing input file should exit non-zero${NC}"
    FAIL=$((FAIL + 1))
fi

# Missing required arguments
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: Error handling — no arguments exits non-zero${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if ! $BIN 2>/dev/null; then
    echo -e "${GREEN}✓ PASS: Error handling — no arguments exits non-zero${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: Error handling — no arguments should exit non-zero${NC}"
    FAIL=$((FAIL + 1))
fi

# Missing output argument
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: Error handling — missing -o exits non-zero${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if ! $BIN -i ultimate-capture.pcap 2>/dev/null; then
    echo -e "${GREEN}✓ PASS: Error handling — missing -o exits non-zero${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: Error handling — missing -o should exit non-zero${NC}"
    FAIL=$((FAIL + 1))
fi

# Invalid acronym CSV path
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}TEST: Error handling — invalid acronym CSV path exits non-zero${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if ! $BIN -i ultimate-capture.pcap -o redacted.pcap --acronym-csv nonexistent.csv 2>/dev/null; then
    echo -e "${GREEN}✓ PASS: Error handling — invalid acronym CSV path exits non-zero${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ FAIL: Error handling — invalid acronym CSV path should exit non-zero${NC}"
    FAIL=$((FAIL + 1))
fi

cleanup

# ─────────────────────────────────────────────────────────────
# 16. IDEMPOTENCY TEST
# ─────────────────────────────────────────────────────────────

# Running the tool on an already-redacted file should still produce valid output
$BIN -i ultimate-capture.pcap -o redacted.pcap --all-ips 2>/dev/null

run_test "Idempotency — redact an already-redacted file" \
    $BIN -i redacted.pcap -o redacted2.pcap --all-ips

run_test "Idempotency — double-redacted output exists" \
    test -f redacted2.pcap

if command -v capinfos &> /dev/null; then
    run_test "Idempotency — double-redacted output is valid pcap" \
        capinfos redacted2.pcap
else
    echo -e "${YELLOW}SKIPPED: capinfos not found — skipping idempotency pcap validation.${NC}"
fi

rm -f redacted2.pcap
cleanup

# ─────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} TEST SUMMARY${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}Passed: ${PASS}${NC}"
echo -e "  ${RED}Failed: ${FAIL}${NC}"
echo -e "  Total:  $((PASS + FAIL))"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Review output above.${NC}"
    exit 1
fi
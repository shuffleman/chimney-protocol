# Chimney — Behaviorally Indistinguishable Session-Parasitic Transport

A Go implementation of the Chimney protocol — a covert transport system that
makes隐蔽通信 (hidden communication) behaviorally indistinguishable from normal
HTTPS traffic to real websites.

## Overview

Chimney is a transport protocol designed to resist detection by advanced traffic
analysis systems. Unlike traditional proxy protocols that attempt to "look like"
HTTPS, Chimney **parasitizes** real HTTPS sessions — borrowing actual TLS
handshakes from legitimate websites and maintaining record-level traffic
characteristics that match real browser behavior.

### Key Features

- **Real TLS Handshake Borrowing**: Uses genuine TLS handshakes with real
  websites — the relay forwards the handshake transparently, and the client
  uses uTLS to mimic real browser fingerprints.
- **Zero-Distinguishable Failure Path (P1)**: Failed authentication is
  indistinguishable from a normal browser connection — traffic is simply
  forwarded to the real website.
- **H2 Framing with Real SETTINGS**: Internally uses HTTP/2 framing with
  SETTINGS values captured from the real whitelisted site, not library defaults.
- **TLS-in-TLS Fingerprint Elimination**: Shapes traffic in the initial
  handshake window (~10 records) to eliminate the size-sequence signature of
  nested TLS handshakes.
- **Traffic Profile Pacing**: Shapes record sizes, burst patterns, and timing
  to match real website traffic profiles calibrated from pcap captures.
- **Two-Layer Whitelist**: Intent layer (site names) + enforce layer (cloud
  CIDR blocks) ensures the relay only connects to destinations within the same
  cloud region.

## Architecture

```
Client         Relay               Real Site (whitelist_i)
  |              |                        |
  |--- TLS ---->|                        |
  |  Handshake   |---- TCP Forward ----->|
  |  (SNI=site_i)|  (transparent relay)   |-- Real Cert --+
  |              |                        |               |
  |<-------------|<-----------------------|<--------------+
  |              |  (ServerHello w/ ServerRandom observed)
  |              |                        |
  |-- AppData -->|                        |
  |  (auth_tag   |  Extract tag, verify   |
  |   + H2 open) |                        |
  |              |  Tag matches?          |
  |              |  YES: CUT real site,   |
  |              |       take over with   |
  |              |       K_sess           |
  |              |  NO:  forward to       |
  |              |       real site        |
  |              |       (zero distinction)|
  |              |                        |
  |<== H2 Tunnel=| (Chimney mode)         |
  |  (DATA frames |                        |
  |   + pacing)  |                        |
```

## Project Structure

```
chimney/
├── cmd/
│   ├── chimney-relay/          # Relay server binary
│   └── chimney-client/         # Client binary (SOCKS5 proxy)
├── internal/
│   ├── auth/                   # Auth tag generation/verification
│   ├── config/                 # Configuration loading
│   ├── dilution/               # Real content blocks for dilution stream
│   ├── h2engine/               # HTTP/2 framing engine
│   ├── keyderiv/               # HKDF key derivation (K_auth, K_sess)
│   ├── pcap/                   # PCAP parser for traffic calibration
│   ├── profile/                # Traffic profile and pacing
│   ├── record/                 # ChimneyRecord codec (AEAD)
│   ├── relay/                  # Core relay logic (handshake, swap, tunnel)
│   └── whitelist/              # Two-layer whitelist (intent + enforce)
├── config/
│   ├── intent.yaml             # Intent whitelist (site names)
│   └── enforce.yaml            # Enforce CIDR whitelist
├── go.mod
├── Makefile
└── README.md
```

## Quick Start

### Prerequisites

- Go 1.23 or later
- Linux/Unix environment (for building)

### Building

```bash
# Clone the repository
git clone <repository-url>
cd chimney

# Download dependencies
go mod download

# Build both binaries
make build

# Or build individually
make build-relay
make build-client
```

### Generate a PSK

```bash
make genkey
# Output: 64-character hex string (256 bits)
```

### Running the Relay

1. Configure `config/intent.yaml` with your whitelisted sites
2. Configure `config/enforce.yaml` with your cloud region CIDRs
3. Run the relay:

```bash
./build/bin/chimney-relay -config config/relay.yaml
```

Example `config/relay.yaml`:

```yaml
listen_addr: ":443"
psk: "your-64-char-hex-psk-here"
tag_len: 16
intent_file: "config/intent.yaml"
enforce_file: "config/enforce.yaml"
cloud_region: "us-east-1"
handshake_timeout: 10s
auth_read_timeout: 5s
log_level: "info"
```

### Running the Client

```bash
./build/bin/chimney-client \
  -relay relay.example.com:443 \
  -sni real-site.com \
  -dest final-destination.com:443 \
  -psk your-64-char-hex-psk-here \
  -fingerprint chrome,firefox,safari \
  -profile profiles/example.com.profile.json \
  -dilution blocks/example.com.blocks.json
```

The client will start a SOCKS5 proxy on `127.0.0.1:1080`. Configure your
applications to use this proxy.

The `-fingerprint` flag accepts a comma-separated list of TLS fingerprints
for rotation. Each new connection uses the next fingerprint in sequence.
Available fingerprints: `chrome`, `firefox`, `safari`, `ios`, `edge`,
`android`, `360`, `qq`, `randomized`, `golang`. Append a version for
specific browser versions (e.g. `chrome-120`, `firefox-105`).

The `-profile` flag enables the padding stream by loading a traffic profile
JSON (generated by the calibration tool). Records are padded with dummy H2
DATA frames on a reserved padding stream to match the site's record size
distribution. Use `-padding-target` to override with a fixed size.

The `-dilution` flag enables the dilution stream by loading pre-recorded
content blocks (base64-encoded HTTP response fragments captured from the
real site). Dilution frames carry semantically meaningful content instead
of random bytes, making the traffic resistant to entropy-based DPI analysis.
Blocks are matched to the target record size from the traffic profile.

## Configuration

### Intent Whitelist (config/intent.yaml)

The intent layer lists allowed SNI values. Each entry should have captured
HTTP/2 SETTINGS from the real site:

```yaml
version: 1
entries:
  example.com:
    sni: example.com
    description: "Example CDN site"
    settings_snapshot:
      HEADER_TABLE_SIZE: 4096
      ENABLE_PUSH: 0
      MAX_CONCURRENT_STREAMS: 100
      INITIAL_WINDOW_SIZE: 65535
      MAX_FRAME_SIZE: 16384
      MAX_HEADER_LIST_SIZE: 16384
```

### Enforce Whitelist (config/enforce.yaml)

The enforce layer defines allowed destination IP CIDRs. This is the
security-critical layer:

```yaml
version: 1
entries:
  - cidr: "52.0.0.0/11"
    provider: "aws"
    region: "us-east-1"
```

To refresh CIDRs from AWS automatically:

```bash
# The relay will refresh CIDRs periodically, or you can force refresh:
curl -X POST http://relay:8080/admin/refresh-cidrs
```

### Site Calibration

Before adding a site to the whitelist, you must capture its real traffic
profile:

```bash
# 1. Capture HTTPS traffic to the site using a real browser
tcpdump -i eth0 -w site_capture.pcap 'host example.com and port 443'

# 2. Use the calibration tool to extract SETTINGS and profile
go run ./cmd/calibrate -pcap site_capture.pcap -site example.com

# 3. Add the generated profile to config/intent.yaml
```

## Security Principles

The Chimney protocol is designed around four security principles:

1. **P1 — No Distinguishable Failure Path**: Failed auth is forwarded to the
   real site. No error codes, no early disconnect, no timing differences.

2. **P2 — No Semantic Discontinuity**: After the swap, record sizes and
   timing match what a real browser visiting the whitelisted site would produce.

3. **P3 — No Observable Protocol Transition**: The transition from real TLS
   to Chimney mode is invisible — only the record sizes/timing are observable,
   and those match the site profile.

4. **P4 — All Unauthenticated Traffic Stays Legitimate**: Any traffic without
   a valid auth tag is forwarded to the real site and receives the real site's
   genuine response.

## Implementation Status

| Component | Status |
|-----------|--------|
| Record codec (AEAD) | ✅ Complete |
| Key derivation (HKDF) | ✅ Complete |
| H2 framing engine | ✅ Complete |
| Auth tag (HMAC) | ✅ Complete |
| TCP relay + handshake forwarding | ✅ Complete |
| Swap mechanism | ✅ Complete |
| Whitelist (intent + enforce) | ✅ Complete |
| Traffic profile + pacing | ✅ Complete |
| Relay server | ✅ Complete |
| Client (SOCKS5) | ✅ Complete |
| Site calibration tool | ✅ Complete |
| uTLS fingerprint rotation | ✅ Complete |
| Padding stream | ✅ Complete |
| Real content dilution | ✅ Complete |

## Protocol Specification

This implementation follows the Chimney protocol specification (v0.1). The key
cryptographic operations are:

```
K_auth = HKDF(PSK, label="chimney-auth", info=ServerRandom)
tag    = HMAC(K_auth, ServerRandom || recordBytes)[:TAG_LEN]

K_sess = HKDF(PSK, label="chimney-sess", info=ServerRandom || ClientRandom)
```

The auth tag is embedded in the first application_data record after the TLS
handshake. The relay verifies the tag without decrypting the TLS record — it
observes ServerRandom during handshake forwarding and derives K_auth from the
shared PSK.

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run benchmarks
make bench

# Run CI pipeline (fmt, vet, test, build)
make ci
```

## Security Considerations

**This is a research implementation.** Before production deployment:

1. Implement TLS decryption in calibration tool (keylog support) for precise SETTINGS
2. Integrate Pacer with tunnel data flow for automatic pacing
3. Review and harden the H2 engine for all edge cases
4. Conduct formal security analysis of the complete system

## License

MIT License — see LICENSE file for details.

## Acknowledgments

This implementation is based on the Chimney protocol specification, building
upon the foundations of ShadowTLS v3 and REALITY. The key innovation is the
post-swap traffic shaping that maintains behavioral indistinguishability from
real HTTPS sessions.

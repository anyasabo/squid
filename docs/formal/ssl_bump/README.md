# SSL Bump State Machine -- TLA+ Model

TLA+ formal model of Squid's SSL bump (peek/stare/splice/bump) pipeline.

## What this models

The SSL bump pipeline is a 3-step state machine:

- **Step 1** (`tlsBump1`): Initial ACL check on connection accept (intercept)
  or CONNECT request. Determines the bump strategy.
- **Step 2** (`tlsBump2`): After ClientHello is parsed. Refines the strategy
  (only reached from peek/stare modes).
- **Step 3** (`tlsBump3`): After connecting to the origin server.
  `PeekingPeerConnector` makes the final bump/splice/terminate decision.

### Modes

| Mode | Value | Meaning |
|------|-------|---------|
| `bumpNone` | 0 | No bumping |
| `clientFirst` | 1 | Client-side TLS first, then origin |
| `serverFirst` | 2 | Origin-side TLS first, then client |
| `peek` | 3 | Forward client's ClientHello, peek at server cert |
| `stare` | 4 | Generate new ClientHello, stare at server cert |
| `bump` | 5 | Full MITM inspection |
| `splice` | 6 | Pass-through tunnel, no inspection |
| `terminate` | 7 | Close connection |

### Server behaviors (step 3)

| Behavior | Effect |
|----------|--------|
| `normalCert` | Server presents a normal certificate |
| `encryptedCert` | Server uses encrypted certificates (TLS 1.3+) |
| `sessionResumption` | Server resumes a previous TLS session |
| `certError` | Server certificate has validation errors |
| `noCert` | Server does not present a certificate |

## Safety property

**`NoUnintendedSplice`**: If the admin configures all ACL steps to return
"bump" (via peek or stare path), no server behavior should cause the
connection to be spliced (bypassing inspection).

### Expected violations

1. **Peek + encrypted certificates**: `PeekingPeerConnector.cc:332-338`
   hardcodes splice when the server uses encrypted certificates (common
   with TLS 1.3). No configuration toggle exists.

2. **Peek + session resumption**: `PeekingPeerConnector.cc:339-348`
   hardcodes splice when the server resumes a previous session. No
   configuration toggle exists.

### Safe configuration

Use **stare** mode instead of **peek**. Stare mode generates a new
ClientHello (rather than forwarding the client's), which avoids both
the encrypted certificate and session resumption bypass paths.

## Running

### Prerequisites

Install TLC (the TLA+ model checker). Options:

```bash
# Via tla2tools.jar (requires Java 11+)
brew install tlaplus   # macOS
# or download from https://github.com/tlaplus/tlaplus/releases

# Via the VS Code TLA+ extension
code --install-extension alygin.vscode-tlaplus
```

### Configs

| Config | Tests | Expected result |
|--------|-------|-----------------|
| `SslBump.cfg` | Peek + normalCert, all inspection | PASS (no violation) |
| `SslBumpSafety.cfg` | Peek + encryptedCert, all inspection | **FAIL** (NoUnintendedSplice violated) |
| `SslBumpExhaustive.cfg` | Peek + encryptedCert, peek→peek→bump | **FAIL** (documents the bypass) |
| `SslBumpResumption.cfg` | Peek + sessionResumption, peek→peek→bump | **FAIL** (NoUnintendedSplice violated) |
| `SslBumpStare.cfg` | Stare + normalCert, stare→bump→bump | PASS (stare is safe) |

### Run

```bash
cd docs/formal/ssl_bump

# Normal case (should pass)
java -jar tla2tools.jar -config SslBump.cfg SslBump.tla

# Demonstrate the encrypted cert bypass (should FAIL)
java -jar tla2tools.jar -config SslBumpExhaustive.cfg SslBump.tla

# Demonstrate the session resumption bypass (should FAIL)
java -jar tla2tools.jar -config SslBumpResumption.cfg SslBump.tla

# Verify stare mode is safe (should pass)
java -jar tla2tools.jar -config SslBumpStare.cfg SslBump.tla
```

### Interpreting violations

When TLC reports a violation of `NoUnintendedSplice`, the error trace shows
the exact state transitions that lead to an unintended splice. The trace
corresponds to real code paths in `src/ssl/PeekingPeerConnector.cc`.

## Source code references

| TLA+ element | C++ source |
|-------------|------------|
| `DoStep1` | `client_side.cc:httpsSslBumpAccessCheckDone` (~2413) |
| `DoStep2` | `client_side.cc:httpsSslBumpStep2AccessCheckDone` (~2900) |
| `DoStep3` | `PeekingPeerConnector::checkForPeekAndSplice` (~68) |
| `Step3Effective` | `PeekingPeerConnector::checkForPeekAndSpliceGuess` (~127) |
| Hardcoded bypass | `PeekingPeerConnector::noteNegotiationError` (~330-354) |
| `BumpMode` enum | `ssl/support.h:132` |
| `XactionStep` | `XactionStep.h:12` |
| `ServerBump` | `ssl/ServerBump.h:58-63` |

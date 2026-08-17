# ccaguest
 
`ccaguest` is a Rust-based command-line tool that provides following ARM CCA attestation capabilities:
 
- Evidence generation
- Evidence verification in remote and local mode
- Endorsements fetch
- Policy fetch and submission
- Evidence, EAR, and endorsements display

## Prerequisites

Before using `ccaguest`, ensure the following requirements are met:

- **Operating System:** Ubuntu 24.04 LTS
- **Rust Toolchain:** Rust 1.88.0 or later
- **Network Access:** Required to connect with remote services: CoSERV service, Verification service, Management service, REGL's ratsd
- **ARM-CCA Hardware:** Required only when using the `tsm` attester backend for generating evidence

## How to Build
 
This is a Rust-based CLI tool, so user need to [install Rust](https://rust-lang.org/tools/install/) first.

Build the project:

```
cargo build
```

The binary executable will be generated at `target/debug/ccaguest`.

Test the project:

```
cargo test
```

## Installation

Install the tool from the repository root directory:

```bash
cargo install --path . --locked
```

After installation, the `ccaguest` binary will be available on your system PATH.

## Quick Start 

Sample tokens are available in the `test/` directory. 

Display an example CCA token:

```bash
$ ccaguest display evidence -f test/cbor/ccatoken.cbor -p
{
  "cca-platform-token": {
    "cca-platform-profile": "tag:arm.com,2023:cca_platform#1.0.0",
    "cca-platform-challenge": "DSLgiphGkFhIYxgoNIm9s28J2+/rGGTfQz+m5U6i1xE=",
    ...
  },
  "cca-realm-delegated-token": {
    "cca-realm-profile": "tag:arm.com,2023:realm#1.0.0",
    "cca-realm-challenge": "bobW2XzHE7xt1D285JGmtAMRwCeov4WjnaY+nORMEyqKEZ0pb65qaZnpvz5EcbDOASRdiJQkwx6JeTs7HWsVBA==",
    ...
  }
}
[2026-07-22T10:56:08Z INFO  ccaguest] done.
```

List all available commands:

```bash
$ ccaguest --help
```
 
## Low Level Design Document

### Command Tree
![Command Tree](./docs/command_tree.png)

The following sections describe each subcommand in detail.

### 1. `ccaguest display evidence`

![ccaguest display evidence](./docs/lld_display_evidence.png)

REGL (Rust Evidence Generation Library) is used to collect and process attestation evidence from Trusted Execution Environment (TEE) platforms. For more information, see the REGL project:

https://github.com/veraison/rust-regl

This command uses REGL to decode and display the contents of a provided attestation evidence file.

To display ARM CCA attestation evidence, provide the CBOR-encoded evidence file using the --file (-f) option.

Example:
```Shell
$ ccaguest display evidence -f test/cbor/ccatoken.cbor -p
{
  "cca-platform-token": {
    "cca-platform-profile": "tag:arm.com,2023:cca_platform#1.0.0",
    "cca-platform-challenge": "DSLgiphGkFhIYxgoNIm9s28J2+/rGGTfQz+m5U6i1xE=",
    ...
  },
  "cca-realm-delegated-token": {
    "cca-realm-profile": "tag:arm.com,2023:realm#1.0.0",
    "cca-realm-challenge": "bobW2XzHE7xt1D285JGmtAMRwCeov4WjnaY+nORMEyqKEZ0pb65qaZnpvz5EcbDOASRdiJQkwx6JeTs7HWsVBA==",
    ...
  }
}
[2026-07-22T10:56:08Z INFO  ccaguest] done.
```

Help:
```Shell
$ ccaguest display evidence -h
Display evidence

Usage: ccaguest display evidence [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>  Path to the evidence file in CBOR format
  -v, --verbose...   Increase logging verbosity
  -p, --pretty       Pretty print the output
  -q, --quiet...     Decrease logging verbosity
      --force        Force write if output exists
  -h, --help         Print help
```

### 2. `ccaguest display ear`

![ccaguest display evidence](./docs/lld_display_ear.png)

This command displays an Entity Attestation Result (EAR) from a provided EAR file.

Provide the EAR file using the --file (-f) option.

Example:
```Shell
$ ccaguest display ear -f test/json/ear.jwk -p
{
  "ear.verifier-id": {
    "build": "vsts 0.0.1",
    "developer": "https://veraison-project.org"
  },
  "eat_profile": "test",
  "iat": 1,
  "submods": {
    "test": {
      "ear.status": "none"
    }
  }
}
[2026-07-22T11:01:52Z INFO  ccaguest] done.
```

Help:
```Shell
$ ccaguest display ear -h
Display entity attestation results (EAR)

Usage: ccaguest display ear [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>  Path to the EAR file in JWK format
  -v, --verbose...   Increase logging verbosity
  -p, --pretty       Pretty print the output
  -q, --quiet...     Decrease logging verbosity
      --force        Force write if output exists
  -h, --help         Print help
```

### 3. `ccaguest fetch evidence`

![ccaguest display evidence](./docs/lld_fetch_evidence.png)

REGL currently supports three attester backends:

- ratsd - Connects to a RATSD daemon. Requires the --ratsd-url option.
- tsm - Generates evidence using the Linux configfs-tsm interface. Requires CCA-capable hardware.
- sim - Generates a simulated CCA token from JSON claims and JWK files located under the test/json/ directory (cca-claims.json and iak.jwk).

Users can optionally provide a nonce for evidence generation. The nonce can be supplied in raw, hexadecimal, Base64, or Base64URL format. If no nonce is specified, a random nonce is generated automatically.

The generated evidence is written to the specified output file. If no output path is provided, the evidence is saved as evidence.cbor in the current working directory.

Example:
```Shell
$ ccaguest fetch evidence -a sim -p
[2026-07-22T11:05:49Z INFO  ccaguest::fetch::evidence] {
      "cca-platform-token": {
        "cca-platform-profile": "tag:arm.com,2023:cca_platform#1.0.0",
        "cca-platform-challenge": "PU8hmS4J+6OFzL6HbpqlMIsZtINOw0gBwN0UVSTedUo=",
        ...
      },
      "cca-realm-delegated-token": {
        "cca-realm-profile": "tag:arm.com,2023:realm#1.0.0",
        "cca-realm-challenge": "a2bORb91exe+J52cL7WfY02/6TYU6e3cEoA/uGqYg8a96LhtFn+fiBfV3rVBPqQVlRCjtjSVIwfx1JZJW5jsFg==",
        ...
      }
    }
[2026-07-22T11:05:49Z INFO  ccaguest::fetch::evidence] Evidence saved to: "evidence.cbor"
[2026-07-22T11:05:49Z INFO  ccaguest] done.
```

Help:
```Shell
$ ccaguest fetch evidence -h
Fetch evidence

Usage: ccaguest fetch evidence [OPTIONS]

Options:
  -a, --attester <ATTESTER>          Regl attester backend to use for evidence generation [default: ratsd] [possible values: ratsd, tsm, sim]
  -v, --verbose...                   Increase logging verbosity
  -q, --quiet...                     Decrease logging verbosity
      --ratsd-url <RATSD_URL>        URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`
      --sim-claims <SIM_CLAIMS>      Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`
      --sim-iak <SIM_IAK>            Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`
      --nonce-raw <NONCE_RAW>        Path to a text file containing nonce as raw bytes
      --nonce-hex <NONCE_HEX>        A hex-encoded nonce passed as a string
      --nonce-b64 <NONCE_B64>        A base64-encoded nonce passed as a string
      --nonce-b64url <NONCE_B64URL>  A base64url-encoded nonce passed as a string
  -o, --output <OUTPUT>              Output file path. If not specified, the evidence will be saved to default `evidence.cbor` in the current working directory [default: evidence.cbor]
  -p, --pretty                       Pretty print the output
      --force                        Force write if output exists
  -h, --help                         Print help (see more with '--help')
```

### 4. `ccaguest fetch endorsements`

![ccaguest display evidence](./docs/lld_fetch_endorsements.png)

This command fetches endorsements from a [remote CoSERV service](https://github.com/veraison/tree/main/coserv).

Endorsements can be fetched using one of the following inputs:

- Implementation ID (impl-id) to retrieve reference values.
- Instance ID (inst-id) to retrieve trust anchors.
- Evidence file, from which the implementation ID and instance ID are extracted automatically.

The user must specify the CoSERV server URL. Optional parameters can be provided to configure TLS certs, local caching, and signing requirements.

The CoSERV service can return:

- Collected artifacts
- Source artifacts
- Both collected and source artifacts

The result type can be selected using the --result-type option.

If the CoSERV service supports signed responses, users can require signed results by specifying the --must-sign option.

By default:

- Trust anchors are stored in coserv_ta.cbor
- Reference values are stored in coserv_rv.cbor

Both files are created in the current working directory unless alternative output paths are specified.

Example:
```Shell
$ ccaguest fetch endorsements -e test/cbor/ccatoken.cbor -S http://localhost:1234
[2026-07-22T11:09:14Z INFO  ccaguest::fetch::endorsements] Trust anchors saved to: "coserv_ta.cbor"
[2026-07-22T11:09:14Z INFO  ccaguest::fetch::endorsements] Reference values saved to: "coserv_rv.cbor"
[2026-07-22T11:09:14Z INFO  ccaguest] done.
```

Help:
```Shell
$ ccaguest fetch endorsements -h
Fetch endorsements

Usage: ccaguest fetch endorsements [OPTIONS] --coserv-server <COSERV_SERVER>

Options:
  -E, --impl-id <IMPL_ID>              Implementation ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648), base64 Standard or URL Safe encoding, padding optional). Use this to fetch reference values
  -v, --verbose...                     Increase logging verbosity
  -I, --inst-id <INST_ID>              Instance ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648), base64 Standard or URL Safe encoding, padding optional). Use this to fetch trust anchors
  -q, --quiet...                       Decrease logging verbosity
  -e, --evidence <EVIDENCE>            Path to an evidence file in CBOR format. Use this to extract impl-id and inst-id and then fetch endorsements
  -S, --coserv-server <COSERV_SERVER>  The base URL to a CoSERV service. Coserv service should support the result-type=collected
  -t, --ca-cert <CA_CERT>              The path to an X509 certificate to bootstrap TLS handshakes with the CoSERV service
  -l, --local-cache <LOCAL_CACHE>      The path to the directory where local coserv results will be cached. If not specified, no local caching is performed, and all CoSERV requests will go to the server
      --must-sign                      The server MUST sign CoSERV results. The command fails if the server does not support signing
  -r, --result-type <RESULT_TYPE>      CoSERV Result type [default: collected] [possible values: collected, source, both]
      --output-ta <OUTPUT_TA>          Output file path for fetched trust anchor. If not specified, the trust anchor output will be saved to default `coserv_ta.cbor` in the current working directory [default: coserv_ta.cbor]
      --output-rv <OUTPUT_RV>          Output file path for fetched reference values. If not specified, the reference values will be saved to default `coserv_rv.cbor` in the current working directory [default: coserv_rv.cbor]
  -p, --pretty                         Pretty print the output
      --force                          Force write if output exists
  -h, --help                           Print help
```

### 5. `ccaguest verify local`
Yet to be implemented.

### 6. `ccaguest verify remote`
Yet to be implemented.

### 7. `ccaguest submit policy`
Yet to be implemented.

### 8. `ccaguest fetch policy`
Yet to be implemented.

### 9. `ccaguest display endorsements`
Yet to be implemented.

>[!NOTE]
>`ccaguest` can also be used within a non-realm VM and the attestation evidence can be retrieved from a Realm VM using `regl`'s `ratsd` backend.

>[!NOTE]
> The CoSERV service used during local verification must support `collected` result type.

>[!NOTE]
> The base url must have empty path segment, e.g. "http://address:port", ""https://veraison.example or "https://veraison.example/" but not "https://veraison.example/foo".


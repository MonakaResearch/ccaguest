# ccaguest
 
This repository contains a Rust-based command-line tool for the following ARM CCA attestation features:
 
- Evidence generation
- Evidence verification in remote and local mode
- Endorsements fetch
- Policy fetch and submission
- Evidence, EAR, and endorsements display

## Command Tree
![Command Tree](./docs/command_tree.png)
 
## Software Architecture

A summary of software architecture is given below.

### Remote verification

![Verify Remote](./docs/verify_remote.png)

The above diagram is simplified down to the most essential interactions. `ccaguest` connects to [Veraison's remote verification service](https://github.com/veraison/services/tree/main/verification) and establishes a challenge response session using [rust-apiclient](https://github.com/veraison/rust-apiclient). Using the nonce received from the remote verifier, it requests the Realm VM for an attestation report using [rust-regl](https://github.com/veraison/rust-regl) and sends it to the verifier.

Once the attestaion evidence has been verified, the received attestation results (EAR) is validated and shown to the relying party. It can also be saved to an output file and displayed later using the `ccaguest display` subcommand.

### Local verification

![Verify local](./docs/verify_local.png)

`ccaguest` uses [cover](https://github.com/veraison/cover) to locally verify an attestation report without connecting to a remote verification service. The endorsements can be queried from a [remote CoSERV service](https://github.com/veraison/tree/main/coserv) using [rust-apiclient](https://github.com/veraison/rust-apiclient).

>[!NOTE]
>`ccaguest` can also be used within a normal VM and the attestation evidence can be retrieved from a Realm VM using `regl`'s `ratsd` backend.

>[!NOTE]
> The CoSERV service used during local verification must support `collected` result type.

## How to Build
 
This is a Rust-based CLI tool, so you need to [install Rust](https://rust-lang.org/tools/install/) first.

Then simply build as follows:

```
cargo build
```

## Installation and Usage

Install by running this command from the repo root:

```bash
cargo install --path . --locked
```

Example usage:

```bash
ccaguest display evidence -f path_to_ccatoken_cbor_file
```

To see a list of available commands, run:

```bash
ccaguest --help
```


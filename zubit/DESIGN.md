# Zubit — Quantum Resistant Zebra for Zcash Blockchain (design v0.1)

Status: draft, local research fork of Zebra v6.4.2 (`e3eef2f`). Nothing here is
active on Zcash mainnet or testnet. It can only become real through a ZIP and a
network upgrade accepted by the Zcash community.

## Goal

Let a user hold transparent ZEC in an output that can **only** be spent with a
post-quantum signature, so that a quantum computer running Shor's algorithm
cannot steal it. Deliver a working end-to-end demo on a local regtest network:
create a PQ address → fund it → spend it with a PQ signature, and show that
Zebra rejects a spend with a wrong or missing PQ signature.

## Choices

| Question | Decision | Why |
|---|---|---|
| Signature scheme | **ML-DSA-44** (FIPS 204), crate `fips204` 0.4.6 (pure Rust) | NIST standard; pk 1312 B, sig 2420 B; fast verify. SLH-DSA (FIPS 205) documented as the conservative alternative |
| Deployment | **Soft fork**, activated at a configured height (same pattern as Zebra's existing `temporary_orchard_disabling_soft_fork_height`) | No new transaction version, no new branch ID, no change to the C++ script interpreter |
| Transaction version | v5 only (ZIP 244 sighash) | v5 sighash does not commit to `scriptSig`, so the PQ signature can live there without circularity |
| Where it is checked | `zebra-script` (new `qr` module), called from `CachedFfiTransaction::is_valid` after the legacy script passes | One choke point used by both block and mempool verification |

## Output format ("P2PQH", pay-to-post-quantum-pubkey-hash)

```
scriptPubKey (39 bytes) = 0x04 "ZUB1"  OP_DROP  0x20 <H(pk)>
H(pk) = BLAKE2b-256(personalization = "Zubit_PKHash_v1_", pk)
```

Under the *old* rules this script is anyone-can-spend (push, drop, push non-zero
→ true). That is what makes the change a soft fork: old nodes accept every
block new nodes accept. It also means **P2PQH outputs must only be used after
activation** — before it they are unprotected.

## Spend format

```
scriptSig = canonical pushes of  pk (1312 B) || sig (2420 B)
            split into 520-byte chunks (the Script element limit), last chunk shorter,
            each chunk pushed with the minimal push opcode.
```

The legacy interpreter still runs (pushes + scriptPubKey → true). When the soft
fork is active and the spent output is P2PQH, Zebra additionally requires:

1. transaction version ≥ 5;
2. `scriptSig` is *exactly* the canonical encoding of some `pk || sig` of the right lengths;
3. `H(pk)` equals the hash in the spent `scriptPubKey`;
4. `ML-DSA-44.Verify(pk, M, sig, ctx) = true` with
   `M = ZIP 244 sighash(SIGHASH_ALL, this input)` and `ctx = "Zubit-v1"`.

Any failure → the transaction is invalid.

## What is and isn't quantum-resistant

- Funds in P2PQH outputs, after activation: protected by ML-DSA-44 (and BLAKE2b
  for the address commitment). An attacker who sees the pending spend learns
  `pk` and a signature on *that* sighash only; producing a signature for a
  different transaction requires breaking ML-DSA.
- Ordinary t-addresses, Sapling, Orchard: unchanged, not covered.
- Migration (moving funds from old addresses into P2PQH) still uses an ECDSA /
  RedDSA signature once; it must happen before a quantum attacker exists.

## Costs

A P2PQH spend adds about 3.75 KB to the transaction. Under ZIP 317 that is
~25 extra logical actions (≈ 0.00125 ZEC at 5000 zats/action); the exact fee
rule for such inputs is an open question for the ZIP.

## Work plan

1. `zebra-chain`: `qr_soft_fork_height` parameter (builder, regtest, accessor), tests.
2. `zebra-network`: config plumbing so regtest/custom testnets can set it.
3. `zebra-script`: `qr` module (template, encoding, verification) + unit tests with real ML-DSA keys.
4. `zebra-consensus`: enable the rule when active; tests for accept / wrong key / bad sig / wrong tx.
5. `zubit-wallet` (separate tool crate): keygen, P2PQH script, build + sign v5 transactions, talk to zebrad RPC.
6. Regtest demo script + README; draft ZIP text.

## Build prerequisites (Windows)

Rust (pinned by `rust-toolchain.toml`), Visual Studio C++ tools, and
**LLVM/libclang** (needed by bindgen for RocksDB and libzcash_script; the fork's
`.cargo/config.toml` points `LIBCLANG_PATH` at `C:\Program Files\LLVM\bin`).
`protoc` is not required (zebra-rpc falls back to pre-generated files).

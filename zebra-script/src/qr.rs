//! Zubit: pay-to-post-quantum-pubkey-hash (P2PQH) outputs, spent with ML-DSA-44 (FIPS 204).
//!
//! This is a research soft fork, not part of the Zcash protocol. See `DESIGN.md` in the
//! Zubit repository.
//!
//! # Output
//!
//! ```text
//! scriptPubKey = 0x04 "ZUB1" OP_DROP 0x20 <BLAKE2b-256("Zubit_PKHash_v1_", pk)>   (39 bytes)
//! ```
//!
//! Under the legacy script rules this evaluates to true for any `scriptSig` that only pushes
//! data, which is what makes the rule a soft fork.
//!
//! # Spend
//!
//! `scriptSig` is `pk || sig` split into 520-byte chunks (the Script element size limit), each
//! pushed with its minimal push opcode. When the soft fork is active the spend must also carry a
//! valid ML-DSA-44 signature by `pk` over the ZIP 244 `SIGHASH_ALL` digest of this input, with
//! context string [`ML_DSA_CONTEXT`].

use fips204::{
    ml_dsa_44,
    traits::{SerDes as _, Verifier as _},
};
use thiserror::Error;

/// Size of an ML-DSA-44 public key in bytes.
pub const PK_LEN: usize = ml_dsa_44::PK_LEN;

/// Size of an ML-DSA-44 signature in bytes.
pub const SIG_LEN: usize = ml_dsa_44::SIG_LEN;

/// The script element size limit, which bounds each chunk of the spend encoding.
pub const MAX_CHUNK: usize = 520;

/// Magic bytes identifying a P2PQH output (version 1).
pub const MAGIC: &[u8; 4] = b"ZUB1";

/// BLAKE2b personalization for the public key commitment.
pub const PK_HASH_PERSONALIZATION: &[u8; 16] = b"Zubit_PKHash_v1_";

/// FIPS 204 context string bound into every Zubit signature.
pub const ML_DSA_CONTEXT: &[u8] = b"Zubit-v1";

/// Length of a P2PQH `scriptPubKey`.
pub const LOCK_SCRIPT_LEN: usize = 1 + 4 + 1 + 1 + 32;

/// Exact length of a canonical P2PQH `scriptSig` (see [`encode_spend`]).
pub const SPEND_SCRIPT_SIG_LEN: usize = spend_script_sig_len();

const fn push_overhead(len: usize) -> usize {
    if len <= 75 {
        1
    } else if len <= 255 {
        2
    } else {
        3
    }
}

const fn spend_script_sig_len() -> usize {
    let payload = PK_LEN + SIG_LEN;
    let full_chunks = payload / MAX_CHUNK;
    let last = payload % MAX_CHUNK;
    let mut len = payload + full_chunks * push_overhead(MAX_CHUNK);
    if last > 0 {
        len += push_overhead(last);
    }
    len
}

const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_DROP: u8 = 0x75;

/// Why a P2PQH spend was rejected.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum QrError {
    /// P2PQH outputs can only be spent by v5 or later transactions.
    #[error("P2PQH outputs can only be spent by v5+ transactions")]
    UnsupportedTransactionVersion,
    /// The `scriptSig` is not the canonical encoding of an ML-DSA-44 key and signature.
    #[error("scriptSig is not a canonical P2PQH spend")]
    MalformedSpend,
    /// The public key does not match the hash committed to in the output.
    #[error("public key does not match the P2PQH output")]
    PublicKeyMismatch,
    /// The public key bytes are not a valid ML-DSA-44 public key.
    #[error("invalid ML-DSA-44 public key")]
    InvalidPublicKey,
    /// The ML-DSA-44 signature does not verify.
    #[error("invalid ML-DSA-44 signature")]
    InvalidSignature,
}

/// Returns the P2PQH public key commitment for `pk`.
pub fn pk_hash(pk: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(PK_HASH_PERSONALIZATION)
        .hash(pk);
    let mut out = [0; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Builds the P2PQH `scriptPubKey` committing to `pk`.
pub fn lock_script(pk: &[u8; PK_LEN]) -> Vec<u8> {
    lock_script_for_hash(&pk_hash(pk))
}

/// Builds the P2PQH `scriptPubKey` for an already-computed key hash.
pub fn lock_script_for_hash(hash: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(LOCK_SCRIPT_LEN);
    script.push(4);
    script.extend_from_slice(MAGIC);
    script.push(OP_DROP);
    script.push(32);
    script.extend_from_slice(hash);
    script
}

/// If `script_pub_key` is a P2PQH output, returns the committed key hash.
pub fn parse_lock_script(script_pub_key: &[u8]) -> Option<[u8; 32]> {
    if script_pub_key.len() != LOCK_SCRIPT_LEN
        || script_pub_key[0] != 4
        || &script_pub_key[1..5] != MAGIC
        || script_pub_key[5] != OP_DROP
        || script_pub_key[6] != 32
    {
        return None;
    }
    let mut hash = [0; 32];
    hash.copy_from_slice(&script_pub_key[7..]);
    Some(hash)
}

fn push(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    match len {
        // Chunks are never empty, and 1-byte chunks are pushed as data (not OP_1..OP_16), so
        // the encoding is a pure function of the bytes.
        1..=75 => out.push(u8::try_from(len).expect("len <= 75 fits in u8")),
        76..=255 => {
            out.push(OP_PUSHDATA1);
            out.push(u8::try_from(len).expect("len <= 255 fits in u8"));
        }
        _ => {
            out.push(OP_PUSHDATA2);
            out.extend_from_slice(
                &u16::try_from(len)
                    .expect("chunks are at most MAX_CHUNK bytes, which fits in u16")
                    .to_le_bytes(),
            );
        }
    }
    out.extend_from_slice(data);
}

/// Encodes an ML-DSA-44 public key and signature as a canonical P2PQH `scriptSig`.
pub fn encode_spend(pk: &[u8; PK_LEN], sig: &[u8; SIG_LEN]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PK_LEN + SIG_LEN);
    payload.extend_from_slice(pk);
    payload.extend_from_slice(sig);

    let mut out = Vec::with_capacity(payload.len() + 3 * payload.len().div_ceil(MAX_CHUNK));
    for chunk in payload.chunks(MAX_CHUNK) {
        push(&mut out, chunk);
    }
    out
}

/// Decodes a canonical P2PQH `scriptSig` into `(pk, sig)`.
///
/// Returns `None` unless `script_sig` is byte-for-byte what [`encode_spend`] would produce, so
/// there is exactly one valid encoding of each spend.
#[allow(clippy::type_complexity)]
pub fn decode_spend(script_sig: &[u8]) -> Option<(Box<[u8; PK_LEN]>, Box<[u8; SIG_LEN]>)> {
    // Bound the work before parsing: the canonical encoding has a fixed length.
    if script_sig.len() != SPEND_SCRIPT_SIG_LEN {
        return None;
    }

    let mut payload = Vec::with_capacity(PK_LEN + SIG_LEN);
    let mut i = 0;
    while i < script_sig.len() {
        let opcode = script_sig[i];
        i += 1;
        let len = match opcode {
            1..=75 => usize::from(opcode),
            OP_PUSHDATA1 => {
                let len = usize::from(*script_sig.get(i)?);
                i += 1;
                len
            }
            OP_PUSHDATA2 => {
                let bytes = script_sig.get(i..i + 2)?;
                i += 2;
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            }
            _ => return None,
        };
        payload.extend_from_slice(script_sig.get(i..i + len)?);
        i += len;
    }

    if payload.len() != PK_LEN + SIG_LEN {
        return None;
    }
    let pk: Box<[u8; PK_LEN]> = payload[..PK_LEN].to_vec().try_into().ok()?;
    let sig: Box<[u8; SIG_LEN]> = payload[PK_LEN..].to_vec().try_into().ok()?;

    (encode_spend(&pk, &sig) == script_sig).then_some((pk, sig))
}

/// Verifies a P2PQH spend.
///
/// `sighash` must be the ZIP 244 `SIGHASH_ALL` signature digest for this input, and
/// `tx_version` the version of the spending transaction.
pub fn verify_spend(
    tx_version: u32,
    committed_hash: &[u8; 32],
    script_sig: &[u8],
    sighash: &[u8; 32],
) -> Result<(), QrError> {
    if tx_version < 5 {
        return Err(QrError::UnsupportedTransactionVersion);
    }
    let (pk_bytes, sig_bytes) = decode_spend(script_sig).ok_or(QrError::MalformedSpend)?;
    if pk_hash(pk_bytes.as_slice()) != *committed_hash {
        return Err(QrError::PublicKeyMismatch);
    }
    let pk =
        ml_dsa_44::PublicKey::try_from_bytes(*pk_bytes).map_err(|_| QrError::InvalidPublicKey)?;
    if pk.verify(sighash, &*sig_bytes, ML_DSA_CONTEXT) {
        Ok(())
    } else {
        Err(QrError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use fips204::traits::{KeyGen as _, Signer as _};

    use super::*;

    fn keypair(seed: u8) -> ([u8; PK_LEN], ml_dsa_44::PrivateKey) {
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&[seed; 32]);
        (pk.into_bytes(), sk)
    }

    fn sign(sk: &ml_dsa_44::PrivateKey, msg: &[u8; 32]) -> [u8; SIG_LEN] {
        sk.try_sign_with_seed(&[7; 32], msg, ML_DSA_CONTEXT)
            .expect("signing with a fixed seed cannot fail")
    }

    #[test]
    fn sizes_are_as_designed() {
        assert_eq!(PK_LEN, 1312);
        assert_eq!(SIG_LEN, 2420);
        assert_eq!(LOCK_SCRIPT_LEN, 39);
        // 7 chunks of 520 bytes (PUSHDATA2) + one of 92 bytes (PUSHDATA1)
        assert_eq!(SPEND_SCRIPT_SIG_LEN, 3732 + 7 * 3 + 2);
    }

    #[test]
    fn lock_script_roundtrip() {
        let (pk, _) = keypair(1);
        let script = lock_script(&pk);
        assert_eq!(script.len(), LOCK_SCRIPT_LEN);
        assert_eq!(parse_lock_script(&script), Some(pk_hash(&pk)));

        // Near-misses are not P2PQH.
        let mut wrong_magic = script.clone();
        wrong_magic[4] ^= 1;
        assert_eq!(parse_lock_script(&wrong_magic), None);
        assert_eq!(parse_lock_script(&script[..38]), None);
        // P2PKH is not P2PQH.
        let p2pkh = [&[0x76, 0xa9, 0x14][..], &[0; 20], &[0x88, 0xac]].concat();
        assert_eq!(parse_lock_script(&p2pkh), None);
    }

    #[test]
    fn spend_encoding_is_canonical() {
        let (pk, sk) = keypair(2);
        let sig = sign(&sk, &[3; 32]);
        let enc = encode_spend(&pk, &sig);
        assert_eq!(enc.len(), SPEND_SCRIPT_SIG_LEN);
        let (dpk, dsig) = decode_spend(&enc).expect("canonical encoding decodes");
        assert_eq!(*dpk, pk);
        assert_eq!(*dsig, sig);

        // A different chunking of the same bytes, with the same total length, is rejected:
        // re-push the final 92-byte chunk (PUSHDATA1, 2 bytes of overhead) as 75 + 17 bytes
        // (two direct pushes, also 2 bytes of overhead).
        let last_start = enc.len() - 92;
        assert_eq!(enc[last_start - 2..last_start], [OP_PUSHDATA1, 92]);
        let mut alt = enc[..last_start - 2].to_vec();
        push(&mut alt, &enc[last_start..last_start + 75]);
        push(&mut alt, &enc[last_start + 75..]);
        assert_eq!(alt.len(), enc.len());
        assert!(decode_spend(&alt).is_none());

        // Truncated and extended encodings are rejected.
        assert!(decode_spend(&enc[..enc.len() - 1]).is_none());
        let mut longer = enc.clone();
        longer.push(0x51);
        assert!(decode_spend(&longer).is_none());
    }

    #[test]
    fn verify_accepts_valid_spend() {
        let (pk, sk) = keypair(4);
        let sighash = [9; 32];
        let script_sig = encode_spend(&pk, &sign(&sk, &sighash));
        assert_eq!(
            verify_spend(5, &pk_hash(&pk), &script_sig, &sighash),
            Ok(())
        );
    }

    /// Serializes a transparent-only v5 transaction with one input and one output.
    fn v5_tx(branch_id: u32, script_sig: &[u8]) -> Vec<u8> {
        fn compact(n: usize) -> Vec<u8> {
            if n < 0xfd {
                vec![u8::try_from(n).expect("checked")]
            } else {
                let mut v = vec![0xfd];
                v.extend_from_slice(
                    &u16::try_from(n)
                        .expect("test scripts are small")
                        .to_le_bytes(),
                );
                v
            }
        }
        let out_script = [0x51u8];
        let mut v = Vec::new();
        v.extend_from_slice(&0x8000_0005u32.to_le_bytes());
        v.extend_from_slice(&0x26A7_270Au32.to_le_bytes());
        v.extend_from_slice(&branch_id.to_le_bytes());
        v.extend_from_slice(&[0; 8]); // lock_time, expiry_height
        v.push(1);
        v.extend_from_slice(&[0xab; 32]);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend(compact(script_sig.len()));
        v.extend_from_slice(script_sig);
        v.extend_from_slice(&u32::MAX.to_le_bytes());
        v.push(1);
        v.extend_from_slice(&90_000i64.to_le_bytes());
        v.extend(compact(out_script.len()));
        v.extend_from_slice(&out_script);
        v.extend_from_slice(&[0, 0, 0]);
        v
    }

    #[test]
    fn full_script_verification_with_and_without_soft_fork() {
        use std::sync::Arc;

        use zebra_chain::{
            amount::Amount, parameters::NetworkUpgrade, serialization::ZcashDeserializeInto as _,
            transaction::Transaction, transparent,
        };

        use crate::{CachedFfiTransaction, Error};

        let nu = NetworkUpgrade::Nu5;
        let branch_id = u32::from(nu.branch_id().expect("NU5 has a branch id"));
        let (pk, sk) = keypair(10);
        let lock = lock_script(&pk);
        let prev = Arc::new(vec![transparent::Output {
            value: Amount::try_from(100_000).expect("valid amount"),
            lock_script: transparent::Script::new(&lock),
        }]);

        let check = |script_sig: &[u8], qr_active: bool| -> Result<(), Error> {
            let tx: Transaction = v5_tx(branch_id, script_sig)
                .zcash_deserialize_into()
                .expect("test transaction deserializes");
            CachedFfiTransaction::new(Arc::new(tx), prev.clone(), nu)
                .expect("sighasher builds")
                .with_qr_rules(qr_active)
                .is_valid(0)
        };

        // The sighash does not depend on scriptSig, so compute it once from an unsigned copy.
        let unsigned: Transaction = v5_tx(branch_id, &[])
            .zcash_deserialize_into()
            .expect("test transaction deserializes");
        let sighash = unsigned
            .sighash(
                nu,
                zebra_chain::transaction::HashType::ALL,
                prev.clone(),
                Some((0, lock.clone())),
            )
            .expect("sighash computes")
            .0;
        let good = encode_spend(&pk, &sign(&sk, &sighash));

        // Valid ML-DSA spend: accepted before and after activation.
        assert_eq!(check(&good, false), Ok(()));
        assert_eq!(check(&good, true), Ok(()));

        // Legacy-style spend with no ML-DSA signature: valid under the old rules
        // (anyone-can-spend), rejected once the soft fork is active.
        assert_eq!(check(&[0x51], false), Ok(()));
        assert_eq!(
            check(&[0x51], true),
            Err(Error::Qr(QrError::MalformedSpend))
        );

        // Signature over a different message.
        let mut other = sighash;
        other[0] ^= 1;
        let wrong = encode_spend(&pk, &sign(&sk, &other));
        assert_eq!(
            check(&wrong, true),
            Err(Error::Qr(QrError::InvalidSignature))
        );
    }

    #[test]
    fn verify_rejects_bad_spends() {
        let (pk, sk) = keypair(5);
        let (other_pk, other_sk) = keypair(6);
        let sighash = [9; 32];
        let good = encode_spend(&pk, &sign(&sk, &sighash));

        assert_eq!(
            verify_spend(4, &pk_hash(&pk), &good, &sighash),
            Err(QrError::UnsupportedTransactionVersion)
        );
        // Signed a different transaction.
        assert_eq!(
            verify_spend(5, &pk_hash(&pk), &good, &[8; 32]),
            Err(QrError::InvalidSignature)
        );
        // Key does not match the output.
        assert_eq!(
            verify_spend(5, &pk_hash(&other_pk), &good, &sighash),
            Err(QrError::PublicKeyMismatch)
        );
        // Right key, signature by someone else.
        let forged = encode_spend(&pk, &sign(&other_sk, &sighash));
        assert_eq!(
            verify_spend(5, &pk_hash(&pk), &forged, &sighash),
            Err(QrError::InvalidSignature)
        );
        // Flipped signature bit.
        let mut sig = sign(&sk, &sighash);
        sig[100] ^= 1;
        assert_eq!(
            verify_spend(5, &pk_hash(&pk), &encode_spend(&pk, &sig), &sighash),
            Err(QrError::InvalidSignature)
        );
        // Not a spend at all.
        assert_eq!(
            verify_spend(5, &pk_hash(&pk), &[0x51], &sighash),
            Err(QrError::MalformedSpend)
        );
        // Wrong context string.
        let wrong_ctx = sk
            .try_sign_with_seed(&[7; 32], &sighash, b"other")
            .expect("signing with a fixed seed cannot fail");
        assert_eq!(
            verify_spend(5, &pk_hash(&pk), &encode_spend(&pk, &wrong_ctx), &sighash),
            Err(QrError::InvalidSignature)
        );
    }
}

//! Zubit demo wallet.
//!
//! Regtest only. Builds transparent-only v5 transactions by hand, computes their ZIP 244
//! sighash with `zebra-chain`, and signs P2PQH spends with ML-DSA-44.
//!
//! ```text
//! zubit-wallet keygen <key.json>            create an ML-DSA-44 key, print its P2PQH script
//! zubit-wallet miner-address                print the Regtest miner address used by the demo
//! zubit-wallet demo <rpc host:port> <key.json>
//! ```

use std::{
    error::Error,
    fs,
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::Arc,
};

use fips204::{
    ml_dsa_44,
    traits::{KeyGen as _, SerDes as _, Signer as _},
};
use rand::RngCore as _;
use ripemd::Ripemd160;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use zebra_chain::{
    amount::{Amount, NonNegative},
    parameters::NetworkUpgrade,
    serialization::ZcashDeserializeInto as _,
    transaction::{HashType, Transaction},
    transparent,
};
use zebra_script::qr;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The demo's funding source: a P2SH output whose redeem script is `OP_TRUE`.
/// Anyone can spend it, which is fine on a private Regtest chain and avoids ECDSA entirely.
const OP_TRUE: u8 = 0x51;
/// Base58Check prefix for Testnet/Regtest P2SH addresses (`t2...`).
const REGTEST_P2SH_PREFIX: [u8; 2] = [0x1c, 0xba];
/// ZIP 317 marginal fee per logical action, in zatoshis.
const MARGINAL_FEE: i64 = 5_000;
/// ZIP 317 grace actions.
const GRACE_ACTIONS: i64 = 2;
/// Coinbase outputs can be spent after this many confirmations.
const COINBASE_MATURITY: u32 = 100;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["keygen", path] => keygen(path),
        ["miner-address"] => {
            println!("{}", miner_address());
            Ok(())
        }
        ["demo", rpc, key] => demo(rpc, key),
        _ => Err(
            "usage: zubit-wallet keygen <key.json> | miner-address | demo <host:port> <key.json>"
                .into(),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Keys and scripts
// ---------------------------------------------------------------------------------------------

struct Key {
    pk: [u8; qr::PK_LEN],
    sk: ml_dsa_44::PrivateKey,
}

impl Key {
    fn from_seed(seed: &[u8; 32]) -> Self {
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
        Key {
            pk: pk.into_bytes(),
            sk,
        }
    }

    fn lock_script(&self) -> Vec<u8> {
        qr::lock_script(&self.pk)
    }

    fn sign(&self, sighash: &[u8; 32]) -> Result<[u8; qr::SIG_LEN]> {
        Ok(self.sk.try_sign(sighash, qr::ML_DSA_CONTEXT)?)
    }
}

fn keygen(path: &str) -> Result<()> {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    fs::write(
        path,
        json!({ "ml_dsa_44_seed": hex::encode(seed) }).to_string(),
    )?;
    let key = Key::from_seed(&seed);
    println!("wrote {path}");
    println!("P2PQH scriptPubKey: {}", hex::encode(key.lock_script()));
    Ok(())
}

fn load_key(path: &str) -> Result<Key> {
    let v: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let seed_hex = v["ml_dsa_44_seed"]
        .as_str()
        .ok_or("key file has no ml_dsa_44_seed")?;
    let seed: [u8; 32] = hex::decode(seed_hex)?
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    Ok(Key::from_seed(&seed))
}

fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

fn p2sh_true_script() -> Vec<u8> {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&hash160(&[OP_TRUE]));
    s.push(0x87);
    s
}

fn miner_address() -> String {
    let mut payload = REGTEST_P2SH_PREFIX.to_vec();
    payload.extend_from_slice(&hash160(&[OP_TRUE]));
    bs58::encode(payload).with_check().into_string()
}

// ---------------------------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------------------------

struct TxIn {
    /// Txid in RPC (display) byte order.
    txid: String,
    vout: u32,
    script_sig: Vec<u8>,
}

struct TxOut {
    value: i64,
    script: Vec<u8>,
}

fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![u8::try_from(n).expect("n <= 0xfc")],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend_from_slice(&u16::try_from(n).expect("n <= 0xffff").to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xfe];
            v.extend_from_slice(
                &u32::try_from(n)
                    .expect("scripts are far below 4 GiB")
                    .to_le_bytes(),
            );
            v
        }
    }
}

fn ser_input(i: &TxIn) -> Result<Vec<u8>> {
    let mut txid = hex::decode(&i.txid)?;
    txid.reverse();
    let mut v = txid;
    v.extend_from_slice(&i.vout.to_le_bytes());
    v.extend(compact_size(i.script_sig.len()));
    v.extend_from_slice(&i.script_sig);
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    Ok(v)
}

fn ser_output(o: &TxOut) -> Vec<u8> {
    let mut v = o.value.to_le_bytes().to_vec();
    v.extend(compact_size(o.script.len()));
    v.extend_from_slice(&o.script);
    v
}

/// Serializes a transparent-only v5 transaction (ZIP 225).
fn build_v5(branch_id: u32, inputs: &[TxIn], outputs: &[TxOut]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x8000_0005u32.to_le_bytes());
    v.extend_from_slice(&0x26A7_270Au32.to_le_bytes());
    v.extend_from_slice(&branch_id.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // lock_time
    v.extend_from_slice(&0u32.to_le_bytes()); // expiry_height: none
    v.extend(compact_size(inputs.len()));
    for i in inputs {
        v.extend(ser_input(i)?);
    }
    v.extend(compact_size(outputs.len()));
    for o in outputs {
        v.extend(ser_output(o));
    }
    v.extend_from_slice(&[0, 0, 0]); // no Sapling spends/outputs, no Orchard actions
    Ok(v)
}

/// ZIP 317 conventional fee for a transparent-only transaction.
fn zip317_fee(inputs: &[TxIn], outputs: &[TxOut]) -> Result<i64> {
    let in_size: usize = inputs
        .iter()
        .map(|i| ser_input(i).map(|v| v.len()))
        .sum::<Result<_>>()?;
    let out_size: usize = outputs.iter().map(|o| ser_output(o).len()).sum();
    let actions = in_size.div_ceil(150).max(out_size.div_ceil(34));
    Ok(MARGINAL_FEE * i64::try_from(actions)?.max(GRACE_ACTIONS))
}

/// ZIP 244 SIGHASH_ALL digest for `input_index`, computed by zebra-chain.
fn sighash_all(
    branch_id: u32,
    raw_unsigned: &[u8],
    spent: &[(i64, Vec<u8>)],
    input_index: usize,
) -> Result<[u8; 32]> {
    let tx: Transaction = raw_unsigned.zcash_deserialize_into()?;
    let nu = NetworkUpgrade::try_from(branch_id)?;
    let prev: Vec<transparent::Output> = spent
        .iter()
        .map(|(value, script)| {
            Ok(transparent::Output {
                value: Amount::<NonNegative>::try_from(*value)?,
                lock_script: transparent::Script::new(script),
            })
        })
        .collect::<Result<_>>()?;
    let script_code = spent[input_index].1.clone();
    Ok(tx
        .sighash(
            nu,
            HashType::ALL,
            Arc::new(prev),
            Some((input_index, script_code)),
        )?
        .0)
}

// ---------------------------------------------------------------------------------------------
// JSON-RPC over plain HTTP (Regtest node on localhost, cookie auth disabled)
// ---------------------------------------------------------------------------------------------

struct Rpc {
    addr: String,
}

impl Rpc {
    fn call(&self, method: &str, params: Value) -> Result<std::result::Result<Value, String>> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let mut stream = TcpStream::connect(&self.addr)?;
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            body.len(),
            body
        )?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let text = String::from_utf8(response)?;
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or("malformed HTTP response")?;
        let body = if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            dechunk(body)?
        } else {
            body.to_string()
        };
        let v: Value = serde_json::from_str(&body)?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Ok(Err(err["message"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string()));
        }
        Ok(Ok(v["result"].clone()))
    }

    fn ok(&self, method: &str, params: Value) -> Result<Value> {
        self.call(method, params)?
            .map_err(|e| format!("{method} failed: {e}").into())
    }
}

fn dechunk(mut s: &str) -> Result<String> {
    let mut out = String::new();
    loop {
        let (size, rest) = s.split_once("\r\n").ok_or("bad chunk")?;
        let size = usize::from_str_radix(size.trim(), 16)?;
        if size == 0 {
            return Ok(out);
        }
        out.push_str(rest.get(..size).ok_or("short chunk")?);
        s = rest.get(size + 2..).ok_or("short chunk")?;
    }
}

// ---------------------------------------------------------------------------------------------
// End-to-end demo
// ---------------------------------------------------------------------------------------------

fn next_branch_id(rpc: &Rpc) -> Result<u32> {
    let info = rpc.ok("getblockchaininfo", json!([]))?;
    let hex = info["consensus"]["nextblock"]
        .as_str()
        .ok_or("getblockchaininfo has no consensus.nextblock")?;
    Ok(u32::from_str_radix(hex, 16)?)
}

fn mine(rpc: &Rpc, n: u32) -> Result<()> {
    rpc.ok("generate", json!([n]))?;
    Ok(())
}

fn confirmed_height(rpc: &Rpc, txid: &str) -> Result<Option<u64>> {
    let tx = rpc.ok("getrawtransaction", json!([txid, 1]))?;
    Ok(tx["height"].as_u64().filter(|h| *h > 0))
}

fn send(rpc: &Rpc, raw: &[u8]) -> Result<std::result::Result<String, String>> {
    Ok(rpc
        .call("sendrawtransaction", json!([hex::encode(raw)]))?
        .map(|v| v.as_str().unwrap_or_default().to_string()))
}

fn expect_rejected(rpc: &Rpc, label: &str, raw: &[u8]) -> Result<()> {
    match send(rpc, raw)? {
        Err(e) => {
            println!("  [ok] rejected: {label}\n       node said: {e}");
            Ok(())
        }
        Ok(txid) => {
            Err(format!("{label} was ACCEPTED ({txid}) — the soft fork is not enforced").into())
        }
    }
}

fn demo(rpc_addr: &str, key_path: &str) -> Result<()> {
    let rpc = Rpc {
        addr: rpc_addr.to_string(),
    };
    let key = load_key(key_path)?;
    let p2pqh = key.lock_script();
    let p2sh_true = p2sh_true_script();

    println!("== Zubit Regtest demo ==");
    println!(
        "P2PQH scriptPubKey ({} bytes): {}",
        p2pqh.len(),
        hex::encode(&p2pqh)
    );

    // 1. Mine a mature coinbase paying the demo's P2SH(OP_TRUE) miner address.
    let start = rpc
        .ok("getblockcount", json!([]))?
        .as_u64()
        .ok_or("bad getblockcount")?;
    println!(
        "\n[1] mining {} blocks (tip was {start})",
        COINBASE_MATURITY + 1
    );
    mine(&rpc, COINBASE_MATURITY + 1)?;
    let coinbase_height = start + 1;
    let block = rpc.ok("getblock", json!([coinbase_height.to_string(), 1]))?;
    let coinbase_txid = block["tx"][0]
        .as_str()
        .ok_or("block has no coinbase")?
        .to_string();
    let coinbase = rpc.ok("getrawtransaction", json!([coinbase_txid, 1]))?;
    let (cb_vout, cb_value) = coinbase["vout"]
        .as_array()
        .ok_or("coinbase has no vout")?
        .iter()
        .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(&hex::encode(&p2sh_true)))
        .map(|o| (o["n"].as_u64(), o["valueZat"].as_i64()))
        .and_then(|(n, v)| Some((u32::try_from(n?).ok()?, v?)))
        .ok_or("coinbase does not pay the demo miner address — check mining.miner_address")?;
    println!("    coinbase {coinbase_txid}:{cb_vout} = {cb_value} zat");

    // 2. Fund a P2PQH output from the coinbase.
    let branch_id = next_branch_id(&rpc)?;
    println!("\n[2] funding P2PQH output (consensus branch {branch_id:08x})");
    let fund_in = [TxIn {
        txid: coinbase_txid.clone(),
        vout: cb_vout,
        script_sig: vec![1, OP_TRUE],
    }];
    let mut fund_out = [TxOut {
        value: 0,
        script: p2pqh.clone(),
    }];
    let fee = zip317_fee(&fund_in, &fund_out)?;
    fund_out[0].value = cb_value - fee;
    let fund_raw = build_v5(branch_id, &fund_in, &fund_out)?;
    let fund_txid = send(&rpc, &fund_raw)?.map_err(|e| format!("funding tx rejected: {e}"))?;
    mine(&rpc, 1)?;
    let h = confirmed_height(&rpc, &fund_txid)?.ok_or("funding tx was not mined")?;
    let pq_value = fund_out[0].value;
    println!(
        "    {fund_txid} mined at height {h}: {pq_value} zat locked to ML-DSA-44 key (fee {fee})"
    );

    // 3. Build the spend back to P2SH(OP_TRUE).
    let branch_id = next_branch_id(&rpc)?;
    let spent = [(pq_value, p2pqh.clone())];
    let dummy_sig = [0u8; qr::SIG_LEN];
    let placeholder = qr::encode_spend(&key.pk, &dummy_sig);
    let mut spend_in = [TxIn {
        txid: fund_txid.clone(),
        vout: 0,
        script_sig: placeholder,
    }];
    let mut spend_out = [TxOut {
        value: 0,
        script: p2sh_true.clone(),
    }];
    let fee = zip317_fee(&spend_in, &spend_out)?;
    spend_out[0].value = pq_value - fee;

    // v5 sighashes do not cover scriptSig, so an empty one gives the same digest.
    spend_in[0].script_sig = Vec::new();
    let unsigned = build_v5(branch_id, &spend_in, &spend_out)?;
    let sighash = sighash_all(branch_id, &unsigned, &spent, 0)?;
    println!(
        "\n[3] spend sighash (ZIP 244, SIGHASH_ALL): {}",
        hex::encode(sighash)
    );

    let with_script_sig = |script_sig: Vec<u8>| -> Result<Vec<u8>> {
        let inputs = [TxIn {
            txid: fund_txid.clone(),
            vout: 0,
            script_sig,
        }];
        build_v5(branch_id, &inputs, &spend_out)
    };

    // 4. Spends that the old rules would accept, but Zubit must reject.
    println!("\n[4] invalid spends");
    expect_rejected(
        &rpc,
        "legacy-style spend with no ML-DSA signature (valid under old rules)",
        &with_script_sig(vec![1, OP_TRUE])?,
    )?;

    let mut bad_sig = key.sign(&sighash)?;
    bad_sig[0] ^= 1;
    expect_rejected(
        &rpc,
        "correct key, corrupted signature",
        &with_script_sig(qr::encode_spend(&key.pk, &bad_sig))?,
    )?;

    let mut other_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut other_seed);
    let attacker = Key::from_seed(&other_seed);
    expect_rejected(
        &rpc,
        "attacker's own key and valid signature",
        &with_script_sig(qr::encode_spend(&attacker.pk, &attacker.sign(&sighash)?))?,
    )?;

    let mut other_msg = sighash;
    other_msg[31] ^= 1;
    expect_rejected(
        &rpc,
        "owner's signature over a different transaction",
        &with_script_sig(qr::encode_spend(&key.pk, &key.sign(&other_msg)?))?,
    )?;

    // 5. The real spend.
    println!("\n[5] valid ML-DSA-44 spend");
    let signed = with_script_sig(qr::encode_spend(&key.pk, &key.sign(&sighash)?))?;
    let spend_txid = send(&rpc, &signed)?.map_err(|e| format!("valid spend rejected: {e}"))?;
    mine(&rpc, 1)?;
    let h = confirmed_height(&rpc, &spend_txid)?.ok_or("spend was not mined")?;
    println!(
        "    {spend_txid} mined at height {h} ({} bytes, fee {fee} zat)",
        signed.len()
    );

    println!(
        "\nDemo passed: the P2PQH output could only be spent with the owner's ML-DSA-44 signature."
    );
    Ok(())
}

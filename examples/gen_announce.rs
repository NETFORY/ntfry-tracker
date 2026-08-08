/*
 * Self-contained helper: print a VALID (or tampered) SmartNet announce request
 * as JSON to stdout, for e2e testing the tracker with curl.
 *
 *   cargo run --example gen_announce              # valid → accepted
 *   cargo run --example gen_announce tamper       # name changed after signing → rejected
 *   cargo run --example gen_announce badid        # id not matching pubkey → rejected
 */

use ripemd::Ripemd160;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let mut r = [0u8; 32];
    r.copy_from_slice(&h.finalize());
    r
}

fn address_from_pubkey(pk_comp: &[u8]) -> String {
    let mut rip = Ripemd160::new();
    rip.update(pk_comp);
    let hash = rip.finalize();
    let mut payload = Vec::with_capacity(21);
    payload.push(0x3f);
    payload.extend_from_slice(&hash);
    bs58::encode(payload).with_check().into_string()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();

    let secret = "smartnet-test-app/1/0";
    let sk = SecretKey::from_slice(&sha256(secret.as_bytes())).unwrap();
    let secp = Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pk_comp = pk.serialize();
    let public_key = hex::encode(pk_comp);
    let id = address_from_pubkey(&pk_comp);

    let name = "Test dApp";
    let description = "demo app for tracker e2e";
    let merkle = "deadbeefcafef00d";

    let digest = sha256(format!("{}|{}|{}|{}", id, name, description, merkle).as_bytes());
    let msg = Message::from_digest_slice(&digest).unwrap();
    let signature = hex::encode(secp.sign_ecdsa(&msg, &sk).serialize_compact());

    // mutate AFTER signing to simulate spoofing
    let out_name = if mode == "tamper" { "Hacked dApp" } else { name };
    let out_id = if mode == "badid" {
        "SXdXoyUAjUyyCC5LES6KH1XS1ewbBB4Dfu".to_string()
    } else {
        id
    };

    let body = serde_json::json!({
        "node": "STestNodeAddress0000000000000000000",
        "endpointId": "test-endpoint-id-0001",
        "apps": [{
            "id": out_id,
            "name": out_name,
            "description": description,
            "tags": ["demo", "test"],
            "merkle": merkle,
            "hash": "blobhash1234567890",
            "signature": signature,
            "publicKey": public_key,
        }]
    });
    println!("{}", body);
}

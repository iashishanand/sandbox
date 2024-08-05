import * as musig from "@cmdcode/musig2";
import bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { Buff } from "@cmdcode/buff";
import { Buffer } from "node:buffer";
import * as fs from "node:fs";

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.testnet;

// Let's create an example list of signers.
const signers = ["alice", "bob"];
// We'll store each member's wallet in an array.
const wallets = [];

// Setup a dummy wallet for each signer.
for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = Buff.random(32);
    const nonce = Buff.random(64);
    // Create a pair of signing keys.
    const [sec_key, pub_key] = musig.keys.get_keypair(secret);
    // Deriving Taproot address from the pub key
    const { address } = bitcoin.payments.p2tr({
        pubkey: Buffer.from(pub_key, "hex"),
        network,
    });
    // Create a pair of nonces (numbers only used once).
    const [sec_nonce, pub_nonce] = musig.keys.get_nonce_pair(nonce);
    // Add the member's wallet to the array.
    wallets.push({
        name,
        address,
        sec_key,
        pub_key,
        sec_nonce,
        pub_nonce,
    });
}

const group_keys = wallets.map((e) => e.pub_key);

const { group_pubkey } = musig.get_key_ctx(group_keys);

const p2pktr = bitcoin.payments.p2tr({
    pubkey: Buffer.from(group_pubkey, "hex"),
    network,
});

let output = `Wallets : \n${JSON.stringify(wallets)}\n\n`;
output += `Combined Taproot address : \n${p2pktr.address}\n\n`;
fs.writeFileSync("wallet.txt", output);

console.log("Wallets : ", wallets);
console.log("Taproot address : ", p2pktr.address);
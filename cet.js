import * as musig from "@cmdcode/musig2";
import bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { Buff } from "@cmdcode/buff";
import { schnorr } from "@noble/curves/secp256k1";
import { Buffer } from "node:buffer";
import { Transaction } from "bitcoinjs-lib";

bitcoin.initEccLib(ecc);
const TESTNET = bitcoin.networks.testnet;

const wallets = [
    {
        name: "alice",
        sec_key: "6ccc11c46751edab5d9ba2acf68d0133fb67b68fa701c2ab8eddd3d98efe5595",
        pub_key: "633d066237862db2292981e8b1e191c15b6a853a8083160076a24168f83a9d57",
        sec_nonce:
            "cab3a3a5bf918e75e6835a37e8988a99b90e15d32efa67a31c5992a1d449754462a3d3468cb0d14c1c3eb4c3c3743c29c821ea2e969fcb847cff6ab137f4555f",
        pub_nonce:
            "33fce8b07af2a03c9ea546c2c231cc8a5668cb28dc95290b3650fdaeaa1ef571e1cc83c729b3838fadc9dd3d6fecf58115e890974e0187d3c75f1ca52cb3759a",
    },
    {
        name: "bob",
        sec_key: "126086e85273e375ec6a059266c92f30ba070696334633624ace6a3bf5777f4b",
        pub_key: "d6be41e01c23fb2c57c1664c58998710f88174a41f1c69fd27be91518a5a84dd",
        sec_nonce:
            "28b75dc04532f69c64ac974eae8d43bd5db60b10410fc4838ae63f80a255108baafbcc53735b698dfce5f57bbbcce233fd9bc220470be343ea2b2b77e17c471f",
        pub_nonce:
            "95f5b0ebb638e5f0d374c17c7fb3d63126a20ffb2ef1b81c2c0afeee04c5e8dc016e291f06ebc7748c7f5e084fd8c12b655b602ebe5001e627334a225fa34350",
    },
];

// Create an "adaptor" tweak to include in signing.
const adaptor_sks = [musig.keys.gen_seckey(), musig.keys.gen_seckey()];
const adapter_pks = adaptor_sks.map((e) => musig.keys.get_pubkey(e, true));

// Configure the musig options to include the key tweak.
const options = { nonce_tweaks: adapter_pks };

// Collect public keys and nonces from all signers.
const group_keys = wallets.map((e) => e.pub_key);
const group_nonces = wallets.map((e) => e.pub_nonce);

// Get the combined public key
const { group_pubkey } = musig.get_key_ctx(group_keys);

// Create a Taproot address from the x-only public key
const p2pktr = bitcoin.payments.p2tr({
    pubkey: Buffer.from(group_pubkey, "hex"),
    network: TESTNET,
});

console.log("Taproot address : ", p2pktr.address);

const utxo = {
    txid: "c08ca53cbf988a8c2d24a325e653683f5a183db7e580d0ea061c0250b903e7c5",
    vout: 1,
    value: 500000,
};

const reciever = {
    value: 10000,
    address: p2pktr.address,
};

// Building a new transaction
let transaction = new Transaction();
transaction.version = 2;
transaction.addInput(Buffer.from(utxo.txid, "hex").reverse(), utxo.vout);
transaction.addOutput(bitcoin.address.toOutputScript(reciever.address, TESTNET), reciever.value);

const signatureHash = transaction.hashForWitnessV1(
    0, // Input index
    [p2pktr.output], // Prevouts
    [utxo.value], // Amounts
    Transaction.SIGHASH_DEFAULT // Sighash type
);

let message = signatureHash;
// console.log("Message : ", message.toString('hex'));



// Combine all your collected keys into a signing session.
const ctx = musig.get_ctx(group_keys, group_nonces, Buff.from(message), options);

// Each member creates their own partial signature,
// using their own computed signing session.
const group_sigs = wallets.map((wallet) => {
    return musig.musign(ctx, wallet.sec_key, wallet.sec_nonce);
});

// Combine all the partial signatures into our final signature.
const signature = musig.combine_psigs(ctx, group_sigs);
// console.log("Signature : ", signature);

// Check the un-tweaked signature is valid.
const is_valid_untweaked = musig.verify_adapter_sig(
  ctx,
  signature,
  adapter_pks
);

console.log("Is the signature w/o adaptor secret valid : ", schnorr.verify(signature, message, ctx.group_pubkey));

console.log("Is adaptor signature correct : ", is_valid_untweaked);

console.log("Adding adaptor secret...");
// We can add the tweak to the signature to make it valid.
const adapted_sig = musig.add_sig_adapters(ctx, signature, adaptor_sks);

// Check if the signature is valid using an independent library.
const is_valid_tweaked = schnorr.verify(adapted_sig, message, ctx.group_pubkey);

console.log("Is the new signature BIP340 valid : ", is_valid_tweaked);


let tapKeySig = Buffer.from(adapted_sig);

// Check if the signature is valid.
const isValid = schnorr.verify(tapKeySig, message, Buffer.from(group_pubkey, "hex"));
if (isValid) {
    console.log("The signature is valid.");
} else {
    console.log("The signature is NOT valid.");
}

transaction.ins[0].witness = [tapKeySig];

// Broadcasting the transaction
const txHex = transaction.toHex();
console.log(`Broadcasting Transaction Hex: ${txHex}`);
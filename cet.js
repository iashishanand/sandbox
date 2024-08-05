import * as musig from "@cmdcode/musig2";
import bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { Buff } from "@cmdcode/buff";
import { schnorr } from "@noble/curves/secp256k1";
import { Buffer } from "node:buffer";
import { Transaction } from "bitcoinjs-lib";
import { TESTNET, wallets, utxo, reciever } from './config.js';

bitcoin.initEccLib(ecc);

export function createTaprootAddress(groupPubKey) {
    const p2pktr = bitcoin.payments.p2tr({
        pubkey: Buffer.from(groupPubKey, "hex"),
        network: TESTNET,
    });
    console.log("Taproot address : ", p2pktr.address);
    return p2pktr.address;
}

export function createTransaction(p2pktrAddress) {
    let transaction = new Transaction();
    transaction.version = 2;
    transaction.addInput(Buffer.from(utxo.txid, "hex").reverse(), utxo.vout);
    transaction.addOutput(bitcoin.address.toOutputScript(p2pktrAddress, TESTNET), reciever.value);

    return transaction;
}

export function getSignatureHash(transaction, p2pktr) {
    return transaction.hashForWitnessV1(
        0, // Input index
        [p2pktr.output], // Prevouts
        [utxo.value], // Amounts
        Transaction.SIGHASH_DEFAULT // Sighash type
    );
}

export function createSigningContext(groupKeys, groupNonces, message, options) {
    return musig.get_ctx(groupKeys, groupNonces, Buff.from(message), options);
}

export function createPartialSignatures(ctx) {
    return wallets.map(wallet => musig.musign(ctx, wallet.sec_key, wallet.sec_nonce));
}

export function combineSignatures(ctx, groupSigs) {
    return musig.combine_psigs(ctx, groupSigs);
}

export function verifyAdaptorSig(ctx, signature, adaptorPks) {
    return musig.verify_adapter_sig(ctx, signature, adaptorPks);
}

export function addAdaptorSecret(ctx, signature, adaptorSks) {
    return musig.add_sig_adapters(ctx, signature, adaptorSks);
}

import * as musig from "@cmdcode/musig2";
import bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { Buff } from "@cmdcode/buff";
import { schnorr } from "@noble/curves/secp256k1";
import { Buffer } from "node:buffer";
import { Transaction } from "bitcoinjs-lib";
import fs from 'fs';
import prompts from 'prompts';

bitcoin.initEccLib(ecc);
const network = bitcoin.networks.testnet;

// Read config file
const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
const { wallets, utxos, oracle } = config;

// Calculate total funds from UTXOs
const totalFunds = utxos.reduce((sum, utxo) => sum + utxo.value, 0);

// Collect public keys and nonces from all signers.
const group_keys = wallets.map((e) => e.pub_key);
const group_nonces = wallets.map((e) => e.pub_nonce);

// Get the combined public key
const { group_pubkey } = musig.get_key_ctx(group_keys);

// Create a Taproot address from the x-only public key
const p2pktr = bitcoin.payments.p2tr({
    pubkey: Buffer.from(group_pubkey, "hex"),
    network,
});

// Function to create and sign a transaction
async function createAndSignTransaction(outcome) {
    console.log(`Creating transaction for outcome: ${outcome.message}`);

    const receiver = [];
    let remainingFunds = totalFunds;

    // Prompt user for output values for each wallet
    for (let i = 0; i < wallets.length; i++) {
        const wallet = wallets[i];

        const value = await prompts({
            type: 'number',
            name: 'value',
            message: `Enter the value for ${wallet.name}'s output (remaining ${remainingFunds} satoshis):`,
            validate: value => value <= remainingFunds ? true : `Value must not exceed ${remainingFunds} satoshis`
        });

        receiver.push({
            value: value.value,
            address: wallet.address,
        });

        remainingFunds -= value.value;
    }

    // Building a new transaction
    let transaction = new Transaction();
    transaction.version = 2;

    // Add inputs
    for (const input of utxos) {
        transaction.addInput(Buffer.from(input.txid, "hex").reverse(), input.vout);
    }

    // Add outputs
    for (const output of receiver) {
        transaction.addOutput(
            bitcoin.address.toOutputScript(output.address, network),
            output.value
        );
    }

    // Prepare prevouts and amounts for signature hash calculation
    const prevouts = utxos.map(() => p2pktr.output);
    const amounts = utxos.map(input => input.value);

    // Calculate the signature hash for all inputs
    const signatureHashes = utxos.map((_, index) =>
        transaction.hashForWitnessV1(
            index,
            prevouts,
            amounts,
            Transaction.SIGHASH_DEFAULT
        )
    );

    // Configure the musig options to include the key tweak for this specific outcome.
    const options = { nonce_tweaks: [outcome.adaptor_point] };

    const signatures = [];
    const contexts = [];

    // Sign all inputs
    for (let i = 0; i < utxos.length; i++) {
        let message = signatureHashes[i];
        // console.log(`Message for input ${i}: ${message.toString("hex")}`);

        // Combine all your collected keys into a signing session.
        const ctx = musig.get_ctx(group_keys, group_nonces, Buff.from(message), options);
        contexts.push(ctx);

        // Each member creates their own partial signature,
        // using their own computed signing session.
        const group_sigs = wallets.map((wallet) => {
            return musig.musign(ctx, wallet.sec_key, wallet.sec_nonce);
        });

        // Combine all the partial signatures into our final signature.
        const signature = musig.combine_psigs(ctx, group_sigs);
        signatures.push(signature);

        // Add the signature to the transaction
        transaction.ins[i].witness = [Buffer.from(signature)];
    }

    return { transaction, signatures, contexts };
}

// Create transactions for each outcome
const transactions = {};
for (const outcome of oracle.outcomes) {
    transactions[outcome.message] = await createAndSignTransaction(outcome);
}

// Prompt user for outcome and adaptor secret
const userInput = await prompts([
    {
        type: 'select',
        name: 'outcome',
        message: 'Select the outcome:',
        choices: oracle.outcomes.map(o => ({ title: o.message, value: o.message })),
    },
    {
        type: 'text',
        name: 'adaptorSecret',
        message: 'Enter the adaptor secret:',
    },
]);

// Get the selected transaction and make it valid
const { transaction: selectedTransaction, signatures, contexts } = transactions[userInput.outcome];
const adaptorSecret = Buffer.from(userInput.adaptorSecret, 'hex');

// Apply adaptor secret to make the transaction valid
for (let i = 0; i < utxos.length; i++) {
    const signature = signatures[i];
    const ctx = contexts[i];
    const adaptedSig = musig.add_sig_adapters(ctx, signature, [adaptorSecret]);

    // Verify the adapted signature
    const isValid = schnorr.verify(adaptedSig, ctx.message, ctx.group_pubkey);
    if (isValid) {
        console.log(`The signature for input ${i} is valid.`);
        selectedTransaction.ins[i].witness = [Buffer.from(adaptedSig)];
    } else {
        console.log(`The signature for input ${i} is NOT valid.`);
    }
}

// Output the final transaction hex
const txHex = selectedTransaction.toHex();
console.log(`Valid Transaction Hex for outcome "${userInput.outcome}": ${txHex}`);
import Oracle from './oracleutils.js';
import {
    createTaprootAddress,
    createTransaction,
    getSignatureHash,
    createSigningContext,
    createPartialSignatures,
    combineSignatures,
    verifyAdaptorSig,
    addAdaptorSecret
} from './cet.js';
import { wallets } from './config.js';
import * as musig from "@cmdcode/musig2";

// Function to simulate the DLC process
async function simulateDLC() {
    // Create an Oracle instance
    const oracle = new Oracle();

    // Publish an event
    const event = oracle.publishEvent();
    console.log("Oracle Event:", event);

    // Define the outcome message for the bet: "rain" or "no rain"
    const outcomeMessageRain = new TextEncoder().encode("rain");
    const outcomeMessageNoRain = new TextEncoder().encode("no rain");

    // Calculate the adaptor points for both outcomes
    const adaptorPointRain = oracle.calculateAdaptorPoint(outcomeMessageRain);
    const adaptorPointNoRain = oracle.calculateAdaptorPoint(outcomeMessageNoRain);

    console.log("Adaptor Point (rain):", adaptorPointRain.hex);
    console.log("Adaptor Point (no rain):", adaptorPointNoRain.hex);

    // Select an adaptor point based on the scenario. Let's assume it's going to rain.
    const selectedAdaptorPoint = adaptorPointRain;
    const adaptorPks = [selectedAdaptorPoint];

    // Configure the musig options to include the key tweak.
    const options = { nonce_tweaks: adaptorPks };

    // Collect public keys and nonces from all signers.
    const groupKeys = wallets.map(wallet => wallet.pub_key);
    const groupNonces = wallets.map(wallet => wallet.pub_nonce);

    // Get the combined public key
    const { group_pubkey } = musig.get_key_ctx(groupKeys);

    // Create a Taproot address from the x-only public key
    const p2pktrAddress = createTaprootAddress(group_pubkey);

    // Build a new transaction
    const transaction = createTransaction(p2pktrAddress);

    // Get the signature hash
    const signatureHash = getSignatureHash(transaction, p2pktrAddress);
    const message = signatureHash;

    // Combine all your collected keys into a signing session.
    const ctx = createSigningContext(groupKeys, groupNonces, message, options);

    // Each member creates their own partial signature
    const groupSigs = createPartialSignatures(ctx);

    // Combine all the partial signatures into our final signature.
    const signature = combineSignatures(ctx, groupSigs);

    // Check the un-tweaked signature is valid.
    const isValidUntweaked = verifyAdaptorSig(ctx, signature, adaptorPks);
    console.log("Is the signature w/o adaptor secret valid:", schnorr.verify(signature, message, ctx.group_pubkey));

    // Assume it's going to rain
    const outcomeMessage = outcomeMessageRain;

    // Generate the adaptor secret
    const adaptorSecret = oracle.signOutcome(outcomeMessage);
    console.log("Adaptor Secret:", adaptorSecret.hex);
    const adaptorSks = [adaptorSecret];

    // Add the tweak to the signature to make it valid.
    const adaptedSig = addAdaptorSecret(ctx, signature, adaptorSks);

    // Check if the signature is valid using an independent library.
    const isValidTweaked = schnorr.verify(adaptedSig, message, ctx.group_pubkey);
    console.log("Is the new signature BIP340 valid:", isValidTweaked);

    const tapKeySig = Buffer.from(adaptedSig);

    // Check if the signature is valid.
    const isValid = schnorr.verify(tapKeySig, message, Buffer.from(group_pubkey, "hex"));
    console.log(isValid ? "The signature is valid." : "The signature is NOT valid.");

    transaction.ins[0].witness = [tapKeySig];

    // Broadcasting the transaction
    const txHex = transaction.toHex();
    console.log(`Broadcasting Transaction Hex: ${txHex}`);
}

// Run the DLC simulation
simulateDLC();

import { Buff } from "@cmdcode/buff";
import { hash, keys, Field, Point } from "@cmdcode/crypto-tools";

class Oracle {
    constructor() {
        let secret = keys.gen_seckey()
        this.secKey = Field.mod(secret);
        this.pubKey = Point.from_x(keys.get_pubkey(secret, true));
        this.secNonce = null;
        this.pubNonce = null;
        console.log("Successfully created oracle: ", this.pubKey.x.hex);
    }

    publishEvent() {
        this.secNonce = Field.mod(keys.gen_seckey());
        this.pubNonce = Point.from_x(keys.get_pubkey(this.secNonce, true));

        return {
            pub_key: this.pubKey.x.hex,
            pub_nonce: this.pubNonce.hex,
        };
    }

    calculateAdaptorPoint(message) {
        if (!this.pubNonce) {
            throw new Error("Event not published yet. Call publishEvent() first.");
        }

        const msg = Buff.bytes(message);
        const ch = hash.hash340("BIP0340/challenge", this.pubNonce.x, this.pubKey.x, msg);
        const c = Field.mod(ch);
        const eP = this.pubKey.mul(c.big);
        const sG = this.pubNonce.add(eP);
        return sG.x;
    }

    signOutcome(message) {
        if (!this.secNonce) {
            throw new Error("Event not published yet. Call publishEvent() first.");
        }

        const msg = Buff.bytes(message);
        const d = this.secKey.negated;
        const k = this.secNonce.negated.big;
        const ch = hash.hash340("BIP0340/challenge", this.pubNonce.x, this.pubKey.x, msg);
        const c = Field.mod(ch);
        return Field.mod(k + (c.big * d.big));
    }

    static verifyAdaptorPair(adaptorPoint, adaptorSecret) {
        const computedPoint = Field.mod(adaptorSecret).point;
        return computedPoint.x.equals(adaptorPoint);
    }
}

export default Oracle;
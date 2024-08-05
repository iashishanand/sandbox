import { Buff } from "@cmdcode/buff";
import {
  hash,
  Field,
  Point,
} from "@cmdcode/crypto-tools";

class Oracle {
  constructor(secKey, pubKey, secNonce, pubNonce) {
    this.secKey = Field.mod(secKey);
    this.pubKey = Point.from_x(pubKey);
    this.secNonce = Field.mod(secNonce);
    this.pubNonce = Point.from_x(pubNonce);
  }

  static fromHex(secKey, pubKey, secNonce, pubNonce) {
    return new Oracle(
      Buff.hex(secKey),
      Buff.hex(pubKey),
      Buff.hex(secNonce),
      Buff.hex(pubNonce)
    );
  }

  calculateAdaptorPoint(message) {
    const msg = Buff.bytes(message);
    const ch = hash.hash340("BIP0340/challenge", this.pubNonce.x, this.pubKey.x, msg);
    const c = Field.mod(ch);
    const eP = this.pubKey.mul(c.big);
    const sG = this.pubNonce.add(eP);
    // Return only the x-coordinate (32 bytes) of the point
    return sG.x;
  }

  signOutcome(message) {
    const msg = Buff.bytes(message);
    const d = this.secKey.negated;
    const k = this.secNonce.negated.big;
    const ch = hash.hash340("BIP0340/challenge", this.pubNonce.x, this.pubKey.x, msg);
    const c = Field.mod(ch);
    // Let s equal (k + ed) mod n.
    return Field.mod(k + c.big * d.big);
  }

  static verifyAdaptorPair(adaptorPoint, adaptorSecret) {
    const computedPoint = Field.mod(adaptorSecret).point
    // Compare only the x-coordinate
    return computedPoint.x.equals(adaptorPoint);
  }
}

// Example usage
const wallet = Oracle.fromHex(
  "f01994b6432bdd312eed7cc2304ba5c7312d78feec24bc13686f4576f38e31e6",
  "512685788aef78e333572993a2f31b2472c0b76319bb24514ce1ed3feb97e896",
  "d4ac30504b7e4dcf3d2f7e1d001f3af99f078ade7fb4f8448cf2c02f74f53541",
  "3e1b2b0c9642b4196546081185845bb6b0b9c28290905f5f646a3a0bb2afee98"
);

const message = new TextEncoder().encode("Sunny");

const adaptorPoint = wallet.calculateAdaptorPoint(message);
const adaptorSecret = wallet.signOutcome(message);

console.log("Adaptor Point (32 bytes):", adaptorPoint.hex);
console.log("Adaptor Secret:", adaptorSecret.hex);

const isValid = Oracle.verifyAdaptorPair(adaptorPoint, adaptorSecret);
console.log("Adaptor pair is valid:", isValid);
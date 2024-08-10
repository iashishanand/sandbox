import { hash, keys, Field, Point } from "@cmdcode/crypto-tools";
import prompts from "prompts";

class Oracle {
  constructor() {
    this.secKey = Field.mod(keys.gen_seckey());
    this.pubKey = Point.from_x(keys.get_pubkey(this.secKey, true));
    this.secNonce = null;
    this.pubNonce = null;
    this.outcomes = [];
  }

  async createNewEvent() {
    const confirmation = await prompts({
      type: "confirm",
      name: "confirm",
      message: "Do you want to create a new event?",
    });

    if (!confirmation.confirm) {
      console.log("Event creation canceled.");
      return;
    }
    this.secNonce = Field.mod(keys.gen_seckey());
    this.pubNonce = Point.from_x(keys.get_pubkey(this.secNonce, true));

    let response = await prompts({
      type: "text",
      name: "outcome",
      message: "Enter the outcome for the event (press enter to finish):",
    });

    while (response.outcome) {
      const adaptorPoint = this.calculateAdaptorPoint(response.outcome);
      this.outcomes.push({
        message: response.outcome,
        adaptor_point: adaptorPoint.hex,
      });
      response = await prompts({
        type: "text",
        name: "outcome",
        message:
          "Enter the next outcome for the event (press enter to finish):",
      });
    }

    return JSON.stringify({
        pub_key: this.pubKey.x.hex,
        pub_nonce: this.pubNonce.hex,
        outcomes: this.outcomes,
      });
  }

  async signOutcome() {
    const confirmation = await prompts({
      type: "confirm",
      name: "confirm",
      message: "Do you want to sign an outcome?",
    });

    if (!confirmation.confirm) {
      console.log("Outcome signing canceled.");
      return;
    }
    if (!this.secNonce) {
      throw new Error("Event not published yet. Call publishEvent() first.");
    }

    const choices = this.outcomes.map((outcome, index) => {
      return { title: outcome.message, value: index };
    });

    const response = await prompts({
      type: "select",
      name: "selectedOutcome",
      message: "Choose the outcome to sign:",
      choices: choices,
    });

    const selectedOutcome = this.outcomes[response.selectedOutcome];

    const encoder = new TextEncoder();
    const msg = encoder.encode(selectedOutcome.message);

    // const msg = Buff.bytes(Buff.hex(selectedOutcome));
    const d = this.secKey.negated;
    const k = this.secNonce.negated.big;
    const ch = hash.hash340(
      "BIP0340/challenge",
      this.pubNonce.x,
      this.pubKey.x,
      msg
    );
    const c = Field.mod(ch);
    const adaptorSecret = Field.mod(k + c.big * d.big);

    const adaptorPoint = this.calculateAdaptorPoint(selectedOutcome.message);

    if (!this.verifyAdaptorPair(adaptorPoint, adaptorSecret)) {
      throw new Error("Adaptor pair verification failed.");
    }

    return adaptorSecret.hex;
  }

  calculateAdaptorPoint(message) {
    if (!this.pubNonce) {
      throw new Error("Event not published yet. Call publishEvent() first.");
    }

    const encoder = new TextEncoder();
    const msg = encoder.encode(message);
    const ch = hash.hash340(
      "BIP0340/challenge",
      this.pubNonce.x,
      this.pubKey.x,
      msg
    );
    const c = Field.mod(ch);
    const eP = this.pubKey.mul(c.big);
    const sG = this.pubNonce.add(eP);
    return sG.x;
  }

  verifyAdaptorPair(adaptorPoint, adaptorSecret) {
    const computedPoint = Field.mod(adaptorSecret).point;
    return computedPoint.x.equals(adaptorPoint);
  }
}

async function testOracle() {
  const oracle = new Oracle();

  const eventDetails = await oracle.createNewEvent();
  console.log("New event created with details:\n", eventDetails);

  const adaptorSecret = await oracle.signOutcome();
  console.log("Adaptor secret:", adaptorSecret);
}

testOracle();
import Oracle from './oracleutils.js';

// Initialize the Oracle
const oracle = new Oracle();

// Publish an event
const newEvent = oracle.publishEvent();
console.log("New Event:", newEvent);

// Now you can use other methods
const message = new TextEncoder().encode("Rainy");

const adaptorPoint = oracle.calculateAdaptorPoint(message);
const adaptorSecret = oracle.signOutcome(message);

console.log("Adaptor Point:", adaptorPoint.hex);
console.log("Adaptor Secret:", adaptorSecret.hex);

const isValid = Oracle.verifyAdaptorPair(adaptorPoint, adaptorSecret);
console.log("Adaptor pair is valid:", isValid);
import { buffer } from '@cmdcode/buff';
import { math } from '@cmdcode/crypto-tools';
import { KeyOperationError } from './error.js';
export function ok(value, message) {
    if (value === false) {
        throw new Error(message ?? 'Assertion failed!');
    }
}
export function exists(value, msg) {
    if (value === undefined || value === null) {
        throw new Error(msg ?? 'Value is null or undefined!');
    }
}
export function size(input, size) {
    const bytes = buffer(input);
    if (bytes.length !== size) {
        throw new TypeError(`Invalid byte size: ${bytes.hex} !== ${size}`);
    }
}
export function nonce_total_size(nonce, size) {
    const bytes = buffer(nonce);
    if (bytes.length !== size) {
        throw new KeyOperationError({
            data: [bytes.hex],
            type: 'nonce_total_size',
            reason: `Nonce size mismatch: ${bytes.length} !== ${size}`
        });
    }
}
export function nonce_key_size(nonce) {
    const bytes = buffer(nonce);
    if (bytes.length % 32 !== 0 && bytes.length % 33 !== 0) {
        throw new KeyOperationError({
            data: [bytes.hex],
            type: 'nonce_key_size',
            reason: `Invalid key size: ${bytes.length}`
        });
    }
}
export function valid_nonce_group(pub_nonces) {
    const nonces = pub_nonces.map(e => buffer(e));
    nonces.forEach((nonce, idx) => {
        nonce_key_size(nonce);
        if (idx > 0) {
            const prev = nonces[idx - 1];
            nonce_total_size(nonce, prev.length);
        }
    });
}
export function in_field(bytes) {
    const big = buffer(bytes).big;
    if (!math.in_field(big)) {
        throw new KeyOperationError({
            type: 'assert_in_field',
            reason: 'Key out of range of N.',
            data: [buffer(big, 32).hex]
        });
    }
}
export function valid_point(point) {
    math.pt.assert_valid(point);
}
//# sourceMappingURL=assert.js.map
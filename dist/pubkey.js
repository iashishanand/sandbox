import { Buff } from '@cmdcode/buff';
import { hash340 } from '@cmdcode/crypto-tools/hash';
import { mod_n, pt } from '@cmdcode/crypto-tools/math';
import { sort_keys } from './util.js';
import { KeyOperationError } from './error.js';
import * as assert from './assert.js';
function compute_group_hash(pubkeys) {
    const group_p = sort_keys(pubkeys);
    return hash340('KeyAgg list', ...group_p);
}
function compute_coeff_hash(group_hash, coeff_key) {
    return hash340('KeyAgg coefficient', group_hash, coeff_key);
}
export function compute_key_coeff(pubkeys, self_key) {
    const group_hash = compute_group_hash(pubkeys);
    const coeff_hash = compute_coeff_hash(group_hash, self_key);
    return Buff.big(mod_n(coeff_hash.big), 32);
}
export function combine_pubkeys(pubkeys) {
    const keys = sort_keys(pubkeys);
    const hash = compute_group_hash(keys);
    const coeffs = [];
    let group_P = null;
    for (const key of keys) {
        const c = compute_coeff_hash(hash, key);
        coeffs.push([key.hex, c]);
        const P = pt.lift_x(key);
        if (P === null) {
            throw new KeyOperationError({
                pubkey: key.hex,
                type: 'lift_x',
                reason: 'Point lifted from key is null!'
            });
        }
        const mP = pt.mul(P, c.big);
        group_P = pt.add(group_P, mP);
        if (group_P === null) {
            throw new KeyOperationError({
                pubkey: key.hex,
                type: 'point_add',
                reason: 'Point nullifies the group!'
            });
        }
    }
    assert.valid_point(group_P);
    return [group_P, coeffs];
}
export function get_key_coeff(pubkey, coeffs) {
    const key = Buff.bytes(pubkey);
    const pkv = coeffs.find(e => e[0] === key.hex);
    if (pkv === undefined) {
        throw new KeyOperationError({
            type: 'get_key_coeff',
            reason: 'Pubkey is not included in coeff map.',
            pubkey: key.hex
        });
    }
    return pkv[1];
}
//# sourceMappingURL=pubkey.js.map
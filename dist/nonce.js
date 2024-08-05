import { Buff } from '@cmdcode/buff';
import { hash340 } from '@cmdcode/crypto-tools/hash';
import { mod_n, pt } from '@cmdcode/crypto-tools/math';
import { convert_32b } from '@cmdcode/crypto-tools/keys';
import { CONST } from '@cmdcode/crypto-tools';
import * as assert from './assert.js';
import * as util from './util.js';
export function get_nonce_coeff(group_nonce, group_key, message) {
    const gpx = convert_32b(group_key);
    const preimg = Buff.bytes([group_nonce, gpx, message]);
    const bytes = hash340('MuSig/noncecoef', preimg);
    const coeff = mod_n(bytes.big);
    return Buff.bytes(coeff, 32);
}
export function combine_nonces(pub_nonces) {
    assert.valid_nonce_group(pub_nonces);
    const rounds = 2;
    const members = pub_nonces.map(e => Buff.parse(e, 32, 64));
    const points = [];
    for (let j = 0; j < rounds; j++) {
        let group_R = null;
        for (const nonces of members) {
            const nonce = nonces[j];
            const n_pt = pt.lift_x(nonce);
            group_R = pt.add(group_R, n_pt);
        }
        if (group_R === null) {
            group_R = CONST._G;
        }
        points.push(group_R);
    }
    return util.parse_points(points);
}
//# sourceMappingURL=nonce.js.map
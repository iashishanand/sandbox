import { Buff } from '@cmdcode/buff';
import { convert_32b } from '@cmdcode/crypto-tools/keys';
import { hash340 } from '@cmdcode/crypto-tools/hash';
import { CONST } from '@cmdcode/crypto-tools';
import { mod_bytes, mod_n, pow_n, pt } from '@cmdcode/crypto-tools/math';
const { _N, _G } = CONST;
export function get_challenge(group_rx, group_pub, message) {
    const grx = convert_32b(group_rx);
    const gpx = convert_32b(group_pub);
    const preimg = Buff.join([grx, gpx, message]);
    return hash340('BIP0340/challenge', preimg);
}
export function get_pt_state(int_pt, adaptors = [], tweaks = []) {
    const pos = BigInt(1);
    const neg = _N - pos;
    const twk = tweaks.map(e => mod_bytes(e).big);
    const pts = [
        ...twk.map(e => pt.mul(_G, e)),
        ...adaptors.map(e => pt.lift_x(e, true))
    ];
    let point = int_pt, parity = pos, state = pos, tweak = 0n;
    for (let i = 0; i < pts.length; i++) {
        const p = pts[i];
        parity = (!pt.is_even(point)) ? neg : pos;
        point = pt.add(pt.mul(point, parity), p);
        pt.assert_valid(point);
        state = mod_n(parity * state);
        if (twk.at(i) !== undefined) {
            tweak = mod_n(twk[i] + parity * tweak);
        }
    }
    parity = (!pt.is_even(point)) ? neg : pos;
    return {
        point,
        parity,
        state,
        tweak
    };
}
export function compute_R(group_nonce, nonce_coeff) {
    const nonces = Buff.parse(group_nonce, 33, 66);
    const ncoeff = Buff.bytes(nonce_coeff);
    let R = null;
    for (let j = 0; j < nonces.length; j++) {
        const c = mod_n(ncoeff.big ** BigInt(j));
        const NC = pt.lift_x(nonces[j]);
        pt.assert_valid(NC);
        const Rj = pt.mul(NC, c);
        R = pt.add(R, Rj);
    }
    pt.assert_valid(R);
    return R;
}
export function compute_s(secret_key, key_coeff, challenge, sec_nonces, nonce_coeff) {
    let s = mod_n(challenge * key_coeff * secret_key);
    for (let j = 0; j < sec_nonces.length; j++) {
        const r = sec_nonces[j];
        const c = pow_n(nonce_coeff, BigInt(j));
        s += (r * c);
        s = mod_n(s);
    }
    return Buff.big(s, 32);
}
export function compute_ps(secret_key, key_coeff, challenge) {
    const ps = mod_n(challenge * key_coeff * secret_key);
    return Buff.big(ps, 32);
}
export function apply_sn(ps, sns, ncf) {
    for (let j = 0; j < sns.length; j++) {
        const r = sns[j];
        const c = pow_n(ncf, BigInt(j));
        ps += (r * c);
        ps = mod_n(ps);
    }
    return Buff.big(ps, 32);
}
//# sourceMappingURL=compute.js.map
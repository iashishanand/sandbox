import { Buff } from '@cmdcode/buff';
import { get_key_coeff } from './pubkey.js';
import { parse_psig } from './util.js';
import { CONST, keys, math } from '@cmdcode/crypto-tools';
import { apply_sn, compute_ps, compute_s, get_pt_state } from './compute.js';
import { get_keypair, get_nonce_pair } from './keys.js';
import * as assert from './assert.js';
function combine_s(signatures) {
    let s = CONST._0n;
    for (const psig of signatures) {
        const s_i = Buff.bytes(psig).big;
        assert.in_field(s_i);
        s = math.mod_n(s + s_i);
    }
    return s;
}
export function combine_psigs(context, signatures) {
    const { challenge, group_state, group_rx } = context;
    const { parity, tweak } = group_state;
    const sigs = signatures
        .map(e => parse_psig(e))
        .map(e => e.sig);
    const s = combine_s(sigs);
    const e = challenge.big;
    const a = e * parity * tweak;
    const sig = math.mod_n(s + a);
    return Buff.join([
        keys.convert_32b(group_rx),
        Buff.big(sig, 32)
    ]);
}
export function add_sig_adapters(context, signature, adapters) {
    const { int_R } = context;
    const s = Buff.bytes(signature).subarray(32, 64).big;
    const T = get_pt_state(int_R.point, [], adapters);
    const a = T.parity * T.tweak;
    const sig = math.mod_n(s + a);
    return Buff.join([
        Buff.bytes(signature).subarray(0, 32),
        Buff.big(sig, 32)
    ]);
}
export function musign(context, secret, snonce) {
    const { challenge, key_coeffs, nonce_coeff } = context;
    const { group_state, nonce_state } = context;
    const [sec, pub] = get_keypair(secret);
    const [snp, pn] = get_nonce_pair(snonce);
    const Q = group_state;
    const R = nonce_state;
    const p_v = get_key_coeff(pub, key_coeffs).big;
    const sk = math.mod_n(Q.parity * Q.state * sec.big);
    const cha = Buff.bytes(challenge).big;
    const n_v = Buff.bytes(nonce_coeff).big;
    const sn = Buff.parse(snp, 32, 64).map(e => {
        return R.parity * R.state * e.big;
    });
    const psig = compute_s(sk, p_v, cha, sn, n_v);
    return Buff.join([psig, pub, pn]);
}
export function cosign_key(context, secret) {
    const { challenge, group_state, key_coeffs } = context;
    const [sec, pub] = get_keypair(secret);
    const Q = group_state;
    const p_v = get_key_coeff(pub, key_coeffs).big;
    const sk = math.mod_n(Q.parity * Q.state * sec.big);
    const cha = Buff.bytes(challenge).big;
    const csig = compute_ps(sk, p_v, cha);
    return Buff.join([csig, pub]);
}
export function cosign_nonce(context, cosig, snonce) {
    const buffer = Buff.bytes(cosig);
    assert.size(buffer, 64);
    const ps = buffer.subarray(0, 32);
    const pub = buffer.subarray(32, 64);
    const { nonce_coeff, nonce_state } = context;
    const [snp, pn] = get_nonce_pair(snonce);
    const R = nonce_state;
    const n_v = Buff.bytes(nonce_coeff).big;
    const sn = Buff.parse(snp, 32, 64).map(e => {
        return R.parity * e.big;
    });
    const psig = apply_sn(ps.big, sn, n_v);
    return Buff.join([psig, pub, pn]);
}
//# sourceMappingURL=sign.js.map
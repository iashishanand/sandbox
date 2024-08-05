import { Buff } from '@cmdcode/buff';
import { keys } from '@cmdcode/crypto-tools';
export const get_seckey = (seckey) => {
    return keys.get_seckey(seckey, true);
};
export const get_pubkey = (seckey) => {
    return keys.get_pubkey(seckey, true);
};
export const get_keypair = (secret) => {
    return keys.get_keypair(secret, true, true);
};
export const gen_seckey = () => {
    return keys.gen_seckey(true);
};
export const gen_keypair = () => {
    return keys.gen_keypair(true, true);
};
export function get_sec_nonce(secret) {
    const nonces = Buff
        .parse(secret, 32, 64)
        .map(e => get_seckey(e));
    return Buff.join(nonces);
}
export function get_pub_nonce(sec_nonce) {
    const nonces = Buff
        .parse(sec_nonce, 32, 64)
        .map(e => get_pubkey(e));
    return Buff.join(nonces);
}
export function get_nonce_pair(secret) {
    const sec_nonce = get_sec_nonce(secret);
    const pub_nonce = get_pub_nonce(sec_nonce);
    return [sec_nonce, pub_nonce];
}
export function gen_nonce_pair() {
    const seed = Buff.random(64);
    return get_nonce_pair(seed);
}
//# sourceMappingURL=keys.js.map
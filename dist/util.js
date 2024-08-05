import { Buff, buffer } from '@cmdcode/buff';
import { convert_32b } from '@cmdcode/crypto-tools/keys';
import { pt } from '@cmdcode/crypto-tools/math';
export function hash_str(str) {
    return Buff.str(str).digest;
}
export function has_key(key, keys) {
    const str = keys.map(e => buffer(e).hex);
    return str.includes(buffer(key).hex);
}
export function sort_keys(keys) {
    const arr = keys.map(e => buffer(e).hex);
    arr.sort();
    return arr.map(e => Buff.hex(e));
}
export function parse_points(points, xonly) {
    let keys = points.map(P => pt.to_bytes(P));
    if (xonly)
        keys = keys.map(e => convert_32b(e));
    return Buff.join(keys);
}
export function parse_psig(psig) {
    const keys = Buff.parse(psig, 32, 128);
    return {
        sig: keys[0],
        pubkey: keys[1],
        nonces: keys.slice(2)
    };
}
export function hexify(item) {
    if (Array.isArray(item)) {
        return item.map(e => hexify(e));
    }
    if (item instanceof Buff) {
        return item.hex;
    }
    return item;
}
export function has_items(arr) {
    return (Array.isArray(arr) && arr.length > 0);
}
//# sourceMappingURL=util.js.map
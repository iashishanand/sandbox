const MUSIG_DEFAULTS = {
    nonce_tweaks: [],
    pubkey_tweaks: []
};
const CONST$1 = {
    SAFE_MIN_VALUE: 0xffn ** 16n
};
function musig_config(options = {}) {
    return { ...MUSIG_DEFAULTS, ...options };
}

function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
// copied from utils
function isBytes$3(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
function bytes(b, ...lengths) {
    if (!isBytes$3(b))
        throw new Error('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
function exists$1(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}

const crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated (2025-04-30), we can just drop the import.
function isBytes$2(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
// Other libraries would silently corrupt the data instead of throwing an error,
// when they don't support it.
const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE)
    throw new Error('Non little-endian hardware is not supported');
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes$1(str) {
    if (typeof str !== 'string')
        throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes$1(data);
    if (!isBytes$2(data))
        throw new Error(`expected Uint8Array, got ${typeof data}`);
    return data;
}
/**
 * Copies several Uint8Arrays into one.
 */
function concatBytes$1(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        if (!isBytes$2(a))
            throw new Error('Uint8Array expected');
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
function wrapConstructor(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
}
/**
 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
 */
function randomBytes(bytesLength = 32) {
    if (crypto && typeof crypto.getRandomValues === 'function') {
        return crypto.getRandomValues(new Uint8Array(bytesLength));
    }
    throw new Error('crypto.getRandomValues must be defined');
}

// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        exists$1(this);
        const { view, buffer, blockLen } = this;
        data = toBytes(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        exists$1(this);
        output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}

// SHA2-256 need to try 2^128 hashes to execute birthday attack.
// BTC network is doing 2^67 hashes/sec as per early 2023.
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = /* @__PURE__ */ new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = /* @__PURE__ */ new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
class SHA256 extends SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256 = /* @__PURE__ */ wrapConstructor(() => new SHA256());

function within_size(data, size) {
    if (data.length > size) {
        throw new TypeError(`Data is larger than array size: ${data.length} > ${size}`);
    }
}
function is_hex$1(hex) {
    if (hex.match(/[^a-fA-f0-9]/) !== null) {
        throw new TypeError('Invalid characters in hex string: ' + hex);
    }
    if (hex.length % 2 !== 0) {
        throw new Error(`Length of hex string is invalid: ${hex.length}`);
    }
}
function is_safe_num(num) {
    if (num > Number.MAX_SAFE_INTEGER) {
        throw new TypeError('Number exceeds safe bounds!');
    }
}
function is_prefix(actual, target) {
    if (actual !== target) {
        throw new TypeError(`Bech32 prefix does not match: ${actual} !== ${target}`);
    }
}

const ec = new TextEncoder();
const dc = new TextDecoder();
function strToBytes(str) {
    return ec.encode(str);
}
function bytesToStr(bytes) {
    return dc.decode(bytes);
}
function hex_size(hexstr, size) {
    is_hex$1(hexstr);
    const len = hexstr.length / 2;
    if (size === undefined)
        size = len;
    if (len > size) {
        throw new TypeError(`Hex string is larger than array size: ${len} > ${size}`);
    }
    return size;
}
function hexToBytes$1(hexstr, size, endian = 'le') {
    size = hex_size(hexstr, size);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    for (let i = 0; i < hexstr.length; i += 2) {
        const char = hexstr.substring(i, i + 2);
        const num = parseInt(char, 16);
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
    }
    return new Uint8Array(buffer);
}
function bytesToHex$1(bytes) {
    let chars = '';
    for (let i = 0; i < bytes.length; i++) {
        chars += bytes[i].toString(16).padStart(2, '0');
    }
    return chars;
}

/*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Utilities

function isBytes$1(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function chain(...args) {
    const id = (a) => a;
    // Wrap call in closure so JIT can inline calls
    const wrap = (a, b) => (c) => a(b(c));
    // Construct chain of args[-1].encode(args[-2].encode([...]))
    const encode = args.map((x) => x.encode).reduceRight(wrap, id);
    // Construct chain of args[0].decode(args[1].decode(...))
    const decode = args.map((x) => x.decode).reduce(wrap, id);
    return { encode, decode };
}
/**
 * Encodes integer radix representation to array of strings using alphabet and back
 * @__NO_SIDE_EFFECTS__
 */
function alphabet(alphabet) {
    return {
        encode: (digits) => {
            if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
                throw new Error('alphabet.encode input should be an array of numbers');
            return digits.map((i) => {
                if (i < 0 || i >= alphabet.length)
                    throw new Error(`Digit index outside alphabet: ${i} (alphabet: ${alphabet.length})`);
                return alphabet[i];
            });
        },
        decode: (input) => {
            if (!Array.isArray(input) || (input.length && typeof input[0] !== 'string'))
                throw new Error('alphabet.decode input should be array of strings');
            return input.map((letter) => {
                if (typeof letter !== 'string')
                    throw new Error(`alphabet.decode: not string element=${letter}`);
                const index = alphabet.indexOf(letter);
                if (index === -1)
                    throw new Error(`Unknown letter: "${letter}". Allowed: ${alphabet}`);
                return index;
            });
        },
    };
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function join(separator = '') {
    if (typeof separator !== 'string')
        throw new Error('join separator should be string');
    return {
        encode: (from) => {
            if (!Array.isArray(from) || (from.length && typeof from[0] !== 'string'))
                throw new Error('join.encode input should be array of strings');
            for (let i of from)
                if (typeof i !== 'string')
                    throw new Error(`join.encode: non-string input=${i}`);
            return from.join(separator);
        },
        decode: (to) => {
            if (typeof to !== 'string')
                throw new Error('join.decode input should be string');
            return to.split(separator);
        },
    };
}
/**
 * Pad strings array so it has integer number of bits
 * @__NO_SIDE_EFFECTS__
 */
function padding(bits, chr = '=') {
    if (typeof chr !== 'string')
        throw new Error('padding chr should be string');
    return {
        encode(data) {
            if (!Array.isArray(data) || (data.length && typeof data[0] !== 'string'))
                throw new Error('padding.encode input should be array of strings');
            for (let i of data)
                if (typeof i !== 'string')
                    throw new Error(`padding.encode: non-string input=${i}`);
            while ((data.length * bits) % 8)
                data.push(chr);
            return data;
        },
        decode(input) {
            if (!Array.isArray(input) || (input.length && typeof input[0] !== 'string'))
                throw new Error('padding.encode input should be array of strings');
            for (let i of input)
                if (typeof i !== 'string')
                    throw new Error(`padding.decode: non-string input=${i}`);
            let end = input.length;
            if ((end * bits) % 8)
                throw new Error('Invalid padding: string should have whole number of bytes');
            for (; end > 0 && input[end - 1] === chr; end--) {
                if (!(((end - 1) * bits) % 8))
                    throw new Error('Invalid padding: string has too much padding');
            }
            return input.slice(0, end);
        },
    };
}
/**
 * Slow: O(n^2) time complexity
 * @__NO_SIDE_EFFECTS__
 */
function convertRadix(data, from, to) {
    // base 1 is impossible
    if (from < 2)
        throw new Error(`convertRadix: wrong from=${from}, base cannot be less than 2`);
    if (to < 2)
        throw new Error(`convertRadix: wrong to=${to}, base cannot be less than 2`);
    if (!Array.isArray(data))
        throw new Error('convertRadix: data should be array');
    if (!data.length)
        return [];
    let pos = 0;
    const res = [];
    const digits = Array.from(data);
    digits.forEach((d) => {
        if (d < 0 || d >= from)
            throw new Error(`Wrong integer: ${d}`);
    });
    while (true) {
        let carry = 0;
        let done = true;
        for (let i = pos; i < digits.length; i++) {
            const digit = digits[i];
            const digitBase = from * carry + digit;
            if (!Number.isSafeInteger(digitBase) ||
                (from * carry) / from !== carry ||
                digitBase - digit !== from * carry) {
                throw new Error('convertRadix: carry overflow');
            }
            carry = digitBase % to;
            const rounded = Math.floor(digitBase / to);
            digits[i] = rounded;
            if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
                throw new Error('convertRadix: carry overflow');
            if (!done)
                continue;
            else if (!rounded)
                pos = i;
            else
                done = false;
        }
        res.push(carry);
        if (done)
            break;
    }
    for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
        res.push(0);
    return res.reverse();
}
const gcd = /* @__NO_SIDE_EFFECTS__ */ (a, b) => (!b ? a : gcd(b, a % b));
const radix2carry = /*@__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
/**
 * Implemented with numbers, because BigInt is 5x slower
 * @__NO_SIDE_EFFECTS__
 */
function convertRadix2(data, from, to, padding) {
    if (!Array.isArray(data))
        throw new Error('convertRadix2: data should be array');
    if (from <= 0 || from > 32)
        throw new Error(`convertRadix2: wrong from=${from}`);
    if (to <= 0 || to > 32)
        throw new Error(`convertRadix2: wrong to=${to}`);
    if (radix2carry(from, to) > 32) {
        throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${radix2carry(from, to)}`);
    }
    let carry = 0;
    let pos = 0; // bitwise position in current element
    const mask = 2 ** to - 1;
    const res = [];
    for (const n of data) {
        if (n >= 2 ** from)
            throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
        carry = (carry << from) | n;
        if (pos + from > 32)
            throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
        pos += from;
        for (; pos >= to; pos -= to)
            res.push(((carry >> (pos - to)) & mask) >>> 0);
        carry &= 2 ** pos - 1; // clean carry, otherwise it will cause overflow
    }
    carry = (carry << (to - pos)) & mask;
    if (!padding && pos >= from)
        throw new Error('Excess padding');
    if (!padding && carry)
        throw new Error(`Non-zero padding: ${carry}`);
    if (padding && pos > 0)
        res.push(carry >>> 0);
    return res;
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function radix(num) {
    return {
        encode: (bytes) => {
            if (!isBytes$1(bytes))
                throw new Error('radix.encode input should be Uint8Array');
            return convertRadix(Array.from(bytes), 2 ** 8, num);
        },
        decode: (digits) => {
            if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
                throw new Error('radix.decode input should be array of numbers');
            return Uint8Array.from(convertRadix(digits, num, 2 ** 8));
        },
    };
}
/**
 * If both bases are power of same number (like `2**8 <-> 2**64`),
 * there is a linear algorithm. For now we have implementation for power-of-two bases only.
 * @__NO_SIDE_EFFECTS__
 */
function radix2(bits, revPadding = false) {
    if (bits <= 0 || bits > 32)
        throw new Error('radix2: bits should be in (0..32]');
    if (radix2carry(8, bits) > 32 || radix2carry(bits, 8) > 32)
        throw new Error('radix2: carry overflow');
    return {
        encode: (bytes) => {
            if (!isBytes$1(bytes))
                throw new Error('radix2.encode input should be Uint8Array');
            return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
        },
        decode: (digits) => {
            if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
                throw new Error('radix2.decode input should be array of numbers');
            return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
        },
    };
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function unsafeWrapper(fn) {
    if (typeof fn !== 'function')
        throw new Error('unsafeWrapper fn should be function');
    return function (...args) {
        try {
            return fn.apply(null, args);
        }
        catch (e) { }
    };
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function checksum(len, fn) {
    if (typeof fn !== 'function')
        throw new Error('checksum fn should be function');
    return {
        encode(data) {
            if (!isBytes$1(data))
                throw new Error('checksum.encode: input should be Uint8Array');
            const checksum = fn(data).slice(0, len);
            const res = new Uint8Array(data.length + len);
            res.set(data);
            res.set(checksum, data.length);
            return res;
        },
        decode(data) {
            if (!isBytes$1(data))
                throw new Error('checksum.decode: input should be Uint8Array');
            const payload = data.slice(0, -len);
            const newChecksum = fn(payload).slice(0, len);
            const oldChecksum = data.slice(-len);
            for (let i = 0; i < len; i++)
                if (newChecksum[i] !== oldChecksum[i])
                    throw new Error('Invalid checksum');
            return payload;
        },
    };
}
const base64 = /* @__PURE__ */ chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), padding(6), join(''));
const base64urlnopad = /* @__PURE__ */ chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'), join(''));
// base58 code
// -----------
const genBase58 = (abc) => chain(radix(58), alphabet(abc), join(''));
const base58 = /* @__PURE__ */ genBase58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
const createBase58check =  (sha256) => chain(checksum(4, (data) => sha256(sha256(data))), base58);
// legacy export, bad name
const base58check = createBase58check;
const BECH_ALPHABET = /* @__PURE__ */ chain(alphabet('qpzry9x8gf2tvdw0s3jn54khce6mua7l'), join(''));
const POLYMOD_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
/**
 * @__NO_SIDE_EFFECTS__
 */
function bech32Polymod(pre) {
    const b = pre >> 25;
    let chk = (pre & 0x1ffffff) << 5;
    for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
        if (((b >> i) & 1) === 1)
            chk ^= POLYMOD_GENERATORS[i];
    }
    return chk;
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function bechChecksum(prefix, words, encodingConst = 1) {
    const len = prefix.length;
    let chk = 1;
    for (let i = 0; i < len; i++) {
        const c = prefix.charCodeAt(i);
        if (c < 33 || c > 126)
            throw new Error(`Invalid prefix (${prefix})`);
        chk = bech32Polymod(chk) ^ (c >> 5);
    }
    chk = bech32Polymod(chk);
    for (let i = 0; i < len; i++)
        chk = bech32Polymod(chk) ^ (prefix.charCodeAt(i) & 0x1f);
    for (let v of words)
        chk = bech32Polymod(chk) ^ v;
    for (let i = 0; i < 6; i++)
        chk = bech32Polymod(chk);
    chk ^= encodingConst;
    return BECH_ALPHABET.encode(convertRadix2([chk % 2 ** 30], 30, 5, false));
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function genBech32(encoding) {
    const ENCODING_CONST = encoding === 'bech32' ? 1 : 0x2bc830a3;
    const _words = radix2(5);
    const fromWords = _words.decode;
    const toWords = _words.encode;
    const fromWordsUnsafe = unsafeWrapper(fromWords);
    function encode(prefix, words, limit = 90) {
        if (typeof prefix !== 'string')
            throw new Error(`bech32.encode prefix should be string, not ${typeof prefix}`);
        if (!Array.isArray(words) || (words.length && typeof words[0] !== 'number'))
            throw new Error(`bech32.encode words should be array of numbers, not ${typeof words}`);
        const actualLength = prefix.length + 7 + words.length;
        if (limit !== false && actualLength > limit)
            throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
        const lowered = prefix.toLowerCase();
        const sum = bechChecksum(lowered, words, ENCODING_CONST);
        return `${lowered}1${BECH_ALPHABET.encode(words)}${sum}`;
    }
    function decode(str, limit = 90) {
        if (typeof str !== 'string')
            throw new Error(`bech32.decode input should be string, not ${typeof str}`);
        if (str.length < 8 || (limit !== false && str.length > limit))
            throw new TypeError(`Wrong string length: ${str.length} (${str}). Expected (8..${limit})`);
        // don't allow mixed case
        const lowered = str.toLowerCase();
        if (str !== lowered && str !== str.toUpperCase())
            throw new Error(`String must be lowercase or uppercase`);
        str = lowered;
        const sepIndex = str.lastIndexOf('1');
        if (sepIndex === 0 || sepIndex === -1)
            throw new Error(`Letter "1" must be present between prefix and data only`);
        const prefix = str.slice(0, sepIndex);
        const _words = str.slice(sepIndex + 1);
        if (_words.length < 6)
            throw new Error('Data must be at least 6 characters long');
        const words = BECH_ALPHABET.decode(_words).slice(0, -6);
        const sum = bechChecksum(prefix, words, ENCODING_CONST);
        if (!_words.endsWith(sum))
            throw new Error(`Invalid checksum in ${str}: expected "${sum}"`);
        return { prefix, words };
    }
    const decodeUnsafe = unsafeWrapper(decode);
    function decodeToBytes(str) {
        const { prefix, words } = decode(str, false);
        return { prefix, words, bytes: fromWords(words) };
    }
    return { encode, decode, decodeToBytes, decodeUnsafe, fromWords, fromWordsUnsafe, toWords };
}
const bech32 = /* @__PURE__ */ genBech32('bech32');
const bech32m = /* @__PURE__ */ genBech32('bech32m');

const B58chk = {
    encode: (data) => base58check(sha256).encode(data),
    decode: (data) => base58check(sha256).decode(data)
};
const Base64 = {
    encode: (data) => base64.encode(data),
    decode: (data) => base64.decode(data)
};
const B64url = {
    encode: (data) => base64urlnopad.encode(data),
    decode: (data) => base64urlnopad.decode(data)
};
const Bech32 = {
    to_words: bech32.toWords,
    to_bytes: bech32.fromWords,
    encode: (prefix, words, limit = false) => {
        return bech32.encode(prefix, words, limit);
    },
    decode: (data, limit = false) => {
        const { prefix, words } = bech32.decode(data, limit);
        return { prefix, words };
    }
};
const Bech32m = {
    to_words: bech32m.toWords,
    to_bytes: bech32m.fromWords,
    encode: (prefix, words, limit = false) => {
        return bech32m.encode(prefix, words, limit);
    },
    decode: (data, limit = false) => {
        const { prefix, words } = bech32m.decode(data, limit);
        return { prefix, words };
    }
};

const _0n$5 = BigInt(0);
const _255n = BigInt(255);
const _256n = BigInt(256);
function big_size(big) {
    if (big <= 0xffn)
        return 1;
    if (big <= 0xffffn)
        return 2;
    if (big <= 0xffffffffn)
        return 4;
    if (big <= 0xffffffffffffffffn)
        return 8;
    if (big <= 0xffffffffffffffffffffffffffffffffn)
        return 16;
    if (big <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn) {
        return 32;
    }
    throw new TypeError('Must specify a fixed buffer size for bigints greater than 32 bytes.');
}
function bigToBytes(big, size, endian = 'be') {
    if (size === undefined)
        size = big_size(big);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    while (big > _0n$5) {
        const byte = big & _255n;
        const num = Number(byte);
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
        big = (big - byte) / _256n;
    }
    return new Uint8Array(buffer);
}
function bytesToBig(bytes) {
    let num = BigInt(0);
    for (let i = bytes.length - 1; i >= 0; i--) {
        num = (num * _256n) + BigInt(bytes[i]);
    }
    return BigInt(num);
}

function binToBytes(binary) {
    const bins = binary.split('').map(Number);
    if (bins.length % 8 !== 0) {
        throw new Error(`Binary array is invalid length: ${binary.length}`);
    }
    const bytes = new Uint8Array(bins.length / 8);
    for (let i = 0, ct = 0; i < bins.length; i += 8, ct++) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte |= (bins[i + j] << (7 - j));
        }
        bytes[ct] = byte;
    }
    return bytes;
}
function bytesToBin(bytes) {
    const bin = new Array(bytes.length * 8);
    let count = 0;
    for (const num of bytes) {
        if (num > 255) {
            throw new Error(`Invalid byte value: ${num}. Byte values must be between 0 and 255.`);
        }
        for (let i = 7; i >= 0; i--, count++) {
            bin[count] = (num >> i) & 1;
        }
    }
    return bin.join('');
}

function num_size(num) {
    if (num <= 0xFF)
        return 1;
    if (num <= 0xFFFF)
        return 2;
    if (num <= 0xFFFFFFFF)
        return 4;
    throw new TypeError('Numbers larger than 4 bytes must specify a fixed size!');
}
function numToBytes(num, size, endian = 'be') {
    if (size === undefined)
        size = num_size(num);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    while (num > 0) {
        const byte = num & 255;
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
        num = (num - byte) / 256;
    }
    return new Uint8Array(buffer);
}
function bytesToNum(bytes) {
    let num = 0;
    for (let i = bytes.length - 1; i >= 0; i--) {
        num = (num * 256) + bytes[i];
        is_safe_num(num);
    }
    return num;
}

function is_hex(input) {
    if (input.match(/[^a-fA-F0-9]/) === null &&
        input.length % 2 === 0) {
        return true;
    }
    return false;
}
function is_bytes(input) {
    if (typeof input === 'string' && is_hex(input)) {
        return true;
    }
    else if (typeof input === 'number' ||
        typeof input === 'bigint' ||
        input instanceof Uint8Array) {
        return true;
    }
    else if (Array.isArray(input) &&
        input.every(e => typeof e === 'number')) {
        return true;
    }
    else {
        return false;
    }
}
function set_buffer(data, size, endian = 'be') {
    if (size === undefined)
        size = data.length;
    within_size(data, size);
    const buffer = new Uint8Array(size).fill(0);
    const offset = (endian === 'be') ? 0 : size - data.length;
    buffer.set(data, offset);
    return buffer;
}
function join_array(arr) {
    let i, offset = 0;
    const size = arr.reduce((len, arr) => len + arr.length, 0);
    const buff = new Uint8Array(size);
    for (i = 0; i < arr.length; i++) {
        const a = arr[i];
        buff.set(a, offset);
        offset += a.length;
    }
    return buff;
}
function bigint_replacer(_, v) {
    return typeof v === 'bigint'
        ? `${v}n`
        : v;
}
function bigint_reviver(_, v) {
    return typeof v === 'string' && /^[0-9]+n$/.test(v)
        ? BigInt(v.slice(0, -1))
        : v;
}
function parse_data$1(data_blob, chunk_size, total_size) {
    const len = data_blob.length, count = total_size / chunk_size;
    if (total_size % chunk_size !== 0) {
        throw new TypeError(`Invalid parameters: ${total_size} % ${chunk_size} !== 0`);
    }
    if (len !== total_size) {
        throw new TypeError(`Invalid data stream: ${len} !== ${total_size}`);
    }
    if (len % chunk_size !== 0) {
        throw new TypeError(`Invalid data stream: ${len} % ${chunk_size} !== 0`);
    }
    const chunks = new Array(count);
    for (let i = 0; i < count; i++) {
        const idx = i * chunk_size;
        chunks[i] = data_blob.subarray(idx, idx + chunk_size);
    }
    return chunks;
}

function buffer_data(data, size, endian) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    else if (data instanceof Uint8Array) {
        return set_buffer(data, size, endian);
    }
    else if (Array.isArray(data)) {
        const bytes = data.map(e => buffer_data(e, size, endian));
        return join_array(bytes);
    }
    else if (typeof data === 'string') {
        return hexToBytes$1(data, size, endian);
    }
    else if (typeof data === 'bigint') {
        return bigToBytes(data, size, endian);
    }
    else if (typeof data === 'number') {
        return numToBytes(data, size, endian);
    }
    else if (typeof data === 'boolean') {
        return Uint8Array.of(data ? 1 : 0);
    }
    throw new TypeError('Unsupported format:' + String(typeof data));
}

class Buff extends Uint8Array {
    static { this.num = numToBuff; }
    static { this.big = bigToBuff; }
    static { this.bin = binToBuff; }
    static { this.raw = rawToBuff; }
    static { this.str = strToBuff; }
    static { this.hex = hexToBuff; }
    static { this.bytes = buffer; }
    static { this.json = jsonToBuff; }
    static { this.base64 = base64ToBuff; }
    static { this.b64url = b64urlToBuff; }
    static { this.bech32 = bech32ToBuff; }
    static { this.bech32m = bech32mToBuff; }
    static { this.b58chk = b58chkToBuff; }
    static { this.encode = strToBytes; }
    static { this.decode = bytesToStr; }
    static { this.parse = parse_data; }
    static { this.is_bytes = is_bytes; }
    static { this.is_hex = is_hex; }
    static { this.is_equal = is_equal; }
    static random(size = 32) {
        const rand = randomBytes(size);
        return new Buff(rand, size);
    }
    static now(size = 4) {
        const stamp = Math.floor(Date.now() / 1000);
        return new Buff(stamp, size);
    }
    constructor(data, size, endian) {
        if (data instanceof Buff &&
            size === undefined) {
            return data;
        }
        const buffer = buffer_data(data, size, endian);
        super(buffer);
    }
    get arr() {
        return [...this];
    }
    get num() {
        return this.to_num();
    }
    get big() {
        return this.to_big();
    }
    get str() {
        return this.to_str();
    }
    get hex() {
        return this.to_hex();
    }
    get raw() {
        return new Uint8Array(this);
    }
    get bin() {
        return this.to_bin();
    }
    get b58chk() {
        return this.to_b58chk();
    }
    get base64() {
        return this.to_base64();
    }
    get b64url() {
        return this.to_b64url();
    }
    get digest() {
        return this.to_hash();
    }
    get id() {
        return this.to_hash().hex;
    }
    get stream() {
        return new Stream(this);
    }
    to_num(endian = 'be') {
        const bytes = (endian === 'be')
            ? this.reverse()
            : this;
        return bytesToNum(bytes);
    }
    to_big(endian = 'be') {
        const bytes = (endian === 'be')
            ? this.reverse()
            : this;
        return bytesToBig(bytes);
    }
    to_bin() {
        return bytesToBin(this);
    }
    to_hash() {
        const digest = sha256(this);
        return new Buff(digest);
    }
    to_json(reviver) {
        if (reviver === undefined) {
            reviver = bigint_reviver;
        }
        const str = bytesToStr(this);
        return JSON.parse(str, reviver);
    }
    to_bech32(prefix, limit) {
        const { encode, to_words } = Bech32;
        const words = to_words(this);
        return encode(prefix, words, limit);
    }
    to_bech32m(prefix, limit) {
        const { encode, to_words } = Bech32m;
        const words = to_words(this);
        return encode(prefix, words, limit);
    }
    to_str() { return bytesToStr(this); }
    to_hex() { return bytesToHex$1(this); }
    to_bytes() { return new Uint8Array(this); }
    to_b58chk() { return B58chk.encode(this); }
    to_base64() { return Base64.encode(this); }
    to_b64url() { return B64url.encode(this); }
    append(data) {
        return Buff.join([this, Buff.bytes(data)]);
    }
    equals(data) {
        return buffer(data).hex === this.hex;
    }
    prepend(data) {
        return Buff.join([Buff.bytes(data), this]);
    }
    reverse() {
        const arr = new Uint8Array(this).reverse();
        return new Buff(arr);
    }
    slice(start, end) {
        const arr = new Uint8Array(this).slice(start, end);
        return new Buff(arr);
    }
    set(array, offset) {
        this.set(array, offset);
    }
    subarray(begin, end) {
        const arr = new Uint8Array(this).subarray(begin, end);
        return new Buff(arr);
    }
    write(bytes, offset) {
        const b = Buff.bytes(bytes);
        this.set(b, offset);
    }
    add_varint(endian) {
        const size = Buff.calc_varint(this.length, endian);
        return Buff.join([size, this]);
    }
    toJSON() {
        return this.hex;
    }
    toString() {
        return this.hex;
    }
    static from(data) {
        return new Buff(Uint8Array.from(data));
    }
    static of(...args) {
        return new Buff(Uint8Array.of(...args));
    }
    static join(arr) {
        const bytes = arr.map(e => Buff.bytes(e));
        const joined = join_array(bytes);
        return new Buff(joined);
    }
    static sort(arr, size) {
        const hex = arr.map(e => buffer(e, size).hex);
        hex.sort();
        return hex.map(e => Buff.hex(e, size));
    }
    static calc_varint(num, endian) {
        if (num < 0xFD) {
            return Buff.num(num, 1);
        }
        else if (num < 0x10000) {
            return Buff.of(0xFD, ...Buff.num(num, 2, endian));
        }
        else if (num < 0x100000000) {
            return Buff.of(0xFE, ...Buff.num(num, 4, endian));
        }
        else if (BigInt(num) < 0x10000000000000000n) {
            return Buff.of(0xFF, ...Buff.num(num, 8, endian));
        }
        else {
            throw new Error(`Value is too large: ${num}`);
        }
    }
}
function numToBuff(number, size, endian) {
    return new Buff(number, size, endian);
}
function binToBuff(data, size, endian) {
    return new Buff(binToBytes(data), size, endian);
}
function bigToBuff(bigint, size, endian) {
    return new Buff(bigint, size, endian);
}
function rawToBuff(data, size, endian) {
    return new Buff(data, size, endian);
}
function strToBuff(data, size, endian) {
    return new Buff(strToBytes(data), size, endian);
}
function hexToBuff(data, size, endian) {
    return new Buff(data, size, endian);
}
function jsonToBuff(data, replacer) {
    if (replacer === undefined) {
        replacer = bigint_replacer;
    }
    const str = JSON.stringify(data, replacer);
    return new Buff(strToBytes(str));
}
function base64ToBuff(data) {
    return new Buff(Base64.decode(data));
}
function b64urlToBuff(data) {
    return new Buff(B64url.decode(data));
}
function bech32ToBuff(data, limit, chk_prefix) {
    const { decode, to_bytes } = Bech32;
    const { prefix, words } = decode(data, limit);
    const bytes = to_bytes(words);
    if (typeof chk_prefix === 'string') {
        is_prefix(prefix, chk_prefix);
    }
    return new Buff(bytes);
}
function bech32mToBuff(data, limit, chk_prefix) {
    const { decode, to_bytes } = Bech32m;
    const { prefix, words } = decode(data, limit);
    const bytes = to_bytes(words);
    if (typeof chk_prefix === 'string') {
        is_prefix(prefix, chk_prefix);
    }
    return new Buff(bytes);
}
function b58chkToBuff(data) {
    return new Buff(B58chk.decode(data));
}
function parse_data(data_blob, chunk_size, total_size) {
    const bytes = buffer_data(data_blob);
    const chunks = parse_data$1(bytes, chunk_size, total_size);
    return chunks.map(e => Buff.bytes(e));
}
function is_equal(a, b) {
    return new Buff(a).hex === new Buff(b).hex;
}
function buffer(bytes, size, end) {
    return new Buff(bytes, size, end);
}
class Stream {
    constructor(data) {
        this.data = Buff.bytes(data);
        this.size = this.data.length;
    }
    peek(size) {
        if (size > this.size) {
            throw new Error(`Size greater than stream: ${size} > ${this.size}`);
        }
        return new Buff(this.data.slice(0, size));
    }
    read(size) {
        const chunk = this.peek(size);
        this.data = this.data.slice(size);
        this.size = this.data.length;
        return chunk;
    }
    read_varint(endian) {
        const num = this.read(1).num;
        switch (true) {
            case (num >= 0 && num < 0xFD):
                return num;
            case (num === 0xFD):
                return this.read(2).to_num(endian);
            case (num === 0xFE):
                return this.read(4).to_num(endian);
            case (num === 0xFF):
                return this.read(8).to_num(endian);
            default:
                throw new Error(`Varint is out of range: ${num}`);
        }
    }
}

// HMAC (RFC 2104)
class HMAC extends Hash {
    constructor(hash$1, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        hash(hash$1);
        const key = toBytes(_key);
        this.iHash = hash$1.create();
        if (typeof this.iHash.update !== 'function')
            throw new Error('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash$1.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash$1.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        exists$1(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        exists$1(this);
        bytes(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

function taghash(tag) {
    const hash = Buff.str(tag).digest;
    return Buff.join([hash, hash]);
}
function hash340(tag, ...data) {
    const hash = taghash(tag);
    return Buff.join([hash, ...data]).digest;
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// 100 lines of code in the file are duplicated from noble-hashes (utils).
// This is OK: `abstract` directory does not use noble-hashes.
// User may opt-in into using different hashing library. This way, noble-hashes
// won't be included into their bundle.
const _0n$4 = BigInt(0);
const _1n$5 = BigInt(1);
const _2n$3 = BigInt(2);
function isBytes(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
function bytesToHex(bytes) {
    if (!isBytes(bytes))
        throw new Error('Uint8Array expected');
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
function numberToHexUnpadded(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // Big Endian
    return BigInt(hex === '' ? '0' : `0x${hex}`);
}
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, _A: 65, _F: 70, _a: 97, _f: 102 };
function asciiToBase16(char) {
    if (char >= asciis._0 && char <= asciis._9)
        return char - asciis._0;
    if (char >= asciis._A && char <= asciis._F)
        return char - (asciis._A - 10);
    if (char >= asciis._a && char <= asciis._f)
        return char - (asciis._a - 10);
    return;
}
/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('padded hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
    }
    return array;
}
// BE: Big Endian, LE: Little Endian
function bytesToNumberBE(bytes) {
    return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
    if (!isBytes(bytes))
        throw new Error('Uint8Array expected');
    return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
    return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}
function numberToBytesLE(n, len) {
    return numberToBytesBE(n, len).reverse();
}
// Unpadded, rarely used
function numberToVarBytesBE(n) {
    return hexToBytes(numberToHexUnpadded(n));
}
/**
 * Takes hex string or Uint8Array, converts to Uint8Array.
 * Validates output length.
 * Will throw error for other types.
 * @param title descriptive title for an error e.g. 'private key'
 * @param hex hex string or Uint8Array
 * @param expectedLength optional, will compare to result array's length
 * @returns
 */
function ensureBytes(title, hex, expectedLength) {
    let res;
    if (typeof hex === 'string') {
        try {
            res = hexToBytes(hex);
        }
        catch (e) {
            throw new Error(`${title} must be valid hex string, got "${hex}". Cause: ${e}`);
        }
    }
    else if (isBytes(hex)) {
        // Uint8Array.from() instead of hash.slice() because node.js Buffer
        // is instance of Uint8Array, and its slice() creates **mutable** copy
        res = Uint8Array.from(hex);
    }
    else {
        throw new Error(`${title} must be hex string or Uint8Array`);
    }
    const len = res.length;
    if (typeof expectedLength === 'number' && len !== expectedLength)
        throw new Error(`${title} expected ${expectedLength} bytes, got ${len}`);
    return res;
}
/**
 * Copies several Uint8Arrays into one.
 */
function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        if (!isBytes(a))
            throw new Error('Uint8Array expected');
        sum += a.length;
    }
    let res = new Uint8Array(sum);
    let pad = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
// Compares 2 u8a-s in kinda constant time
function equalBytes(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
// Bit operations
/**
 * Calculates amount of bits in a bigint.
 * Same as `n.toString(2).length`
 */
function bitLen(n) {
    let len;
    for (len = 0; n > _0n$4; n >>= _1n$5, len += 1)
        ;
    return len;
}
/**
 * Gets single bit at position.
 * NOTE: first bit position is 0 (same as arrays)
 * Same as `!!+Array.from(n.toString(2)).reverse()[pos]`
 */
function bitGet(n, pos) {
    return (n >> BigInt(pos)) & _1n$5;
}
/**
 * Sets single bit at position.
 */
const bitSet = (n, pos, value) => {
    return n | ((value ? _1n$5 : _0n$4) << BigInt(pos));
};
/**
 * Calculate mask for N bits. Not using ** operator with bigints because of old engines.
 * Same as BigInt(`0b${Array(i).fill('1').join('')}`)
 */
const bitMask = (n) => (_2n$3 << BigInt(n - 1)) - _1n$5;
// DRBG
const u8n = (data) => new Uint8Array(data); // creates Uint8Array
const u8fr = (arr) => Uint8Array.from(arr); // another shortcut
/**
 * Minimal HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
 * @returns function that will call DRBG until 2nd arg returns something meaningful
 * @example
 *   const drbg = createHmacDRBG<Key>(32, 32, hmac);
 *   drbg(seed, bytesToKey); // bytesToKey must return Key or undefined
 */
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
    if (typeof hashLen !== 'number' || hashLen < 2)
        throw new Error('hashLen must be a number');
    if (typeof qByteLen !== 'number' || qByteLen < 2)
        throw new Error('qByteLen must be a number');
    if (typeof hmacFn !== 'function')
        throw new Error('hmacFn must be a function');
    // Step B, Step C: set hashLen to 8*ceil(hlen/8)
    let v = u8n(hashLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
    let k = u8n(hashLen); // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
    let i = 0; // Iterations counter, will throw when over 1000
    const reset = () => {
        v.fill(1);
        k.fill(0);
        i = 0;
    };
    const h = (...b) => hmacFn(k, v, ...b); // hmac(k)(v, ...values)
    const reseed = (seed = u8n()) => {
        // HMAC-DRBG reseed() function. Steps D-G
        k = h(u8fr([0x00]), seed); // k = hmac(k || v || 0x00 || seed)
        v = h(); // v = hmac(k || v)
        if (seed.length === 0)
            return;
        k = h(u8fr([0x01]), seed); // k = hmac(k || v || 0x01 || seed)
        v = h(); // v = hmac(k || v)
    };
    const gen = () => {
        // HMAC-DRBG generate() function
        if (i++ >= 1000)
            throw new Error('drbg: tried 1000 values');
        let len = 0;
        const out = [];
        while (len < qByteLen) {
            v = h();
            const sl = v.slice();
            out.push(sl);
            len += v.length;
        }
        return concatBytes(...out);
    };
    const genUntil = (seed, pred) => {
        reset();
        reseed(seed); // Steps D-G
        let res = undefined; // Step H: grind until k is in [1..n-1]
        while (!(res = pred(gen())))
            reseed();
        reset();
        return res;
    };
    return genUntil;
}
// Validating curves and fields
const validatorFns = {
    bigint: (val) => typeof val === 'bigint',
    function: (val) => typeof val === 'function',
    boolean: (val) => typeof val === 'boolean',
    string: (val) => typeof val === 'string',
    stringOrUint8Array: (val) => typeof val === 'string' || isBytes(val),
    isSafeInteger: (val) => Number.isSafeInteger(val),
    array: (val) => Array.isArray(val),
    field: (val, object) => object.Fp.isValid(val),
    hash: (val) => typeof val === 'function' && Number.isSafeInteger(val.outputLen),
};
// type Record<K extends string | number | symbol, T> = { [P in K]: T; }
function validateObject(object, validators, optValidators = {}) {
    const checkField = (fieldName, type, isOptional) => {
        const checkVal = validatorFns[type];
        if (typeof checkVal !== 'function')
            throw new Error(`Invalid validator "${type}", expected function`);
        const val = object[fieldName];
        if (isOptional && val === undefined)
            return;
        if (!checkVal(val, object)) {
            throw new Error(`Invalid param ${String(fieldName)}=${val} (${typeof val}), expected ${type}`);
        }
    };
    for (const [fieldName, type] of Object.entries(validators))
        checkField(fieldName, type, false);
    for (const [fieldName, type] of Object.entries(optValidators))
        checkField(fieldName, type, true);
    return object;
}
// validate type tests
// const o: { a: number; b: number; c: number } = { a: 1, b: 5, c: 6 };
// const z0 = validateObject(o, { a: 'isSafeInteger' }, { c: 'bigint' }); // Ok!
// // Should fail type-check
// const z1 = validateObject(o, { a: 'tmp' }, { c: 'zz' });
// const z2 = validateObject(o, { a: 'isSafeInteger' }, { c: 'zz' });
// const z3 = validateObject(o, { test: 'boolean', z: 'bug' });
// const z4 = validateObject(o, { a: 'boolean', z: 'bug' });

var ut = /*#__PURE__*/Object.freeze({
    __proto__: null,
    bitGet: bitGet,
    bitLen: bitLen,
    bitMask: bitMask,
    bitSet: bitSet,
    bytesToHex: bytesToHex,
    bytesToNumberBE: bytesToNumberBE,
    bytesToNumberLE: bytesToNumberLE,
    concatBytes: concatBytes,
    createHmacDrbg: createHmacDrbg,
    ensureBytes: ensureBytes,
    equalBytes: equalBytes,
    hexToBytes: hexToBytes,
    hexToNumber: hexToNumber,
    isBytes: isBytes,
    numberToBytesBE: numberToBytesBE,
    numberToBytesLE: numberToBytesLE,
    numberToHexUnpadded: numberToHexUnpadded,
    numberToVarBytesBE: numberToVarBytesBE,
    utf8ToBytes: utf8ToBytes,
    validateObject: validateObject
});

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Utilities for modular arithmetics and finite fields
// prettier-ignore
const _0n$3 = BigInt(0), _1n$4 = BigInt(1), _2n$2 = BigInt(2), _3n$2 = BigInt(3);
// prettier-ignore
const _4n$1 = BigInt(4), _5n = BigInt(5), _8n = BigInt(8);
// prettier-ignore
BigInt(9); BigInt(16);
// Calculates a modulo b
function mod(a, b) {
    const result = a % b;
    return result >= _0n$3 ? result : b + result;
}
/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 */
// TODO: use field version && remove
function pow(num, power, modulo) {
    if (modulo <= _0n$3 || power < _0n$3)
        throw new Error('Expected power/modulo > 0');
    if (modulo === _1n$4)
        return _0n$3;
    let res = _1n$4;
    while (power > _0n$3) {
        if (power & _1n$4)
            res = (res * num) % modulo;
        num = (num * num) % modulo;
        power >>= _1n$4;
    }
    return res;
}
// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
function pow2(x, power, modulo) {
    let res = x;
    while (power-- > _0n$3) {
        res *= res;
        res %= modulo;
    }
    return res;
}
// Inverses number over modulo
function invert(number, modulo) {
    if (number === _0n$3 || modulo <= _0n$3) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    // Euclidean GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
    // Fermat's little theorem "CT-like" version inv(n) = n^(m-2) mod m is 30x slower.
    let a = mod(number, modulo);
    let b = modulo;
    // prettier-ignore
    let x = _0n$3, u = _1n$4;
    while (a !== _0n$3) {
        // JIT applies optimization if those two lines follow each other
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        // prettier-ignore
        b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== _1n$4)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
/**
 * Tonelli-Shanks square root search algorithm.
 * 1. https://eprint.iacr.org/2012/685.pdf (page 12)
 * 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
 * Will start an infinite loop if field order P is not prime.
 * @param P field order
 * @returns function that takes field Fp (created from P) and number n
 */
function tonelliShanks(P) {
    // Legendre constant: used to calculate Legendre symbol (a | p),
    // which denotes the value of a^((p-1)/2) (mod p).
    // (a | p) ≡ 1    if a is a square (mod p)
    // (a | p) ≡ -1   if a is not a square (mod p)
    // (a | p) ≡ 0    if a ≡ 0 (mod p)
    const legendreC = (P - _1n$4) / _2n$2;
    let Q, S, Z;
    // Step 1: By factoring out powers of 2 from p - 1,
    // find q and s such that p - 1 = q*(2^s) with q odd
    for (Q = P - _1n$4, S = 0; Q % _2n$2 === _0n$3; Q /= _2n$2, S++)
        ;
    // Step 2: Select a non-square z such that (z | p) ≡ -1 and set c ≡ zq
    for (Z = _2n$2; Z < P && pow(Z, legendreC, P) !== P - _1n$4; Z++)
        ;
    // Fast-path
    if (S === 1) {
        const p1div4 = (P + _1n$4) / _4n$1;
        return function tonelliFast(Fp, n) {
            const root = Fp.pow(n, p1div4);
            if (!Fp.eql(Fp.sqr(root), n))
                throw new Error('Cannot find square root');
            return root;
        };
    }
    // Slow-path
    const Q1div2 = (Q + _1n$4) / _2n$2;
    return function tonelliSlow(Fp, n) {
        // Step 0: Check that n is indeed a square: (n | p) should not be ≡ -1
        if (Fp.pow(n, legendreC) === Fp.neg(Fp.ONE))
            throw new Error('Cannot find square root');
        let r = S;
        // TODO: will fail at Fp2/etc
        let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q); // will update both x and b
        let x = Fp.pow(n, Q1div2); // first guess at the square root
        let b = Fp.pow(n, Q); // first guess at the fudge factor
        while (!Fp.eql(b, Fp.ONE)) {
            if (Fp.eql(b, Fp.ZERO))
                return Fp.ZERO; // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm (4. If t = 0, return r = 0)
            // Find m such b^(2^m)==1
            let m = 1;
            for (let t2 = Fp.sqr(b); m < r; m++) {
                if (Fp.eql(t2, Fp.ONE))
                    break;
                t2 = Fp.sqr(t2); // t2 *= t2
            }
            // NOTE: r-m-1 can be bigger than 32, need to convert to bigint before shift, otherwise there will be overflow
            const ge = Fp.pow(g, _1n$4 << BigInt(r - m - 1)); // ge = 2^(r-m-1)
            g = Fp.sqr(ge); // g = ge * ge
            x = Fp.mul(x, ge); // x *= ge
            b = Fp.mul(b, g); // b *= g
            r = m;
        }
        return x;
    };
}
function FpSqrt(P) {
    // NOTE: different algorithms can give different roots, it is up to user to decide which one they want.
    // For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).
    // P ≡ 3 (mod 4)
    // √n = n^((P+1)/4)
    if (P % _4n$1 === _3n$2) {
        // Not all roots possible!
        // const ORDER =
        //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
        // const NUM = 72057594037927816n;
        const p1div4 = (P + _1n$4) / _4n$1;
        return function sqrt3mod4(Fp, n) {
            const root = Fp.pow(n, p1div4);
            // Throw if root**2 != n
            if (!Fp.eql(Fp.sqr(root), n))
                throw new Error('Cannot find square root');
            return root;
        };
    }
    // Atkin algorithm for q ≡ 5 (mod 8), https://eprint.iacr.org/2012/685.pdf (page 10)
    if (P % _8n === _5n) {
        const c1 = (P - _5n) / _8n;
        return function sqrt5mod8(Fp, n) {
            const n2 = Fp.mul(n, _2n$2);
            const v = Fp.pow(n2, c1);
            const nv = Fp.mul(n, v);
            const i = Fp.mul(Fp.mul(nv, _2n$2), v);
            const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
            if (!Fp.eql(Fp.sqr(root), n))
                throw new Error('Cannot find square root');
            return root;
        };
    }
    // Other cases: Tonelli-Shanks algorithm
    return tonelliShanks(P);
}
// prettier-ignore
const FIELD_FIELDS = [
    'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
    'eql', 'add', 'sub', 'mul', 'pow', 'div',
    'addN', 'subN', 'mulN', 'sqrN'
];
function validateField(field) {
    const initial = {
        ORDER: 'bigint',
        MASK: 'bigint',
        BYTES: 'isSafeInteger',
        BITS: 'isSafeInteger',
    };
    const opts = FIELD_FIELDS.reduce((map, val) => {
        map[val] = 'function';
        return map;
    }, initial);
    return validateObject(field, opts);
}
// Generic field functions
/**
 * Same as `pow` but for Fp: non-constant-time.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 */
function FpPow(f, num, power) {
    // Should have same speed as pow for bigints
    // TODO: benchmark!
    if (power < _0n$3)
        throw new Error('Expected power > 0');
    if (power === _0n$3)
        return f.ONE;
    if (power === _1n$4)
        return num;
    let p = f.ONE;
    let d = num;
    while (power > _0n$3) {
        if (power & _1n$4)
            p = f.mul(p, d);
        d = f.sqr(d);
        power >>= _1n$4;
    }
    return p;
}
/**
 * Efficiently invert an array of Field elements.
 * `inv(0)` will return `undefined` here: make sure to throw an error.
 */
function FpInvertBatch(f, nums) {
    const tmp = new Array(nums.length);
    // Walk from first to last, multiply them by each other MOD p
    const lastMultiplied = nums.reduce((acc, num, i) => {
        if (f.is0(num))
            return acc;
        tmp[i] = acc;
        return f.mul(acc, num);
    }, f.ONE);
    // Invert last element
    const inverted = f.inv(lastMultiplied);
    // Walk from last to first, multiply them by inverted each other MOD p
    nums.reduceRight((acc, num, i) => {
        if (f.is0(num))
            return acc;
        tmp[i] = f.mul(acc, tmp[i]);
        return f.mul(acc, num);
    }, inverted);
    return tmp;
}
// CURVE.n lengths
function nLength(n, nBitLength) {
    // Bit size, byte size of CURVE.n
    const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
    const nByteLength = Math.ceil(_nBitLength / 8);
    return { nBitLength: _nBitLength, nByteLength };
}
/**
 * Initializes a finite field over prime. **Non-primes are not supported.**
 * Do not init in loop: slow. Very fragile: always run a benchmark on a change.
 * Major performance optimizations:
 * * a) denormalized operations like mulN instead of mul
 * * b) same object shape: never add or remove keys
 * * c) Object.freeze
 * @param ORDER prime positive bigint
 * @param bitLen how many bits the field consumes
 * @param isLE (def: false) if encoding / decoding should be in little-endian
 * @param redef optional faster redefinitions of sqrt and other methods
 */
function Field$1(ORDER, bitLen, isLE = false, redef = {}) {
    if (ORDER <= _0n$3)
        throw new Error(`Expected Field ORDER > 0, got ${ORDER}`);
    const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
    if (BYTES > 2048)
        throw new Error('Field lengths over 2048 bytes are not supported');
    const sqrtP = FpSqrt(ORDER);
    const f = Object.freeze({
        ORDER,
        BITS,
        BYTES,
        MASK: bitMask(BITS),
        ZERO: _0n$3,
        ONE: _1n$4,
        create: (num) => mod(num, ORDER),
        isValid: (num) => {
            if (typeof num !== 'bigint')
                throw new Error(`Invalid field element: expected bigint, got ${typeof num}`);
            return _0n$3 <= num && num < ORDER; // 0 is valid element, but it's not invertible
        },
        is0: (num) => num === _0n$3,
        isOdd: (num) => (num & _1n$4) === _1n$4,
        neg: (num) => mod(-num, ORDER),
        eql: (lhs, rhs) => lhs === rhs,
        sqr: (num) => mod(num * num, ORDER),
        add: (lhs, rhs) => mod(lhs + rhs, ORDER),
        sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
        mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
        pow: (num, power) => FpPow(f, num, power),
        div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
        // Same as above, but doesn't normalize
        sqrN: (num) => num * num,
        addN: (lhs, rhs) => lhs + rhs,
        subN: (lhs, rhs) => lhs - rhs,
        mulN: (lhs, rhs) => lhs * rhs,
        inv: (num) => invert(num, ORDER),
        sqrt: redef.sqrt || ((n) => sqrtP(f, n)),
        invertBatch: (lst) => FpInvertBatch(f, lst),
        // TODO: do we really need constant cmov?
        // We don't have const-time bigints anyway, so probably will be not very useful
        cmov: (a, b, c) => (c ? b : a),
        toBytes: (num) => (isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES)),
        fromBytes: (bytes) => {
            if (bytes.length !== BYTES)
                throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes.length}`);
            return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
        },
    });
    return Object.freeze(f);
}
/**
 * Returns total number of bytes consumed by the field element.
 * For example, 32 bytes for usual 256-bit weierstrass curve.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of field
 */
function getFieldBytesLength(fieldOrder) {
    if (typeof fieldOrder !== 'bigint')
        throw new Error('field order must be bigint');
    const bitLength = fieldOrder.toString(2).length;
    return Math.ceil(bitLength / 8);
}
/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of target hash
 */
function getMinHashLength(fieldOrder) {
    const length = getFieldBytesLength(fieldOrder);
    return length + Math.ceil(length / 2);
}
/**
 * "Constant-time" private key generation utility.
 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being negligible.
 * Needs at least 48 bytes of input for 32-byte private key.
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
 * RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
 * @param hash hash output from SHA3 or a similar function
 * @param groupOrder size of subgroup - (e.g. secp256k1.CURVE.n)
 * @param isLE interpret hash bytes as LE num
 * @returns valid private scalar
 */
function mapHashToField(key, fieldOrder, isLE = false) {
    const len = key.length;
    const fieldLen = getFieldBytesLength(fieldOrder);
    const minLen = getMinHashLength(fieldOrder);
    // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
    if (len < 16 || len < minLen || len > 1024)
        throw new Error(`expected ${minLen}-1024 bytes of input, got ${len}`);
    const num = isLE ? bytesToNumberBE(key) : bytesToNumberLE(key);
    // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
    const reduced = mod(num, fieldOrder - _1n$4) + _1n$4;
    return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Abelian group utilities
const _0n$2 = BigInt(0);
const _1n$3 = BigInt(1);
// Elliptic curve multiplication of Point by scalar. Fragile.
// Scalars should always be less than curve order: this should be checked inside of a curve itself.
// Creates precomputation tables for fast multiplication:
// - private scalar is split by fixed size windows of W bits
// - every window point is collected from window's table & added to accumulator
// - since windows are different, same point inside tables won't be accessed more than once per calc
// - each multiplication is 'Math.ceil(CURVE_ORDER / 𝑊) + 1' point additions (fixed for any scalar)
// - +1 window is neccessary for wNAF
// - wNAF reduces table size: 2x less memory + 2x faster generation, but 10% slower multiplication
// TODO: Research returning 2d JS array of windows, instead of a single window. This would allow
// windows to be in different memory locations
function wNAF(c, bits) {
    const constTimeNegate = (condition, item) => {
        const neg = item.negate();
        return condition ? neg : item;
    };
    const opts = (W) => {
        const windows = Math.ceil(bits / W) + 1; // +1, because
        const windowSize = 2 ** (W - 1); // -1 because we skip zero
        return { windows, windowSize };
    };
    return {
        constTimeNegate,
        // non-const time multiplication ladder
        unsafeLadder(elm, n) {
            let p = c.ZERO;
            let d = elm;
            while (n > _0n$2) {
                if (n & _1n$3)
                    p = p.add(d);
                d = d.double();
                n >>= _1n$3;
            }
            return p;
        },
        /**
         * Creates a wNAF precomputation window. Used for caching.
         * Default window size is set by `utils.precompute()` and is equal to 8.
         * Number of precomputed points depends on the curve size:
         * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
         * - 𝑊 is the window size
         * - 𝑛 is the bitlength of the curve order.
         * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
         * @returns precomputed point tables flattened to a single array
         */
        precomputeWindow(elm, W) {
            const { windows, windowSize } = opts(W);
            const points = [];
            let p = elm;
            let base = p;
            for (let window = 0; window < windows; window++) {
                base = p;
                points.push(base);
                // =1, because we skip zero
                for (let i = 1; i < windowSize; i++) {
                    base = base.add(p);
                    points.push(base);
                }
                p = base.double();
            }
            return points;
        },
        /**
         * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
         * @param W window size
         * @param precomputes precomputed tables
         * @param n scalar (we don't check here, but should be less than curve order)
         * @returns real and fake (for const-time) points
         */
        wNAF(W, precomputes, n) {
            // TODO: maybe check that scalar is less than group order? wNAF behavious is undefined otherwise
            // But need to carefully remove other checks before wNAF. ORDER == bits here
            const { windows, windowSize } = opts(W);
            let p = c.ZERO;
            let f = c.BASE;
            const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
            const maxNumber = 2 ** W;
            const shiftBy = BigInt(W);
            for (let window = 0; window < windows; window++) {
                const offset = window * windowSize;
                // Extract W bits.
                let wbits = Number(n & mask);
                // Shift number by W bits.
                n >>= shiftBy;
                // If the bits are bigger than max size, we'll split those.
                // +224 => 256 - 32
                if (wbits > windowSize) {
                    wbits -= maxNumber;
                    n += _1n$3;
                }
                // This code was first written with assumption that 'f' and 'p' will never be infinity point:
                // since each addition is multiplied by 2 ** W, it cannot cancel each other. However,
                // there is negate now: it is possible that negated element from low value
                // would be the same as high element, which will create carry into next window.
                // It's not obvious how this can fail, but still worth investigating later.
                // Check if we're onto Zero point.
                // Add random point inside current window to f.
                const offset1 = offset;
                const offset2 = offset + Math.abs(wbits) - 1; // -1 because we skip zero
                const cond1 = window % 2 !== 0;
                const cond2 = wbits < 0;
                if (wbits === 0) {
                    // The most important part for const-time getPublicKey
                    f = f.add(constTimeNegate(cond1, precomputes[offset1]));
                }
                else {
                    p = p.add(constTimeNegate(cond2, precomputes[offset2]));
                }
            }
            // JIT-compiler should not eliminate f here, since it will later be used in normalizeZ()
            // Even if the variable is still unused, there are some checks which will
            // throw an exception, so compiler needs to prove they won't happen, which is hard.
            // At this point there is a way to F be infinity-point even if p is not,
            // which makes it less const-time: around 1 bigint multiply.
            return { p, f };
        },
        wNAFCached(P, precomputesMap, n, transform) {
            // @ts-ignore
            const W = P._WINDOW_SIZE || 1;
            // Calculate precomputes on a first run, reuse them after
            let comp = precomputesMap.get(P);
            if (!comp) {
                comp = this.precomputeWindow(P, W);
                if (W !== 1) {
                    precomputesMap.set(P, transform(comp));
                }
            }
            return this.wNAF(W, comp, n);
        },
    };
}
function validateBasic(curve) {
    validateField(curve.Fp);
    validateObject(curve, {
        n: 'bigint',
        h: 'bigint',
        Gx: 'field',
        Gy: 'field',
    }, {
        nBitLength: 'isSafeInteger',
        nByteLength: 'isSafeInteger',
    });
    // Set defaults
    return Object.freeze({
        ...nLength(curve.n, curve.nBitLength),
        ...curve,
        ...{ p: curve.Fp.ORDER },
    });
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Short Weierstrass curve. The formula is: y² = x³ + ax + b
function validatePointOpts(curve) {
    const opts = validateBasic(curve);
    validateObject(opts, {
        a: 'field',
        b: 'field',
    }, {
        allowedPrivateKeyLengths: 'array',
        wrapPrivateKey: 'boolean',
        isTorsionFree: 'function',
        clearCofactor: 'function',
        allowInfinityPoint: 'boolean',
        fromBytes: 'function',
        toBytes: 'function',
    });
    const { endo, Fp, a } = opts;
    if (endo) {
        if (!Fp.eql(a, Fp.ZERO)) {
            throw new Error('Endomorphism can only be defined for Koblitz curves that have a=0');
        }
        if (typeof endo !== 'object' ||
            typeof endo.beta !== 'bigint' ||
            typeof endo.splitScalar !== 'function') {
            throw new Error('Expected endomorphism with beta: bigint and splitScalar: function');
        }
    }
    return Object.freeze({ ...opts });
}
// ASN.1 DER encoding utilities
const { bytesToNumberBE: b2n, hexToBytes: h2b } = ut;
const DER = {
    // asn.1 DER encoding utils
    Err: class DERErr extends Error {
        constructor(m = '') {
            super(m);
        }
    },
    _parseInt(data) {
        const { Err: E } = DER;
        if (data.length < 2 || data[0] !== 0x02)
            throw new E('Invalid signature integer tag');
        const len = data[1];
        const res = data.subarray(2, len + 2);
        if (!len || res.length !== len)
            throw new E('Invalid signature integer: wrong length');
        // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
        // since we always use positive integers here. It must always be empty:
        // - add zero byte if exists
        // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
        if (res[0] & 0b10000000)
            throw new E('Invalid signature integer: negative');
        if (res[0] === 0x00 && !(res[1] & 0b10000000))
            throw new E('Invalid signature integer: unnecessary leading zero');
        return { d: b2n(res), l: data.subarray(len + 2) }; // d is data, l is left
    },
    toSig(hex) {
        // parse DER signature
        const { Err: E } = DER;
        const data = typeof hex === 'string' ? h2b(hex) : hex;
        if (!isBytes(data))
            throw new Error('ui8a expected');
        let l = data.length;
        if (l < 2 || data[0] != 0x30)
            throw new E('Invalid signature tag');
        if (data[1] !== l - 2)
            throw new E('Invalid signature: incorrect length');
        const { d: r, l: sBytes } = DER._parseInt(data.subarray(2));
        const { d: s, l: rBytesLeft } = DER._parseInt(sBytes);
        if (rBytesLeft.length)
            throw new E('Invalid signature: left bytes after parsing');
        return { r, s };
    },
    hexFromSig(sig) {
        // Add leading zero if first byte has negative bit enabled. More details in '_parseInt'
        const slice = (s) => (Number.parseInt(s[0], 16) & 0b1000 ? '00' + s : s);
        const h = (num) => {
            const hex = num.toString(16);
            return hex.length & 1 ? `0${hex}` : hex;
        };
        const s = slice(h(sig.s));
        const r = slice(h(sig.r));
        const shl = s.length / 2;
        const rhl = r.length / 2;
        const sl = h(shl);
        const rl = h(rhl);
        return `30${h(rhl + shl + 4)}02${rl}${r}02${sl}${s}`;
    },
};
// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n$1 = BigInt(0), _1n$2 = BigInt(1); BigInt(2); const _3n$1 = BigInt(3); BigInt(4);
function weierstrassPoints(opts) {
    const CURVE = validatePointOpts(opts);
    const { Fp } = CURVE; // All curves has same field / group length as for now, but they can differ
    const toBytes = CURVE.toBytes ||
        ((_c, point, _isCompressed) => {
            const a = point.toAffine();
            return concatBytes(Uint8Array.from([0x04]), Fp.toBytes(a.x), Fp.toBytes(a.y));
        });
    const fromBytes = CURVE.fromBytes ||
        ((bytes) => {
            // const head = bytes[0];
            const tail = bytes.subarray(1);
            // if (head !== 0x04) throw new Error('Only non-compressed encoding is supported');
            const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
            const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
            return { x, y };
        });
    /**
     * y² = x³ + ax + b: Short weierstrass curve formula
     * @returns y²
     */
    function weierstrassEquation(x) {
        const { a, b } = CURVE;
        const x2 = Fp.sqr(x); // x * x
        const x3 = Fp.mul(x2, x); // x2 * x
        return Fp.add(Fp.add(x3, Fp.mul(x, a)), b); // x3 + a * x + b
    }
    // Validate whether the passed curve params are valid.
    // We check if curve equation works for generator point.
    // `assertValidity()` won't work: `isTorsionFree()` is not available at this point in bls12-381.
    // ProjectivePoint class has not been initialized yet.
    if (!Fp.eql(Fp.sqr(CURVE.Gy), weierstrassEquation(CURVE.Gx)))
        throw new Error('bad generator point: equation left != right');
    // Valid group elements reside in range 1..n-1
    function isWithinCurveOrder(num) {
        return typeof num === 'bigint' && _0n$1 < num && num < CURVE.n;
    }
    function assertGE(num) {
        if (!isWithinCurveOrder(num))
            throw new Error('Expected valid bigint: 0 < bigint < curve.n');
    }
    // Validates if priv key is valid and converts it to bigint.
    // Supports options allowedPrivateKeyLengths and wrapPrivateKey.
    function normPrivateKeyToScalar(key) {
        const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n } = CURVE;
        if (lengths && typeof key !== 'bigint') {
            if (isBytes(key))
                key = bytesToHex(key);
            // Normalize to hex string, pad. E.g. P521 would norm 130-132 char hex to 132-char bytes
            if (typeof key !== 'string' || !lengths.includes(key.length))
                throw new Error('Invalid key');
            key = key.padStart(nByteLength * 2, '0');
        }
        let num;
        try {
            num =
                typeof key === 'bigint'
                    ? key
                    : bytesToNumberBE(ensureBytes('private key', key, nByteLength));
        }
        catch (error) {
            throw new Error(`private key must be ${nByteLength} bytes, hex or bigint, not ${typeof key}`);
        }
        if (wrapPrivateKey)
            num = mod(num, n); // disabled by default, enabled for BLS
        assertGE(num); // num in range [1..N-1]
        return num;
    }
    const pointPrecomputes = new Map();
    function assertPrjPoint(other) {
        if (!(other instanceof Point))
            throw new Error('ProjectivePoint expected');
    }
    /**
     * Projective Point works in 3d / projective (homogeneous) coordinates: (x, y, z) ∋ (x=x/z, y=y/z)
     * Default Point works in 2d / affine coordinates: (x, y)
     * We're doing calculations in projective, because its operations don't require costly inversion.
     */
    class Point {
        constructor(px, py, pz) {
            this.px = px;
            this.py = py;
            this.pz = pz;
            if (px == null || !Fp.isValid(px))
                throw new Error('x required');
            if (py == null || !Fp.isValid(py))
                throw new Error('y required');
            if (pz == null || !Fp.isValid(pz))
                throw new Error('z required');
        }
        // Does not validate if the point is on-curve.
        // Use fromHex instead, or call assertValidity() later.
        static fromAffine(p) {
            const { x, y } = p || {};
            if (!p || !Fp.isValid(x) || !Fp.isValid(y))
                throw new Error('invalid affine point');
            if (p instanceof Point)
                throw new Error('projective point not allowed');
            const is0 = (i) => Fp.eql(i, Fp.ZERO);
            // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
            if (is0(x) && is0(y))
                return Point.ZERO;
            return new Point(x, y, Fp.ONE);
        }
        get x() {
            return this.toAffine().x;
        }
        get y() {
            return this.toAffine().y;
        }
        /**
         * Takes a bunch of Projective Points but executes only one
         * inversion on all of them. Inversion is very slow operation,
         * so this improves performance massively.
         * Optimization: converts a list of projective points to a list of identical points with Z=1.
         */
        static normalizeZ(points) {
            const toInv = Fp.invertBatch(points.map((p) => p.pz));
            return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
        }
        /**
         * Converts hash string or Uint8Array to Point.
         * @param hex short/long ECDSA hex
         */
        static fromHex(hex) {
            const P = Point.fromAffine(fromBytes(ensureBytes('pointHex', hex)));
            P.assertValidity();
            return P;
        }
        // Multiplies generator point by privateKey.
        static fromPrivateKey(privateKey) {
            return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
        }
        // "Private method", don't use it directly
        _setWindowSize(windowSize) {
            this._WINDOW_SIZE = windowSize;
            pointPrecomputes.delete(this);
        }
        // A point on curve is valid if it conforms to equation.
        assertValidity() {
            if (this.is0()) {
                // (0, 1, 0) aka ZERO is invalid in most contexts.
                // In BLS, ZERO can be serialized, so we allow it.
                // (0, 0, 0) is wrong representation of ZERO and is always invalid.
                if (CURVE.allowInfinityPoint && !Fp.is0(this.py))
                    return;
                throw new Error('bad point: ZERO');
            }
            // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
            const { x, y } = this.toAffine();
            // Check if x, y are valid field elements
            if (!Fp.isValid(x) || !Fp.isValid(y))
                throw new Error('bad point: x or y not FE');
            const left = Fp.sqr(y); // y²
            const right = weierstrassEquation(x); // x³ + ax + b
            if (!Fp.eql(left, right))
                throw new Error('bad point: equation left != right');
            if (!this.isTorsionFree())
                throw new Error('bad point: not in prime-order subgroup');
        }
        hasEvenY() {
            const { y } = this.toAffine();
            if (Fp.isOdd)
                return !Fp.isOdd(y);
            throw new Error("Field doesn't support isOdd");
        }
        /**
         * Compare one point to another.
         */
        equals(other) {
            assertPrjPoint(other);
            const { px: X1, py: Y1, pz: Z1 } = this;
            const { px: X2, py: Y2, pz: Z2 } = other;
            const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
            const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
            return U1 && U2;
        }
        /**
         * Flips point to one corresponding to (x, -y) in Affine coordinates.
         */
        negate() {
            return new Point(this.px, Fp.neg(this.py), this.pz);
        }
        // Renes-Costello-Batina exception-free doubling formula.
        // There is 30% faster Jacobian formula, but it is not complete.
        // https://eprint.iacr.org/2015/1060, algorithm 3
        // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
        double() {
            const { a, b } = CURVE;
            const b3 = Fp.mul(b, _3n$1);
            const { px: X1, py: Y1, pz: Z1 } = this;
            let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
            let t0 = Fp.mul(X1, X1); // step 1
            let t1 = Fp.mul(Y1, Y1);
            let t2 = Fp.mul(Z1, Z1);
            let t3 = Fp.mul(X1, Y1);
            t3 = Fp.add(t3, t3); // step 5
            Z3 = Fp.mul(X1, Z1);
            Z3 = Fp.add(Z3, Z3);
            X3 = Fp.mul(a, Z3);
            Y3 = Fp.mul(b3, t2);
            Y3 = Fp.add(X3, Y3); // step 10
            X3 = Fp.sub(t1, Y3);
            Y3 = Fp.add(t1, Y3);
            Y3 = Fp.mul(X3, Y3);
            X3 = Fp.mul(t3, X3);
            Z3 = Fp.mul(b3, Z3); // step 15
            t2 = Fp.mul(a, t2);
            t3 = Fp.sub(t0, t2);
            t3 = Fp.mul(a, t3);
            t3 = Fp.add(t3, Z3);
            Z3 = Fp.add(t0, t0); // step 20
            t0 = Fp.add(Z3, t0);
            t0 = Fp.add(t0, t2);
            t0 = Fp.mul(t0, t3);
            Y3 = Fp.add(Y3, t0);
            t2 = Fp.mul(Y1, Z1); // step 25
            t2 = Fp.add(t2, t2);
            t0 = Fp.mul(t2, t3);
            X3 = Fp.sub(X3, t0);
            Z3 = Fp.mul(t2, t1);
            Z3 = Fp.add(Z3, Z3); // step 30
            Z3 = Fp.add(Z3, Z3);
            return new Point(X3, Y3, Z3);
        }
        // Renes-Costello-Batina exception-free addition formula.
        // There is 30% faster Jacobian formula, but it is not complete.
        // https://eprint.iacr.org/2015/1060, algorithm 1
        // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
        add(other) {
            assertPrjPoint(other);
            const { px: X1, py: Y1, pz: Z1 } = this;
            const { px: X2, py: Y2, pz: Z2 } = other;
            let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
            const a = CURVE.a;
            const b3 = Fp.mul(CURVE.b, _3n$1);
            let t0 = Fp.mul(X1, X2); // step 1
            let t1 = Fp.mul(Y1, Y2);
            let t2 = Fp.mul(Z1, Z2);
            let t3 = Fp.add(X1, Y1);
            let t4 = Fp.add(X2, Y2); // step 5
            t3 = Fp.mul(t3, t4);
            t4 = Fp.add(t0, t1);
            t3 = Fp.sub(t3, t4);
            t4 = Fp.add(X1, Z1);
            let t5 = Fp.add(X2, Z2); // step 10
            t4 = Fp.mul(t4, t5);
            t5 = Fp.add(t0, t2);
            t4 = Fp.sub(t4, t5);
            t5 = Fp.add(Y1, Z1);
            X3 = Fp.add(Y2, Z2); // step 15
            t5 = Fp.mul(t5, X3);
            X3 = Fp.add(t1, t2);
            t5 = Fp.sub(t5, X3);
            Z3 = Fp.mul(a, t4);
            X3 = Fp.mul(b3, t2); // step 20
            Z3 = Fp.add(X3, Z3);
            X3 = Fp.sub(t1, Z3);
            Z3 = Fp.add(t1, Z3);
            Y3 = Fp.mul(X3, Z3);
            t1 = Fp.add(t0, t0); // step 25
            t1 = Fp.add(t1, t0);
            t2 = Fp.mul(a, t2);
            t4 = Fp.mul(b3, t4);
            t1 = Fp.add(t1, t2);
            t2 = Fp.sub(t0, t2); // step 30
            t2 = Fp.mul(a, t2);
            t4 = Fp.add(t4, t2);
            t0 = Fp.mul(t1, t4);
            Y3 = Fp.add(Y3, t0);
            t0 = Fp.mul(t5, t4); // step 35
            X3 = Fp.mul(t3, X3);
            X3 = Fp.sub(X3, t0);
            t0 = Fp.mul(t3, t1);
            Z3 = Fp.mul(t5, Z3);
            Z3 = Fp.add(Z3, t0); // step 40
            return new Point(X3, Y3, Z3);
        }
        subtract(other) {
            return this.add(other.negate());
        }
        is0() {
            return this.equals(Point.ZERO);
        }
        wNAF(n) {
            return wnaf.wNAFCached(this, pointPrecomputes, n, (comp) => {
                const toInv = Fp.invertBatch(comp.map((p) => p.pz));
                return comp.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
            });
        }
        /**
         * Non-constant-time multiplication. Uses double-and-add algorithm.
         * It's faster, but should only be used when you don't care about
         * an exposed private key e.g. sig verification, which works over *public* keys.
         */
        multiplyUnsafe(n) {
            const I = Point.ZERO;
            if (n === _0n$1)
                return I;
            assertGE(n); // Will throw on 0
            if (n === _1n$2)
                return this;
            const { endo } = CURVE;
            if (!endo)
                return wnaf.unsafeLadder(this, n);
            // Apply endomorphism
            let { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
            let k1p = I;
            let k2p = I;
            let d = this;
            while (k1 > _0n$1 || k2 > _0n$1) {
                if (k1 & _1n$2)
                    k1p = k1p.add(d);
                if (k2 & _1n$2)
                    k2p = k2p.add(d);
                d = d.double();
                k1 >>= _1n$2;
                k2 >>= _1n$2;
            }
            if (k1neg)
                k1p = k1p.negate();
            if (k2neg)
                k2p = k2p.negate();
            k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
            return k1p.add(k2p);
        }
        /**
         * Constant time multiplication.
         * Uses wNAF method. Windowed method may be 10% faster,
         * but takes 2x longer to generate and consumes 2x memory.
         * Uses precomputes when available.
         * Uses endomorphism for Koblitz curves.
         * @param scalar by which the point would be multiplied
         * @returns New point
         */
        multiply(scalar) {
            assertGE(scalar);
            let n = scalar;
            let point, fake; // Fake point is used to const-time mult
            const { endo } = CURVE;
            if (endo) {
                const { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
                let { p: k1p, f: f1p } = this.wNAF(k1);
                let { p: k2p, f: f2p } = this.wNAF(k2);
                k1p = wnaf.constTimeNegate(k1neg, k1p);
                k2p = wnaf.constTimeNegate(k2neg, k2p);
                k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
                point = k1p.add(k2p);
                fake = f1p.add(f2p);
            }
            else {
                const { p, f } = this.wNAF(n);
                point = p;
                fake = f;
            }
            // Normalize `z` for both points, but return only real one
            return Point.normalizeZ([point, fake])[0];
        }
        /**
         * Efficiently calculate `aP + bQ`. Unsafe, can expose private key, if used incorrectly.
         * Not using Strauss-Shamir trick: precomputation tables are faster.
         * The trick could be useful if both P and Q are not G (not in our case).
         * @returns non-zero affine point
         */
        multiplyAndAddUnsafe(Q, a, b) {
            const G = Point.BASE; // No Strauss-Shamir trick: we have 10% faster G precomputes
            const mul = (P, a // Select faster multiply() method
            ) => (a === _0n$1 || a === _1n$2 || !P.equals(G) ? P.multiplyUnsafe(a) : P.multiply(a));
            const sum = mul(this, a).add(mul(Q, b));
            return sum.is0() ? undefined : sum;
        }
        // Converts Projective point to affine (x, y) coordinates.
        // Can accept precomputed Z^-1 - for example, from invertBatch.
        // (x, y, z) ∋ (x=x/z, y=y/z)
        toAffine(iz) {
            const { px: x, py: y, pz: z } = this;
            const is0 = this.is0();
            // If invZ was 0, we return zero point. However we still want to execute
            // all operations, so we replace invZ with a random number, 1.
            if (iz == null)
                iz = is0 ? Fp.ONE : Fp.inv(z);
            const ax = Fp.mul(x, iz);
            const ay = Fp.mul(y, iz);
            const zz = Fp.mul(z, iz);
            if (is0)
                return { x: Fp.ZERO, y: Fp.ZERO };
            if (!Fp.eql(zz, Fp.ONE))
                throw new Error('invZ was invalid');
            return { x: ax, y: ay };
        }
        isTorsionFree() {
            const { h: cofactor, isTorsionFree } = CURVE;
            if (cofactor === _1n$2)
                return true; // No subgroups, always torsion-free
            if (isTorsionFree)
                return isTorsionFree(Point, this);
            throw new Error('isTorsionFree() has not been declared for the elliptic curve');
        }
        clearCofactor() {
            const { h: cofactor, clearCofactor } = CURVE;
            if (cofactor === _1n$2)
                return this; // Fast-path
            if (clearCofactor)
                return clearCofactor(Point, this);
            return this.multiplyUnsafe(CURVE.h);
        }
        toRawBytes(isCompressed = true) {
            this.assertValidity();
            return toBytes(Point, this, isCompressed);
        }
        toHex(isCompressed = true) {
            return bytesToHex(this.toRawBytes(isCompressed));
        }
    }
    Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
    const _bits = CURVE.nBitLength;
    const wnaf = wNAF(Point, CURVE.endo ? Math.ceil(_bits / 2) : _bits);
    // Validate if generator point is on curve
    return {
        CURVE,
        ProjectivePoint: Point,
        normPrivateKeyToScalar,
        weierstrassEquation,
        isWithinCurveOrder,
    };
}
function validateOpts(curve) {
    const opts = validateBasic(curve);
    validateObject(opts, {
        hash: 'hash',
        hmac: 'function',
        randomBytes: 'function',
    }, {
        bits2int: 'function',
        bits2int_modN: 'function',
        lowS: 'boolean',
    });
    return Object.freeze({ lowS: true, ...opts });
}
function weierstrass(curveDef) {
    const CURVE = validateOpts(curveDef);
    const { Fp, n: CURVE_ORDER } = CURVE;
    const compressedLen = Fp.BYTES + 1; // e.g. 33 for 32
    const uncompressedLen = 2 * Fp.BYTES + 1; // e.g. 65 for 32
    function isValidFieldElement(num) {
        return _0n$1 < num && num < Fp.ORDER; // 0 is banned since it's not invertible FE
    }
    function modN(a) {
        return mod(a, CURVE_ORDER);
    }
    function invN(a) {
        return invert(a, CURVE_ORDER);
    }
    const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder, } = weierstrassPoints({
        ...CURVE,
        toBytes(_c, point, isCompressed) {
            const a = point.toAffine();
            const x = Fp.toBytes(a.x);
            const cat = concatBytes;
            if (isCompressed) {
                return cat(Uint8Array.from([point.hasEvenY() ? 0x02 : 0x03]), x);
            }
            else {
                return cat(Uint8Array.from([0x04]), x, Fp.toBytes(a.y));
            }
        },
        fromBytes(bytes) {
            const len = bytes.length;
            const head = bytes[0];
            const tail = bytes.subarray(1);
            // this.assertValidity() is done inside of fromHex
            if (len === compressedLen && (head === 0x02 || head === 0x03)) {
                const x = bytesToNumberBE(tail);
                if (!isValidFieldElement(x))
                    throw new Error('Point is not on curve');
                const y2 = weierstrassEquation(x); // y² = x³ + ax + b
                let y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
                const isYOdd = (y & _1n$2) === _1n$2;
                // ECDSA
                const isHeadOdd = (head & 1) === 1;
                if (isHeadOdd !== isYOdd)
                    y = Fp.neg(y);
                return { x, y };
            }
            else if (len === uncompressedLen && head === 0x04) {
                const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
                const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
                return { x, y };
            }
            else {
                throw new Error(`Point of length ${len} was invalid. Expected ${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes`);
            }
        },
    });
    const numToNByteStr = (num) => bytesToHex(numberToBytesBE(num, CURVE.nByteLength));
    function isBiggerThanHalfOrder(number) {
        const HALF = CURVE_ORDER >> _1n$2;
        return number > HALF;
    }
    function normalizeS(s) {
        return isBiggerThanHalfOrder(s) ? modN(-s) : s;
    }
    // slice bytes num
    const slcNum = (b, from, to) => bytesToNumberBE(b.slice(from, to));
    /**
     * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
     */
    class Signature {
        constructor(r, s, recovery) {
            this.r = r;
            this.s = s;
            this.recovery = recovery;
            this.assertValidity();
        }
        // pair (bytes of r, bytes of s)
        static fromCompact(hex) {
            const l = CURVE.nByteLength;
            hex = ensureBytes('compactSignature', hex, l * 2);
            return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
        }
        // DER encoded ECDSA signature
        // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
        static fromDER(hex) {
            const { r, s } = DER.toSig(ensureBytes('DER', hex));
            return new Signature(r, s);
        }
        assertValidity() {
            // can use assertGE here
            if (!isWithinCurveOrder(this.r))
                throw new Error('r must be 0 < r < CURVE.n');
            if (!isWithinCurveOrder(this.s))
                throw new Error('s must be 0 < s < CURVE.n');
        }
        addRecoveryBit(recovery) {
            return new Signature(this.r, this.s, recovery);
        }
        recoverPublicKey(msgHash) {
            const { r, s, recovery: rec } = this;
            const h = bits2int_modN(ensureBytes('msgHash', msgHash)); // Truncate hash
            if (rec == null || ![0, 1, 2, 3].includes(rec))
                throw new Error('recovery id invalid');
            const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
            if (radj >= Fp.ORDER)
                throw new Error('recovery id 2 or 3 invalid');
            const prefix = (rec & 1) === 0 ? '02' : '03';
            const R = Point.fromHex(prefix + numToNByteStr(radj));
            const ir = invN(radj); // r^-1
            const u1 = modN(-h * ir); // -hr^-1
            const u2 = modN(s * ir); // sr^-1
            const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
            if (!Q)
                throw new Error('point at infinify'); // unsafe is fine: no priv data leaked
            Q.assertValidity();
            return Q;
        }
        // Signatures should be low-s, to prevent malleability.
        hasHighS() {
            return isBiggerThanHalfOrder(this.s);
        }
        normalizeS() {
            return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
        }
        // DER-encoded
        toDERRawBytes() {
            return hexToBytes(this.toDERHex());
        }
        toDERHex() {
            return DER.hexFromSig({ r: this.r, s: this.s });
        }
        // padded bytes of r, then padded bytes of s
        toCompactRawBytes() {
            return hexToBytes(this.toCompactHex());
        }
        toCompactHex() {
            return numToNByteStr(this.r) + numToNByteStr(this.s);
        }
    }
    const utils = {
        isValidPrivateKey(privateKey) {
            try {
                normPrivateKeyToScalar(privateKey);
                return true;
            }
            catch (error) {
                return false;
            }
        },
        normPrivateKeyToScalar: normPrivateKeyToScalar,
        /**
         * Produces cryptographically secure private key from random of size
         * (groupLen + ceil(groupLen / 2)) with modulo bias being negligible.
         */
        randomPrivateKey: () => {
            const length = getMinHashLength(CURVE.n);
            return mapHashToField(CURVE.randomBytes(length), CURVE.n);
        },
        /**
         * Creates precompute table for an arbitrary EC point. Makes point "cached".
         * Allows to massively speed-up `point.multiply(scalar)`.
         * @returns cached point
         * @example
         * const fast = utils.precompute(8, ProjectivePoint.fromHex(someonesPubKey));
         * fast.multiply(privKey); // much faster ECDH now
         */
        precompute(windowSize = 8, point = Point.BASE) {
            point._setWindowSize(windowSize);
            point.multiply(BigInt(3)); // 3 is arbitrary, just need any number here
            return point;
        },
    };
    /**
     * Computes public key for a private key. Checks for validity of the private key.
     * @param privateKey private key
     * @param isCompressed whether to return compact (default), or full key
     * @returns Public key, full when isCompressed=false; short when isCompressed=true
     */
    function getPublicKey(privateKey, isCompressed = true) {
        return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
    }
    /**
     * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
     */
    function isProbPub(item) {
        const arr = isBytes(item);
        const str = typeof item === 'string';
        const len = (arr || str) && item.length;
        if (arr)
            return len === compressedLen || len === uncompressedLen;
        if (str)
            return len === 2 * compressedLen || len === 2 * uncompressedLen;
        if (item instanceof Point)
            return true;
        return false;
    }
    /**
     * ECDH (Elliptic Curve Diffie Hellman).
     * Computes shared public key from private key and public key.
     * Checks: 1) private key validity 2) shared key is on-curve.
     * Does NOT hash the result.
     * @param privateA private key
     * @param publicB different public key
     * @param isCompressed whether to return compact (default), or full key
     * @returns shared public key
     */
    function getSharedSecret(privateA, publicB, isCompressed = true) {
        if (isProbPub(privateA))
            throw new Error('first arg must be private key');
        if (!isProbPub(publicB))
            throw new Error('second arg must be public key');
        const b = Point.fromHex(publicB); // check for being on-curve
        return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
    }
    // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
    // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
    // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
    // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
    const bits2int = CURVE.bits2int ||
        function (bytes) {
            // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
            // for some cases, since bytes.length * 8 is not actual bitLength.
            const num = bytesToNumberBE(bytes); // check for == u8 done here
            const delta = bytes.length * 8 - CURVE.nBitLength; // truncate to nBitLength leftmost bits
            return delta > 0 ? num >> BigInt(delta) : num;
        };
    const bits2int_modN = CURVE.bits2int_modN ||
        function (bytes) {
            return modN(bits2int(bytes)); // can't use bytesToNumberBE here
        };
    // NOTE: pads output with zero as per spec
    const ORDER_MASK = bitMask(CURVE.nBitLength);
    /**
     * Converts to bytes. Checks if num in `[0..ORDER_MASK-1]` e.g.: `[0..2^256-1]`.
     */
    function int2octets(num) {
        if (typeof num !== 'bigint')
            throw new Error('bigint expected');
        if (!(_0n$1 <= num && num < ORDER_MASK))
            throw new Error(`bigint expected < 2^${CURVE.nBitLength}`);
        // works with order, can have different size than numToField!
        return numberToBytesBE(num, CURVE.nByteLength);
    }
    // Steps A, D of RFC6979 3.2
    // Creates RFC6979 seed; converts msg/privKey to numbers.
    // Used only in sign, not in verify.
    // NOTE: we cannot assume here that msgHash has same amount of bytes as curve order, this will be wrong at least for P521.
    // Also it can be bigger for P224 + SHA256
    function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
        if (['recovered', 'canonical'].some((k) => k in opts))
            throw new Error('sign() legacy options not supported');
        const { hash, randomBytes } = CURVE;
        let { lowS, prehash, extraEntropy: ent } = opts; // generates low-s sigs by default
        if (lowS == null)
            lowS = true; // RFC6979 3.2: we skip step A, because we already provide hash
        msgHash = ensureBytes('msgHash', msgHash);
        if (prehash)
            msgHash = ensureBytes('prehashed msgHash', hash(msgHash));
        // We can't later call bits2octets, since nested bits2int is broken for curves
        // with nBitLength % 8 !== 0. Because of that, we unwrap it here as int2octets call.
        // const bits2octets = (bits) => int2octets(bits2int_modN(bits))
        const h1int = bits2int_modN(msgHash);
        const d = normPrivateKeyToScalar(privateKey); // validate private key, convert to bigint
        const seedArgs = [int2octets(d), int2octets(h1int)];
        // extraEntropy. RFC6979 3.6: additional k' (optional).
        if (ent != null) {
            // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
            const e = ent === true ? randomBytes(Fp.BYTES) : ent; // generate random bytes OR pass as-is
            seedArgs.push(ensureBytes('extraEntropy', e)); // check for being bytes
        }
        const seed = concatBytes(...seedArgs); // Step D of RFC6979 3.2
        const m = h1int; // NOTE: no need to call bits2int second time here, it is inside truncateHash!
        // Converts signature params into point w r/s, checks result for validity.
        function k2sig(kBytes) {
            // RFC 6979 Section 3.2, step 3: k = bits2int(T)
            const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
            if (!isWithinCurveOrder(k))
                return; // Important: all mod() calls here must be done over N
            const ik = invN(k); // k^-1 mod n
            const q = Point.BASE.multiply(k).toAffine(); // q = Gk
            const r = modN(q.x); // r = q.x mod n
            if (r === _0n$1)
                return;
            // Can use scalar blinding b^-1(bm + bdr) where b ∈ [1,q−1] according to
            // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. We've decided against it:
            // a) dependency on CSPRNG b) 15% slowdown c) doesn't really help since bigints are not CT
            const s = modN(ik * modN(m + r * d)); // Not using blinding here
            if (s === _0n$1)
                return;
            let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n$2); // recovery bit (2 or 3, when q.x > n)
            let normS = s;
            if (lowS && isBiggerThanHalfOrder(s)) {
                normS = normalizeS(s); // if lowS was passed, ensure s is always
                recovery ^= 1; // // in the bottom half of N
            }
            return new Signature(r, normS, recovery); // use normS, not s
        }
        return { seed, k2sig };
    }
    const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
    const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
    /**
     * Signs message hash with a private key.
     * ```
     * sign(m, d, k) where
     *   (x, y) = G × k
     *   r = x mod n
     *   s = (m + dr)/k mod n
     * ```
     * @param msgHash NOT message. msg needs to be hashed to `msgHash`, or use `prehash`.
     * @param privKey private key
     * @param opts lowS for non-malleable sigs. extraEntropy for mixing randomness into k. prehash will hash first arg.
     * @returns signature with recovery param
     */
    function sign(msgHash, privKey, opts = defaultSigOpts) {
        const { seed, k2sig } = prepSig(msgHash, privKey, opts); // Steps A, D of RFC6979 3.2.
        const C = CURVE;
        const drbg = createHmacDrbg(C.hash.outputLen, C.nByteLength, C.hmac);
        return drbg(seed, k2sig); // Steps B, C, D, E, F, G
    }
    // Enable precomputes. Slows down first publicKey computation by 20ms.
    Point.BASE._setWindowSize(8);
    // utils.precompute(8, ProjectivePoint.BASE)
    /**
     * Verifies a signature against message hash and public key.
     * Rejects lowS signatures by default: to override,
     * specify option `{lowS: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
     *
     * ```
     * verify(r, s, h, P) where
     *   U1 = hs^-1 mod n
     *   U2 = rs^-1 mod n
     *   R = U1⋅G - U2⋅P
     *   mod(R.x, n) == r
     * ```
     */
    function verify(signature, msgHash, publicKey, opts = defaultVerOpts) {
        const sg = signature;
        msgHash = ensureBytes('msgHash', msgHash);
        publicKey = ensureBytes('publicKey', publicKey);
        if ('strict' in opts)
            throw new Error('options.strict was renamed to lowS');
        const { lowS, prehash } = opts;
        let _sig = undefined;
        let P;
        try {
            if (typeof sg === 'string' || isBytes(sg)) {
                // Signature can be represented in 2 ways: compact (2*nByteLength) & DER (variable-length).
                // Since DER can also be 2*nByteLength bytes, we check for it first.
                try {
                    _sig = Signature.fromDER(sg);
                }
                catch (derError) {
                    if (!(derError instanceof DER.Err))
                        throw derError;
                    _sig = Signature.fromCompact(sg);
                }
            }
            else if (typeof sg === 'object' && typeof sg.r === 'bigint' && typeof sg.s === 'bigint') {
                const { r, s } = sg;
                _sig = new Signature(r, s);
            }
            else {
                throw new Error('PARSE');
            }
            P = Point.fromHex(publicKey);
        }
        catch (error) {
            if (error.message === 'PARSE')
                throw new Error(`signature must be Signature instance, Uint8Array or hex string`);
            return false;
        }
        if (lowS && _sig.hasHighS())
            return false;
        if (prehash)
            msgHash = CURVE.hash(msgHash);
        const { r, s } = _sig;
        const h = bits2int_modN(msgHash); // Cannot use fields methods, since it is group element
        const is = invN(s); // s^-1
        const u1 = modN(h * is); // u1 = hs^-1 mod n
        const u2 = modN(r * is); // u2 = rs^-1 mod n
        const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine(); // R = u1⋅G + u2⋅P
        if (!R)
            return false;
        const v = modN(R.x);
        return v === r;
    }
    return {
        CURVE,
        getPublicKey,
        getSharedSecret,
        sign,
        verify,
        ProjectivePoint: Point,
        Signature,
        utils,
    };
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// connects noble-curves to noble-hashes
function getHash(hash) {
    return {
        hash,
        hmac: (key, ...msgs) => hmac(hash, key, concatBytes$1(...msgs)),
        randomBytes,
    };
}
function createCurve(curveDef, defHash) {
    const create = (hash) => weierstrass({ ...curveDef, ...getHash(hash) });
    return Object.freeze({ ...create(defHash), create });
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const secp256k1P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const _1n$1 = BigInt(1);
const _2n$1 = BigInt(2);
const divNearest = (a, b) => (a + b / _2n$1) / b;
/**
 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y) {
    const P = secp256k1P;
    // prettier-ignore
    const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
    // prettier-ignore
    const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
    const b2 = (y * y * y) % P; // x^3, 11
    const b3 = (b2 * b2 * y) % P; // x^7
    const b6 = (pow2(b3, _3n, P) * b3) % P;
    const b9 = (pow2(b6, _3n, P) * b3) % P;
    const b11 = (pow2(b9, _2n$1, P) * b2) % P;
    const b22 = (pow2(b11, _11n, P) * b11) % P;
    const b44 = (pow2(b22, _22n, P) * b22) % P;
    const b88 = (pow2(b44, _44n, P) * b44) % P;
    const b176 = (pow2(b88, _88n, P) * b88) % P;
    const b220 = (pow2(b176, _44n, P) * b44) % P;
    const b223 = (pow2(b220, _3n, P) * b3) % P;
    const t1 = (pow2(b223, _23n, P) * b22) % P;
    const t2 = (pow2(t1, _6n, P) * b2) % P;
    const root = pow2(t2, _2n$1, P);
    if (!Fp.eql(Fp.sqr(root), y))
        throw new Error('Cannot find square root');
    return root;
}
const Fp = Field$1(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
const secp256k1 = createCurve({
    a: BigInt(0), // equation params: a, b
    b: BigInt(7), // Seem to be rigid: bitcointalk.org/index.php?topic=289795.msg3183975#msg3183975
    Fp, // Field's prime: 2n**256n - 2n**32n - 2n**9n - 2n**8n - 2n**7n - 2n**6n - 2n**4n - 1n
    n: secp256k1N, // Curve order, total count of valid points in the field
    // Base point (x, y) aka generator point
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    h: BigInt(1), // Cofactor
    lowS: true, // Allow only low-S signatures by default in sign() and verify()
    /**
     * secp256k1 belongs to Koblitz curves: it has efficiently computable endomorphism.
     * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
     * For precomputed wNAF it trades off 1/2 init time & 1/3 ram for 20% perf hit.
     * Explanation: https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
     */
    endo: {
        beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
        splitScalar: (k) => {
            const n = secp256k1N;
            const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
            const b1 = -_1n$1 * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
            const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
            const b2 = a1;
            const POW_2_128 = BigInt('0x100000000000000000000000000000000'); // (2n**128n).toString(16)
            const c1 = divNearest(b2 * k, n);
            const c2 = divNearest(-b1 * k, n);
            let k1 = mod(k - c1 * a1 - c2 * a2, n);
            let k2 = mod(-c1 * b1 - c2 * b2, n);
            const k1neg = k1 > POW_2_128;
            const k2neg = k2 > POW_2_128;
            if (k1neg)
                k1 = n - k1;
            if (k2neg)
                k2 = n - k2;
            if (k1 > POW_2_128 || k2 > POW_2_128) {
                throw new Error('splitScalar: Endomorphism failed, k=' + k);
            }
            return { k1neg, k1, k2neg, k2 };
        },
    },
}, sha256);
// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
BigInt(0);

const curve = secp256k1.CURVE;
const _N$2 = curve.n;
const _P = curve.p;
const _G$2 = { x: curve.Gx, y: curve.Gy };
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _4n = BigInt(4);

var CONST = /*#__PURE__*/Object.freeze({
    __proto__: null,
    _0n: _0n,
    _1n: _1n,
    _2n: _2n,
    _3n: _3n,
    _4n: _4n,
    _G: _G$2,
    _N: _N$2,
    _P: _P
});

const ECPoint = secp256k1.ProjectivePoint;
function is_even(p) {
    const pa = new ECPoint(p.x, p.y, _1n);
    return pa.hasEvenY();
}
function is_point(point) {
    const p = point;
    return ((typeof p === 'object' && p !== null) &&
        (typeof p.x === 'bigint' && typeof p.y === 'bigint'));
}
function is_valid(point) {
    if (!is_point(point))
        return false;
    const pt = new ECPoint(point.x, point.y, _1n);
    try {
        pt.assertValidity();
        return true;
    }
    catch {
        return false;
    }
}
function assert_valid(p) {
    if (!is_valid(p)) {
        throw new Error('ECC point is invalid: ' + String(p));
    }
}
function add(a, b) {
    if (a === null)
        return b;
    if (b === null)
        return a;
    const pa = new ECPoint(a.x, a.y, _1n);
    const pb = new ECPoint(b.x, b.y, _1n);
    try {
        const pc = pa.add(pb);
        pc.assertValidity();
        return { x: pc.x, y: pc.y };
    }
    catch {
        return null;
    }
}
function sub(a, b) {
    if (a === null)
        return b;
    if (b === null)
        return a;
    const pa = new ECPoint(a.x, a.y, _1n);
    const pb = new ECPoint(b.x, b.y, _1n);
    try {
        const pc = pa.subtract(pb);
        pc.assertValidity();
        return { x: pc.x, y: pc.y };
    }
    catch {
        return null;
    }
}
function eq(a, b) {
    if (a === null && b === null) {
        return true;
    }
    if (a !== null && b !== null) {
        return (a.x === b.x && a.y === b.y);
    }
    return false;
}
function mul(a, b) {
    if (a === null)
        return null;
    try {
        const buff = Buff.bytes(b);
        const pa = new ECPoint(a.x, a.y, _1n);
        const pc = pa.multiply(buff.big);
        pc.assertValidity();
        return { x: pc.x, y: pc.y };
    }
    catch {
        return null;
    }
}
function gen(b) {
    const buff = Buff.bytes(b);
    const base = ECPoint.BASE;
    const pt = base.multiply(buff.big);
    pt.assertValidity();
    return { x: pt.x, y: pt.y };
}
function lift_x(bytes, xonly = false) {
    let key = Buff.bytes(bytes);
    if (key.length === 32) {
        key = key.prepend(0x02);
    }
    if (xonly && key[0] !== 0x02) {
        key[0] = 0x02;
    }
    const point = ECPoint.fromHex(key.hex);
    point.assertValidity();
    return { x: point.x, y: point.y };
}
function to_bytes(p) {
    const bytes = Buff.big(p.x, 32);
    const parity = is_even(p) ? 0x02 : 0x03;
    return Buff.join([parity, bytes]);
}

const fd = Field$1(_N$2, 32, true);
const mod_n = (x) => mod(x, _N$2);
const pow_n = (x, exp) => pow(x, exp, _N$2);
FpSqrt(_N$2);
FpSqrt(_P);
const in_field$2 = (x) => {
    return typeof x === 'bigint' && _0n < x && x < _N$2;
};
function mod_bytes(bytes) {
    const b = Buff.bytes(bytes).big;
    return Buff.big(mod_n(b), 32);
}

function fail(error, throws = false) {
    if (!throws)
        return false;
    throw new Error(error);
}
function size$1(input, size, throws) {
    const bytes = Buff.bytes(input);
    if (bytes.length !== size) {
        return fail(`Invalid byte size: ${bytes.hex} !== ${size}`, throws);
    }
    return true;
}
function in_field$1(x, throws) {
    if (!(typeof x === 'bigint' && _0n < x && x < _N$2)) {
        fail('x value is not in the field!', throws);
    }
    return true;
}

const NoblePoint = secp256k1.ProjectivePoint;
class Field extends Uint8Array {
    static { this.N = _N$2; }
    static add(x) {
        return x.map(e => Field.mod(e)).reduce((p, n) => p.add(n));
    }
    static mod(x) {
        return new Field(x);
    }
    static mul(x) {
        return x.map(e => Field.mod(e)).reduce((p, n) => p.mul(n));
    }
    static is_valid(value, throws) {
        const big = Buff.bytes(value, 32).big;
        return in_field$1(big, throws);
    }
    static random() {
        return Field.mod(Buff.random(32));
    }
    constructor(x) {
        const b = mod_n(normalizeField(x));
        Field.is_valid(b, true);
        super(Buff.big(b, 32), 32);
    }
    get buff() {
        return new Buff(this);
    }
    get raw() {
        return this.buff.raw;
    }
    get big() {
        return this.buff.big;
    }
    get hex() {
        return this.buff.hex;
    }
    get point() {
        return this.generate();
    }
    get hasOddY() {
        return this.point.hasOddY;
    }
    get negated() {
        return (this.hasOddY)
            ? this.negate()
            : this;
    }
    gt(value) {
        const x = new Field(value);
        return x.big > this.big;
    }
    lt(value) {
        const x = new Field(value);
        return x.big < this.big;
    }
    eq(value) {
        const x = new Field(value);
        return x.big === this.big;
    }
    ne(value) {
        const x = new Field(value);
        return x.big !== this.big;
    }
    add(value) {
        const x = Field.mod(value);
        const a = fd.add(this.big, x.big);
        return new Field(a);
    }
    sub(value) {
        const x = Field.mod(value);
        const a = fd.sub(this.big, x.big);
        return new Field(a);
    }
    mul(value) {
        const x = Field.mod(value);
        const a = fd.mul(this.big, x.big);
        return new Field(a);
    }
    pow(value) {
        const x = Field.mod(value);
        const a = fd.pow(this.big, x.big);
        return new Field(a);
    }
    div(value) {
        const x = Field.mod(value);
        const a = fd.div(this.big, x.big);
        return new Field(a);
    }
    negate() {
        return new Field(Field.N - this.big);
    }
    generate() {
        const base = secp256k1.ProjectivePoint.BASE;
        const point = base.multiply(this.big);
        return Point.import(point);
    }
}
class Point {
    static { this.P = _P; }
    static { this.G = new Point(_G$2.x, _G$2.y); }
    static { this.curve = secp256k1.CURVE; }
    static { this.base = secp256k1.ProjectivePoint.BASE; }
    static from_x(bytes, even_y = false) {
        let cp = normalizePoint(bytes);
        if (cp.length === 32) {
            cp = cp.prepend(0x02);
        }
        else if (even_y) {
            cp[0] = 0x02;
        }
        size$1(cp, 33);
        const point = NoblePoint.fromHex(cp.hex);
        point.assertValidity();
        return new Point(point.x, point.y);
    }
    static generate(value) {
        const field = Field.mod(value);
        const point = Point.base.multiply(field.big);
        return Point.import(point);
    }
    static { this.mul = Point.generate; }
    static import(point) {
        const p = (point instanceof Point)
            ? { x: point.x.big, y: point.y.big }
            : { x: point.x, y: point.y };
        return new Point(p.x, p.y);
    }
    constructor(x, y) {
        this._p = new NoblePoint(x, y, 1n);
        this.p.assertValidity();
    }
    get p() {
        return this._p;
    }
    get x() {
        return Buff.big(this.p.x, 32);
    }
    get y() {
        return Buff.big(this.p.y, 32);
    }
    get buff() {
        return Buff.raw(this.p.toRawBytes(true));
    }
    get raw() {
        return this.buff.raw;
    }
    get hex() {
        return this.buff.hex;
    }
    get hasEvenY() {
        return this.p.hasEvenY();
    }
    get hasOddY() {
        return !this.p.hasEvenY();
    }
    get negated() {
        return (this.hasOddY)
            ? this.negate()
            : this;
    }
    eq(value) {
        const p = (value instanceof Point) ? value : Point.from_x(value);
        return this.x.big === p.x.big && this.y.big === p.y.big;
    }
    add(x) {
        return (x instanceof Point)
            ? Point.import(this.p.add(x.p))
            : Point.import(this.p.add(Point.generate(x).p));
    }
    sub(x) {
        return (x instanceof Point)
            ? Point.import(this.p.subtract(x.p))
            : Point.import(this.p.subtract(Point.generate(x).p));
    }
    mul(value) {
        return (value instanceof Point)
            ? Point.import(this.p.multiply(value.x.big))
            : Point.import(this.p.multiply(Field.mod(value).big));
    }
    negate() {
        return Point.import(this.p.negate());
    }
}
function normalizeField(value) {
    if (value instanceof Field) {
        return value.big;
    }
    if (value instanceof Point) {
        return value.x.big;
    }
    if (value instanceof Uint8Array) {
        return Buff.raw(value).big;
    }
    if (typeof value === 'string') {
        return Buff.hex(value).big;
    }
    if (typeof value === 'number') {
        return Buff.num(value).big;
    }
    if (typeof value === 'bigint') {
        return BigInt(value);
    }
    throw TypeError('Invalid input type:' + typeof value);
}
function normalizePoint(value) {
    if (value instanceof Field) {
        return value.point.buff;
    }
    if (value instanceof Point) {
        return value.buff;
    }
    if (value instanceof Uint8Array ||
        typeof value === 'string') {
        return Buff.bytes(value);
    }
    if (typeof value === 'number' ||
        typeof value === 'bigint') {
        return Buff.bytes(value, 32);
    }
    throw new TypeError(`Unknown type: ${typeof value}`);
}

function random(size) {
    return Buff.random(size);
}

function gen_seckey$1(even_y) {
    return get_seckey$1(random(32), even_y);
}
function get_seckey$1(secret, even_y = false) {
    const sec = Field.mod(secret);
    return (even_y) ? sec.negated.buff : sec.buff;
}
function get_pubkey$1(seckey, x_only = false) {
    const p = Field.mod(seckey).point;
    return (x_only) ? p.x : p.buff;
}
function get_keypair$1(secret, x_only, even_y) {
    const sec = get_seckey$1(secret, even_y);
    const pub = get_pubkey$1(sec, x_only);
    return [sec, pub];
}
function gen_keypair$1(x_only, even_y) {
    const sec = random(32);
    return get_keypair$1(sec, x_only, even_y);
}
function convert_32b(pubkey) {
    const key = Buff.bytes(pubkey);
    if (key.length === 32)
        return key;
    if (key.length === 33)
        return key.slice(1, 33);
    throw new TypeError(`Invalid key length: ${key.length}`);
}

function hash_str(str) {
    return Buff.str(str).digest;
}
function has_key(key, keys) {
    const str = keys.map(e => buffer(e).hex);
    return str.includes(buffer(key).hex);
}
function sort_keys(keys) {
    const arr = keys.map(e => buffer(e).hex);
    arr.sort();
    return arr.map(e => Buff.hex(e));
}
function parse_points(points, xonly) {
    let keys = points.map(P => to_bytes(P));
    if (xonly)
        keys = keys.map(e => convert_32b(e));
    return Buff.join(keys);
}
function parse_psig(psig) {
    const keys = Buff.parse(psig, 32, 128);
    return {
        sig: keys[0],
        pubkey: keys[1],
        nonces: keys.slice(2)
    };
}
function hexify$1(item) {
    if (Array.isArray(item)) {
        return item.map(e => hexify$1(e));
    }
    if (item instanceof Buff) {
        return item.hex;
    }
    return item;
}
function has_items(arr) {
    return (Array.isArray(arr) && arr.length > 0);
}

var util = /*#__PURE__*/Object.freeze({
    __proto__: null,
    has_items: has_items,
    has_key: has_key,
    hash_str: hash_str,
    hexify: hexify$1,
    parse_points: parse_points,
    parse_psig: parse_psig,
    sort_keys: sort_keys
});

class KeyOperationError extends Error {
    constructor(report) {
        const { reason = 'Key operation failed!' } = report;
        super(reason);
        this.name = 'KeyOperationError';
        this.pubkey = report.pubkey;
        this.type = report.type;
        this.data = report.data ?? [];
    }
}

function ok(value, message) {
    if (value === false) {
        throw new Error(message ?? 'Assertion failed!');
    }
}
function exists(value, msg) {
    if (value === undefined || value === null) {
        throw new Error(msg ?? 'Value is null or undefined!');
    }
}
function size(input, size) {
    const bytes = buffer(input);
    if (bytes.length !== size) {
        throw new TypeError(`Invalid byte size: ${bytes.hex} !== ${size}`);
    }
}
function nonce_total_size(nonce, size) {
    const bytes = buffer(nonce);
    if (bytes.length !== size) {
        throw new KeyOperationError({
            data: [bytes.hex],
            type: 'nonce_total_size',
            reason: `Nonce size mismatch: ${bytes.length} !== ${size}`
        });
    }
}
function nonce_key_size(nonce) {
    const bytes = buffer(nonce);
    if (bytes.length % 32 !== 0 && bytes.length % 33 !== 0) {
        throw new KeyOperationError({
            data: [bytes.hex],
            type: 'nonce_key_size',
            reason: `Invalid key size: ${bytes.length}`
        });
    }
}
function valid_nonce_group(pub_nonces) {
    const nonces = pub_nonces.map(e => buffer(e));
    nonces.forEach((nonce, idx) => {
        nonce_key_size(nonce);
        if (idx > 0) {
            const prev = nonces[idx - 1];
            nonce_total_size(nonce, prev.length);
        }
    });
}
function in_field(bytes) {
    const big = buffer(bytes).big;
    if (!in_field$2(big)) {
        throw new KeyOperationError({
            type: 'assert_in_field',
            reason: 'Key out of range of N.',
            data: [buffer(big, 32).hex]
        });
    }
}
function valid_point(point) {
    assert_valid(point);
}

var assert = /*#__PURE__*/Object.freeze({
    __proto__: null,
    exists: exists,
    in_field: in_field,
    nonce_key_size: nonce_key_size,
    nonce_total_size: nonce_total_size,
    ok: ok,
    size: size,
    valid_nonce_group: valid_nonce_group,
    valid_point: valid_point
});

function compute_group_hash(pubkeys) {
    const group_p = sort_keys(pubkeys);
    return hash340('KeyAgg list', ...group_p);
}
function compute_coeff_hash(group_hash, coeff_key) {
    return hash340('KeyAgg coefficient', group_hash, coeff_key);
}
function combine_pubkeys(pubkeys) {
    const keys = sort_keys(pubkeys);
    const hash = compute_group_hash(keys);
    const coeffs = [];
    let group_P = null;
    for (const key of keys) {
        const c = compute_coeff_hash(hash, key);
        coeffs.push([key.hex, c]);
        const P = lift_x(key);
        if (P === null) {
            throw new KeyOperationError({
                pubkey: key.hex,
                type: 'lift_x',
                reason: 'Point lifted from key is null!'
            });
        }
        const mP = mul(P, c.big);
        group_P = add(group_P, mP);
        if (group_P === null) {
            throw new KeyOperationError({
                pubkey: key.hex,
                type: 'point_add',
                reason: 'Point nullifies the group!'
            });
        }
    }
    valid_point(group_P);
    return [group_P, coeffs];
}
function get_key_coeff(pubkey, coeffs) {
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

const { _N: _N$1, _G: _G$1 } = CONST;
function get_challenge(group_rx, group_pub, message) {
    const grx = convert_32b(group_rx);
    const gpx = convert_32b(group_pub);
    const preimg = Buff.join([grx, gpx, message]);
    return hash340('BIP0340/challenge', preimg);
}
function get_pt_state(int_pt, adaptors = [], tweaks = []) {
    const pos = BigInt(1);
    const neg = _N$1 - pos;
    const twk = tweaks.map(e => mod_bytes(e).big);
    const pts = [
        ...twk.map(e => mul(_G$1, e)),
        ...adaptors.map(e => lift_x(e, true))
    ];
    let point = int_pt, parity = pos, state = pos, tweak = 0n;
    for (let i = 0; i < pts.length; i++) {
        const p = pts[i];
        parity = (!is_even(point)) ? neg : pos;
        point = add(mul(point, parity), p);
        assert_valid(point);
        state = mod_n(parity * state);
        if (twk.at(i) !== undefined) {
            tweak = mod_n(twk[i] + parity * tweak);
        }
    }
    parity = (!is_even(point)) ? neg : pos;
    return {
        point,
        parity,
        state,
        tweak
    };
}
function compute_R(group_nonce, nonce_coeff) {
    const nonces = Buff.parse(group_nonce, 33, 66);
    const ncoeff = Buff.bytes(nonce_coeff);
    let R = null;
    for (let j = 0; j < nonces.length; j++) {
        const c = mod_n(ncoeff.big ** BigInt(j));
        const NC = lift_x(nonces[j]);
        assert_valid(NC);
        const Rj = mul(NC, c);
        R = add(R, Rj);
    }
    assert_valid(R);
    return R;
}
function compute_s(secret_key, key_coeff, challenge, sec_nonces, nonce_coeff) {
    let s = mod_n(challenge * key_coeff * secret_key);
    for (let j = 0; j < sec_nonces.length; j++) {
        const r = sec_nonces[j];
        const c = pow_n(nonce_coeff, BigInt(j));
        s += (r * c);
        s = mod_n(s);
    }
    return Buff.big(s, 32);
}
function compute_ps(secret_key, key_coeff, challenge) {
    const ps = mod_n(challenge * key_coeff * secret_key);
    return Buff.big(ps, 32);
}
function apply_sn(ps, sns, ncf) {
    for (let j = 0; j < sns.length; j++) {
        const r = sns[j];
        const c = pow_n(ncf, BigInt(j));
        ps += (r * c);
        ps = mod_n(ps);
    }
    return Buff.big(ps, 32);
}

function get_nonce_coeff(group_nonce, group_key, message) {
    const gpx = convert_32b(group_key);
    const preimg = Buff.bytes([group_nonce, gpx, message]);
    const bytes = hash340('MuSig/noncecoef', preimg);
    const coeff = mod_n(bytes.big);
    return Buff.bytes(coeff, 32);
}
function combine_nonces(pub_nonces) {
    valid_nonce_group(pub_nonces);
    const rounds = 2;
    const members = pub_nonces.map(e => Buff.parse(e, 32, 64));
    const points = [];
    for (let j = 0; j < rounds; j++) {
        let group_R = null;
        for (const nonces of members) {
            const nonce = nonces[j];
            const n_pt = lift_x(nonce);
            group_R = add(group_R, n_pt);
        }
        if (group_R === null) {
            group_R = _G$2;
        }
        points.push(group_R);
    }
    return parse_points(points);
}

function get_key_ctx(pubkeys, tweaks) {
    pubkeys.forEach(e => { size(e, 32); });
    const [point, key_coeffs] = combine_pubkeys(pubkeys);
    const int_state = get_pt_state(point);
    const int_pubkey = to_bytes(point).slice(1);
    const group_state = get_pt_state(point, [], tweaks);
    const group_pubkey = to_bytes(group_state.point).slice(1);
    return {
        int_pubkey,
        int_state,
        group_state,
        group_pubkey,
        key_coeffs,
        pub_keys: pubkeys.map(e => Buff.bytes(e))
    };
}
function get_nonce_ctx(pub_nonces, grp_pubkey, message, adaptors) {
    size(grp_pubkey, 32);
    pub_nonces.forEach(e => { size(e, 64); });
    const group_nonce = combine_nonces(pub_nonces);
    const nonce_coeff = get_nonce_coeff(group_nonce, grp_pubkey, message);
    const R_point = compute_R(group_nonce, nonce_coeff);
    const int_R = get_pt_state(R_point);
    const int_rx = to_bytes(int_R.point).slice(1);
    const nonce_state = get_pt_state(R_point, adaptors);
    const group_rx = to_bytes(nonce_state.point).slice(1);
    const challenge = get_challenge(group_rx, grp_pubkey, message);
    return {
        group_nonce,
        nonce_coeff,
        int_rx,
        int_R,
        nonce_state,
        group_rx,
        challenge,
        message: Buff.bytes(message),
        pub_nonces: pub_nonces.map(e => Buff.bytes(e))
    };
}
function get_ctx(pubkeys, nonces, message, options) {
    const { nonce_tweaks = [], pubkey_tweaks = [] } = options ?? {};
    const key_ctx = get_key_ctx(pubkeys, pubkey_tweaks);
    const nonce_ctx = get_nonce_ctx(nonces, key_ctx.group_pubkey, message, nonce_tweaks);
    return create_ctx(key_ctx, nonce_ctx, options);
}
function create_ctx(key_ctx, non_ctx, options) {
    const config = musig_config(options);
    return { ...key_ctx, ...non_ctx, config };
}
function hexify(ctx) {
    const obj = {};
    for (const [key, val] of Object.entries(ctx)) {
        if (Array.isArray(val)) {
            obj[key] = val.map(e => {
                if (Array.isArray(e)) {
                    return e.map(x => (x.hex !== undefined) ? x.hex : x);
                }
                else if (e instanceof Buff) {
                    return e.hex;
                }
                else {
                    return e;
                }
            });
        }
        else if (val.hex !== undefined) {
            obj[key] = val.hex;
        }
    }
    return obj;
}

const get_seckey = (seckey) => {
    return get_seckey$1(seckey, true);
};
const get_pubkey = (seckey) => {
    return get_pubkey$1(seckey, true);
};
const get_keypair = (secret) => {
    return get_keypair$1(secret, true, true);
};
const gen_seckey = () => {
    return gen_seckey$1(true);
};
const gen_keypair = () => {
    return gen_keypair$1(true, true);
};
function get_sec_nonce(secret) {
    const nonces = Buff
        .parse(secret, 32, 64)
        .map(e => get_seckey(e));
    return Buff.join(nonces);
}
function get_pub_nonce(sec_nonce) {
    const nonces = Buff
        .parse(sec_nonce, 32, 64)
        .map(e => get_pubkey(e));
    return Buff.join(nonces);
}
function get_nonce_pair(secret) {
    const sec_nonce = get_sec_nonce(secret);
    const pub_nonce = get_pub_nonce(sec_nonce);
    return [sec_nonce, pub_nonce];
}
function gen_nonce_pair() {
    const seed = Buff.random(64);
    return get_nonce_pair(seed);
}

var keys = /*#__PURE__*/Object.freeze({
    __proto__: null,
    gen_keypair: gen_keypair,
    gen_nonce_pair: gen_nonce_pair,
    gen_seckey: gen_seckey,
    get_keypair: get_keypair,
    get_nonce_pair: get_nonce_pair,
    get_pub_nonce: get_pub_nonce,
    get_pubkey: get_pubkey,
    get_sec_nonce: get_sec_nonce,
    get_seckey: get_seckey
});

function combine_s(signatures) {
    let s = _0n;
    for (const psig of signatures) {
        const s_i = Buff.bytes(psig).big;
        in_field(s_i);
        s = mod_n(s + s_i);
    }
    return s;
}
function combine_psigs(context, signatures) {
    const { challenge, group_state, group_rx } = context;
    const { parity, tweak } = group_state;
    const sigs = signatures
        .map(e => parse_psig(e))
        .map(e => e.sig);
    const s = combine_s(sigs);
    const e = challenge.big;
    const a = e * parity * tweak;
    const sig = mod_n(s + a);
    return Buff.join([
        convert_32b(group_rx),
        Buff.big(sig, 32)
    ]);
}
function add_sig_adapters(context, signature, adapters) {
    const { int_R } = context;
    const s = Buff.bytes(signature).subarray(32, 64).big;
    const T = get_pt_state(int_R.point, [], adapters);
    const a = T.parity * T.tweak;
    const sig = mod_n(s + a);
    return Buff.join([
        Buff.bytes(signature).subarray(0, 32),
        Buff.big(sig, 32)
    ]);
}
function musign(context, secret, snonce) {
    const { challenge, key_coeffs, nonce_coeff } = context;
    const { group_state, nonce_state } = context;
    const [sec, pub] = get_keypair(secret);
    const [snp, pn] = get_nonce_pair(snonce);
    const Q = group_state;
    const R = nonce_state;
    const p_v = get_key_coeff(pub, key_coeffs).big;
    const sk = mod_n(Q.parity * Q.state * sec.big);
    const cha = Buff.bytes(challenge).big;
    const n_v = Buff.bytes(nonce_coeff).big;
    const sn = Buff.parse(snp, 32, 64).map(e => {
        return R.parity * R.state * e.big;
    });
    const psig = compute_s(sk, p_v, cha, sn, n_v);
    return Buff.join([psig, pub, pn]);
}
function cosign_key(context, secret) {
    const { challenge, group_state, key_coeffs } = context;
    const [sec, pub] = get_keypair(secret);
    const Q = group_state;
    const p_v = get_key_coeff(pub, key_coeffs).big;
    const sk = mod_n(Q.parity * Q.state * sec.big);
    const cha = Buff.bytes(challenge).big;
    const csig = compute_ps(sk, p_v, cha);
    return Buff.join([csig, pub]);
}
function cosign_nonce(context, cosig, snonce) {
    const buffer = Buff.bytes(cosig);
    size(buffer, 64);
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

const { _G, _N } = CONST;
function verify_psig(context, psig) {
    const { challenge, key_coeffs, nonce_coeff } = context;
    const { group_state, nonce_state } = context;
    const { sig, pubkey, nonces } = parse_psig(psig);
    in_field(sig);
    const Q = group_state;
    const R = nonce_state;
    const kvec = get_key_coeff(pubkey, key_coeffs);
    const P = lift_x(pubkey);
    const g_P = (Q.parity * Q.state) % _N;
    const coef = (challenge.big * kvec.big * g_P) % _N;
    const R_s1 = lift_x(nonces[0]);
    const R_s2 = lift_x(nonces[1]);
    const R_sP = add(R_s1, mul(R_s2, nonce_coeff));
    const R_s = mul(R_sP, R.parity);
    valid_point(R_s);
    const S1 = gen(sig);
    const S2 = add(R_s, mul(P, coef));
    valid_point(S1);
    valid_point(S2);
    return to_bytes(S1).hex === to_bytes(S2).hex;
}
function verify_musig(context, signature) {
    const { challenge, group_pubkey } = context;
    const sig = (Array.isArray(signature))
        ? combine_psigs(context, signature)
        : signature;
    const [rx, s] = Buff.parse(sig, 32, 64);
    const S = mul(_G, s.big);
    const R = lift_x(rx, true);
    const P = lift_x(group_pubkey, true);
    const c = Buff.bytes(challenge).big;
    const SP = add(R, mul(P, c));
    valid_point(S);
    return eq(S, SP);
}
function verify_adapter_sig(context, signature, adapter_pks) {
    const { challenge, group_pubkey, group_rx, int_rx } = context;
    const b = Buff.bytes(signature);
    const r = b.subarray(0, 32);
    const s = b.subarray(32, 64);
    ok(group_rx.hex === r.hex, 'signature rx does not match signing context');
    const R = lift_x(int_rx, true);
    const A = get_pt_state(R, adapter_pks);
    const ax = to_bytes(A.point).slice(1);
    ok(group_rx.hex === ax.hex, 'internal rx does not match signing context when tweaked');
    const c = challenge.big;
    const P = lift_x(group_pubkey);
    const S = gen(s);
    const eP = mul(P, c);
    const rS = sub(S, eP);
    exists(rS);
    return rS.x === R.x;
}

export { CONST$1 as CONST, MUSIG_DEFAULTS, add_sig_adapters, assert, combine_psigs, cosign_key, cosign_nonce, create_ctx, get_ctx, get_key_ctx, get_nonce_ctx, hexify, keys, musig_config, musign, util, verify_adapter_sig, verify_musig, verify_psig };
//# sourceMappingURL=module.mjs.map

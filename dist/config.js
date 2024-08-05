export const MUSIG_DEFAULTS = {
    nonce_tweaks: [],
    pubkey_tweaks: []
};
export const CONST = {
    SAFE_MIN_VALUE: 0xffn ** 16n
};
export function musig_config(options = {}) {
    return { ...MUSIG_DEFAULTS, ...options };
}
//# sourceMappingURL=config.js.map
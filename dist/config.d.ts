import { Bytes } from '@cmdcode/buff';
export type MusigOptions = Partial<MusigConfig>;
export interface MusigConfig {
    nonce_tweaks: Bytes[];
    pubkey_tweaks: Bytes[];
}
export declare const MUSIG_DEFAULTS: {
    nonce_tweaks: never[];
    pubkey_tweaks: never[];
};
export declare const CONST: {
    SAFE_MIN_VALUE: bigint;
};
export declare function musig_config(options?: MusigOptions): MusigConfig;
//# sourceMappingURL=config.d.ts.map
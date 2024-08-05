import { Buff, Bytes } from '@cmdcode/buff';
export declare const get_seckey: (seckey: Bytes) => Buff;
export declare const get_pubkey: (seckey: Bytes) => Buff;
export declare const get_keypair: (secret: Bytes) => Buff[];
export declare const gen_seckey: () => Buff;
export declare const gen_keypair: () => Buff[];
export declare function get_sec_nonce(secret: Bytes): Buff;
export declare function get_pub_nonce(sec_nonce: Bytes): Buff;
export declare function get_nonce_pair(secret: Bytes): Buff[];
export declare function gen_nonce_pair(): Buff[];
//# sourceMappingURL=keys.d.ts.map
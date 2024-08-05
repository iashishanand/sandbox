import { Bytes } from '@cmdcode/buff';
import { MusigOptions } from './config.js';
import { KeyContext, NonceContext, MusigContext } from './types.js';
export declare function get_key_ctx(pubkeys: Bytes[], tweaks?: Bytes[]): KeyContext;
export declare function get_nonce_ctx(pub_nonces: Bytes[], grp_pubkey: Bytes, message: Bytes, adaptors?: Bytes[]): NonceContext;
export declare function get_ctx(pubkeys: Bytes[], nonces: Bytes[], message: Bytes, options?: MusigOptions): MusigContext;
export declare function create_ctx(key_ctx: KeyContext, non_ctx: NonceContext, options?: MusigOptions): MusigContext;
export declare function hexify(ctx: MusigContext): MusigContext;
//# sourceMappingURL=context.d.ts.map
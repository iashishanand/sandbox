import { Buff, Bytes } from '@cmdcode/buff';
import { MusigContext } from './types.js';
export declare function combine_psigs(context: MusigContext, signatures: Bytes[]): Buff;
export declare function add_sig_adapters(context: MusigContext, signature: Bytes, adapters: Bytes[]): Buff;
export declare function musign(context: MusigContext, secret: Bytes, snonce: Bytes): Buff;
export declare function cosign_key(context: MusigContext, secret: Bytes): Buff;
export declare function cosign_nonce(context: MusigContext, cosig: Bytes, snonce: Bytes): Buff;
//# sourceMappingURL=sign.d.ts.map
import { Bytes } from '@cmdcode/buff';
import { MusigContext } from './types.js';
export declare function verify_psig(context: MusigContext, psig: Bytes): boolean;
export declare function verify_musig(context: MusigContext, signature: Bytes | Bytes[]): boolean;
export declare function verify_adapter_sig(context: MusigContext, signature: Bytes, adapter_pks: Bytes[]): boolean;
//# sourceMappingURL=verify.d.ts.map
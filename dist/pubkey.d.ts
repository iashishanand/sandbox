import { Buff, Bytes } from '@cmdcode/buff';
import { PointData } from '@cmdcode/crypto-tools';
import { KeyCoeff } from './types.js';
export declare function compute_key_coeff(pubkeys: Bytes[], self_key: Bytes): Buff;
export declare function combine_pubkeys(pubkeys: Bytes[]): [point: PointData, coeffs: KeyCoeff[]];
export declare function get_key_coeff(pubkey: Bytes, coeffs: KeyCoeff[]): Buff;
//# sourceMappingURL=pubkey.d.ts.map
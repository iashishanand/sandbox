import { Buff, Bytes } from '@cmdcode/buff';
import { PointState } from './types.js';
import { PointData } from '@cmdcode/crypto-tools';
export declare function get_challenge(group_rx: Bytes, group_pub: Bytes, message: Bytes): Buff;
export declare function get_pt_state(int_pt: PointData, adaptors?: Bytes[], tweaks?: Bytes[]): PointState;
export declare function compute_R(group_nonce: Bytes, nonce_coeff: Bytes): PointData;
export declare function compute_s(secret_key: bigint, key_coeff: bigint, challenge: bigint, sec_nonces: bigint[], nonce_coeff: bigint): Buff;
export declare function compute_ps(secret_key: bigint, key_coeff: bigint, challenge: bigint): Buff;
export declare function apply_sn(ps: bigint, sns: bigint[], ncf: bigint): Buff;
//# sourceMappingURL=compute.d.ts.map
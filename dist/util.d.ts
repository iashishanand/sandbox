import { Buff, Bytes } from '@cmdcode/buff';
import { PointData } from '@cmdcode/crypto-tools';
import { PartialSig } from './types.js';
export declare function hash_str(str: string): Buff;
export declare function has_key(key: Bytes, keys: Bytes[]): boolean;
export declare function sort_keys(keys: Bytes[]): Buff[];
export declare function parse_points(points: PointData[], xonly?: boolean): Buff;
export declare function parse_psig(psig: Bytes): PartialSig;
export declare function hexify(item: any): Buff | Buff[] | any;
export declare function has_items<T>(arr: Array<T>): boolean;
//# sourceMappingURL=util.d.ts.map
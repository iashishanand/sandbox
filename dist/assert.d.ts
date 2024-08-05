import { Bytes } from '@cmdcode/buff';
import { PointData } from '@cmdcode/crypto-tools';
export declare function ok(value: unknown, message?: string): asserts value;
export declare function exists<T>(value?: T | null, msg?: string): asserts value is NonNullable<T>;
export declare function size(input: Bytes, size: number): void;
export declare function nonce_total_size(nonce: Bytes, size: number): void;
export declare function nonce_key_size(nonce: Bytes): void;
export declare function valid_nonce_group(pub_nonces: Bytes[]): void;
export declare function in_field(bytes: Bytes): void;
export declare function valid_point(point: PointData | null): asserts point is PointData;
//# sourceMappingURL=assert.d.ts.map
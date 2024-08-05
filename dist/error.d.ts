interface ErrorReport {
    type?: string;
    data?: string[];
    pubkey?: string;
    reason: string;
}
export declare class KeyOperationError extends Error {
    type?: string;
    data?: string[];
    pubkey?: string;
    constructor(report: ErrorReport);
}
export {};
//# sourceMappingURL=error.d.ts.map
export class KeyOperationError extends Error {
    constructor(report) {
        const { reason = 'Key operation failed!' } = report;
        super(reason);
        this.name = 'KeyOperationError';
        this.pubkey = report.pubkey;
        this.type = report.type;
        this.data = report.data ?? [];
    }
}
//# sourceMappingURL=error.js.map
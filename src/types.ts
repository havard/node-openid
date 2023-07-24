// export interface ExpressRequest {
//     method: string;
//     url: string;
//     get(header: string): string | number | string[] | undefined;
//     on(event: string, cb: (data: any) => void): void;
// }

// export const isRequest = (b: any): b is ExpressRequest => {
//     return (b as Request).method !== undefined &&
//         (b as Request).url !== undefined &&
//         typeof (b as Request).getHeader === 'function'
//         && typeof (b as Request).on === 'function';
// }

export interface ErrorMessage {
    message: string;
}

export type AssertionResponse = ({
    authenticated: false;
} | {
    authenticated: true;
    claimedIdentifier: string | null;
}) & Record<string, string | string[] | boolean | null>

export type Realm = string | null;

export interface Provider {
    endpoint: string;
    claimedIdentifier?: string;
    version: string;
    localIdentifier: string | null;
}

export interface Association {
    provider: Provider,
    type: string,
    secret: string
}

export type RequestOrUrl = /*ExpressRequest*/ | URL | string;

export interface ValidityChecks {
    /**
     * Checks if ns is in this array
     */
    ns: string[],
    /**
     * Checks if claimed_id starts with any of these
     */
    claimed_id: string[],
    /**
     * Checks if identity starts with any of these
     */
    identity: string[],
    /**
     * Checks if op_endpoint is in this array
     */
    op_endpoint: string[]
};
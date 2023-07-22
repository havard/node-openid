import { AssertionResponse } from "openid";

export default abstract class Extension {
    requestParams: Record<string, string> = {};

    getHeader(header: string) {
        return this.requestParams[header];
    }

    abstract fillResult(params: URLSearchParams, result: AssertionResponse): void;
}
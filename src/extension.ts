import { AssertionResponse } from "./types";

export default abstract class Extension {
    requestParams: Record<string, string> = {};

    getHeader(header: string) {
        return this.requestParams[header];
    }

    static getExtensionAlias(params: URLSearchParams, ns: string) {
        for (let key of params.keys()) {
            if (params.get(key) == ns) {
                return key.replace("openid.ns.", "");
            }
        }
      }

    abstract fillResult(params: URLSearchParams, result: Record<string, string | string[] | boolean | null>): void;
}
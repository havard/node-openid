import Extension from "../extension";

export interface OAuthHybridOptions {
    consumerKey: string;
    scope: string;
}

export default class OAuthHybrid extends Extension {
    constructor(options: OAuthHybridOptions) {
        super();

        this.requestParams = {
            'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0',
            'openid.oauth.consumer': options['consumerKey'],
            'openid.oauth.scope': options['scope']
        };
    }

    fillResult(params: URLSearchParams, result: Record<string, string | boolean | string[] | null>): void {
        let extension = Extension.getExtensionAlias(params, 'http://specs.openid.net/extensions/oauth/1.0') || 'oauth',
            token_attr = params.get('openid.' + extension + '.request_token');

        if (token_attr !== null) {
            result['request_token'] = token_attr;
        }
    }
}
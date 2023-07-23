import Extension from "../extension";

export default class PAPE extends Extension {
    /* Just the keys that aren't open to customisation */
    readonly pape_request_keys = ['max_auth_age', 'preferred_auth_policies', 'preferred_auth_level_types'];
    readonly pape_response_keys = ['auth_policies', 'auth_time'];

    /* Some short-hand mappings for auth_policies */
    readonly papePolicyNameMap = {
        'phishing-resistant': 'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant',
        'multi-factor': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
        'multi-factor-physical': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical',
        'none': 'http://schemas.openid.net/pape/policies/2007/06/none'
    };

    /** 
     * Provider Authentication Policy Extension (PAPE)  
     * http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
     * 
     * Note that this extension does not validate that the provider is obeying the
     * authentication request, it only allows the request to be made.
     *
     * TODO: verify requested 'max_auth_age' against response 'auth_time'  
     * TODO: verify requested 'auth_level.ns.<cust>' (etc) against response 'auth_level.ns.<cust>'  
     * TODO: verify requested 'preferred_auth_policies' against response 'auth_policies'  
     *
     */
    constructor(options: Record<string, string>) {
        super();

        this.requestParams = {
            'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0'
        };

        for (let k in options) {
            if (k === 'preferred_auth_policies') {
                this.requestParams['openid.pape.' + k] = this.#getLongPolicyName(options[k]);
            } else {
                this.requestParams['openid.pape.' + k] = options[k];
            }
        }
    }

    fillResult(params: URLSearchParams, result: Record<string, string | boolean | string[] | null>): void {
        let extension = Extension.getExtensionAlias(params, 'http://specs.openid.net/extensions/pape/1.0') || 'pape';
        let paramString = 'openid.' + extension + '.';
        let thisParam;

        for (let p of params.keys()) {
            let v = params.get(p);
            if (v !== null) {
                if (p.startsWith(paramString)) {
                    thisParam = p.replace(paramString, '');
                    if (thisParam === 'auth_policies') {
                        result[thisParam] = this.#getShortPolicyName(v);
                    } else {
                        result[thisParam] = v;
                    }
                }
            }
        }
    }

    /**
     * you can express multiple pape 'preferred_auth_policies', so replace each
     * with the full policy URI as per papePolicyNameMapping. 
     */
    #getLongPolicyName(policyNames: string) {
        let policies = policyNames.split(' ');

        for (let i = 0; i < policies.length; i++) {
            if (policies[i] in this.papePolicyNameMap) {
                policies[i] = this.papePolicyNameMap[policies[i] as keyof typeof this.papePolicyNameMap];
            }
        }

        return policies.join(' ');
    }

    #getShortPolicyName(policyNames: string) {
        let policies = policyNames.split(' ');

        for (let i = 0; i < policies.length; i++) {
            for (let shortName in this.papePolicyNameMap) {
                if (this.papePolicyNameMap[shortName as keyof typeof this.papePolicyNameMap] === policies[i]) {
                    policies[i] = shortName;
                }
            }
        }

        return policies.join(' ');
    }
}
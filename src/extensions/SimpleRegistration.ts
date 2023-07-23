import Extension from "../extension";

export interface SimpleRegistrationOptions {
    'policy_url'?: string,
    'nickname'?: 'required' | 'optional',
    'email'?: 'required' | 'optional',
    'fullname'?: 'required' | 'optional',
    'dob'?: 'required' | 'optional',
    'gender'?: 'required' | 'optional',
    'postcode'?: 'required' | 'optional',
    'country'?: 'required' | 'optional',
    'language'?: 'required' | 'optional',
    'timezone'?: 'required' | 'optional'
};

export default class SimpleRegistration extends Extension {
    readonly sreg_keys = ['nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country', 'language', 'timezone'];

    /**
     * Simple Registration Extension  
     * http://openid.net/specs/openid-simple-registration-extension-1_1-01.html
     */
    constructor(options: SimpleRegistrationOptions) {
        super();

        this.requestParams = { 'openid.ns.sreg': 'http://openid.net/extensions/sreg/1.1' };
        if (options.policy_url) {
            this.requestParams['openid.sreg.policy_url'] = options.policy_url;
        }

        let required = [];
        let optional = [];
        for (let i = 0; i < this.sreg_keys.length; i++) {
            let key = this.sreg_keys[i] as keyof SimpleRegistrationOptions;
            if (options[key]) {
                if (options[key] == 'required') {
                    required.push(key);
                } else {
                    optional.push(key);
                }
            }

            if (required.length) {
                this.requestParams['openid.sreg.required'] = required.join(',');
            }

            if (optional.length) {
                this.requestParams['openid.sreg.optional'] = optional.join(',');
            }
        }
    }

    fillResult(params: URLSearchParams, result: Record<string, string | string[] | boolean | null>): void {
        let extension = Extension.getExtensionAlias(params, 'http://openid.net/extensions/sreg/1.1') || 'sreg';
        for (let key of this.sreg_keys) {
            const value = params.get('openid.' + extension + '.' + key);
            if (value) {
                result[key] = value;
            }
        }
    }
}
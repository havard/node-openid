import Extension from "../extension";
import { AX_MAX_VALUES_COUNT } from "../lib/constants";

export default class AttributeExchange extends Extension {
    attributeMapping: Record<string, string> = {
        'http://axschema.org/contact/country/home': 'country',
        'http://axschema.org/contact/email': 'email',
        'http://axschema.org/namePerson/first': 'firstname',
        'http://axschema.org/pref/language': 'language',
        'http://axschema.org/namePerson/last': 'lastname',
        // The following are not in the Google document:
        'http://axschema.org/namePerson/friendly': 'nickname',
        'http://axschema.org/namePerson': 'fullname'
    };

    /**
     * Attribute Exchange Extension  
     * http://openid.net/specs/openid-attribute-exchange-1_0.html  
     * Also see:
     *  - http://www.axschema.org/types/ 
     *  - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
     */
    constructor(options: Record<string, string>) {
        super();

        this.requestParams = {
            'openid.ns.ax': 'http://openid.net/srv/ax/1.0',
            'openid.ax.mode': 'fetch_request'
        };
        let required = [];
        let optional = [];
        for (let ns in options) {
            if (!options.hasOwnProperty(ns)) {
                continue;
            }

            if (options[ns] == 'required') {
                required.push(ns);
            } else {
                optional.push(ns);
            }
        }

        required = required.map((ns, i) => {
            let attr = this.attributeMapping[ns] || 'req' + i;
            this.requestParams['openid.ax.type.' + attr] = ns;
            return attr;
        });

        optional = optional.map((ns, i) => {
            let attr = this.attributeMapping[ns] || 'opt' + i;
            this.requestParams['openid.ax.type.' + attr] = ns;
            return attr;
        });

        if (required.length) {
            this.requestParams['openid.ax.required'] = required.join(',');
        }
        if (optional.length) {
            this.requestParams['openid.ax.if_available'] = optional.join(',');
        }
    }

    fillResult(params: URLSearchParams, result: Record<string, string | string[] | boolean | null>): void {
        let extension = Extension.getExtensionAlias(params, 'http://openid.net/srv/ax/1.0') || 'ax';
        let regex = new RegExp('^openid\\.' + extension + '\\.(value|type|count)\\.(\\w+)(\\.(\\d+)){0,1}$');

        let aliases: Record<string, string> = {};
        let counters: Record<string, number> = {};
        let values: Record<string, string | string[]> = {};

        for (let k of params.keys()) {
            const v = params.get(k);

            if (v === null) {
                continue;
            }

            let matches = k.match(regex);
            if (!matches) {
                continue;
            }

            if (matches[1] == 'type') {
                aliases[v] = matches[2];
            } else if (matches[1] == 'count') {
                //counter sanitization
                let count = parseInt(v, 10);

                // values number limitation (potential attack by overflow ?)
                counters[matches[2]] = (count < AX_MAX_VALUES_COUNT) ? count : AX_MAX_VALUES_COUNT;
            } else {
                if (matches[3]) {
                    //matches multi-value, aka "count" aliases

                    //counter sanitization
                    let count = parseInt(matches[4], 10);

                    // "in bounds" verification
                    if (count > 0 && count <= (counters[matches[2]] || AX_MAX_VALUES_COUNT)) {
                        if (!values[matches[2]]) {
                            values[matches[2]] = [];
                        }

                        // @ts-ignore
                        values[matches[2]][count - 1] = v;
                    }
                } else {
                    //matches single-value aliases
                    values[matches[2]] = v;
                }
            }
        }

        for (let ns in aliases) {
            if (aliases[ns] in values) {
                result[aliases[ns]] = values[aliases[ns]];
                result[ns] = values[aliases[ns]];
            }
        }
    }
}
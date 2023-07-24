import Extension from "../extension";

export type UserInterfaceOptions = string | Record<string, string>;

export default class UserInterface extends Extension {
  /**
   * User Interface Extension  
   * http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html 
   */
  constructor(options: UserInterfaceOptions) {
    super();

    if (typeof options !== 'object') {
      options = { mode: options || 'popup' };
    }

    this.requestParams = { 'openid.ns.ui': 'http://specs.openid.net/extensions/ui/1.0' };
    for (let k in options) {
      this.requestParams['openid.ui.' + k] = options[k];
    }
  }

  fillResult(params: URLSearchParams, result: Record<string, string | string[] | boolean | null>): void {
    // TODO: Fill results
  }
}
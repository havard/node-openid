import OAuthHybrid from "./extensions/OAuthHybrid";
import PAPE from "./extensions/PAPE";
import SimpleRegistration from "./extensions/SimpleRegistration";
import AttributeExchange from "./extensions/AttributeExchange";
import UserInterface from "./extensions/UserInterface";
import { RelyingParty as RelyingParty1 } from './openid';
import { Store as Store1 } from './lib/store';
import Extension2 from './extension';

export const RelyingParty = RelyingParty1;
export const Store = Store1;

/* ==================================================================
 * Extensions
 * ================================================================== 
 */
export const Extension = Extension2;

export const extensions = {
    AttributeExchange,
    OAuthHybrid,
    PAPE,
    SimpleRegistration,
    UserInterface
}
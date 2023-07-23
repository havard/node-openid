import OAuthHybrid from "./extensions/OAuthHybrid";
import PAPE from "./extensions/PAPE";
import SimpleRegistration from "./extensions/SimpleRegistration";
import AttributeExchange from "./extensions/AttributeExchange";
import UserInterface from "./extensions/UserInterface";
import {RelyingParty as RelyingParty1} from './openid';

export const RelyingParty = RelyingParty1;

/* ==================================================================
 * Extensions
 * ================================================================== 
 */
export const extensions = {
    AttributeExchange,
    OAuthHybrid,
    PAPE,
    SimpleRegistration,
    UserInterface
}
import {Chance} from "chance";
import * as _ from "lodash";
import * as moment from "moment";
import {IJwtToken, IUser} from "./ngJwtAuthInterfaces";

let seededChance:Chance.Chance = new Chance(1);

let loadedToken:string;

export const fixtures = {
    loginPrompt:null,
    user: {
        userId: 1,
        email: 'joe.bloggs@example.com',
        firstName: seededChance.first(),
        lastName: seededChance.last(),
        password: 'password',
        phone: seededChance.phone()
    },

    get userResponse():IUser{
        return <IUser>_.omit(fixtures.user, 'password');
    },

    get authBasic():string{
        return 'Basic '+btoa(fixtures.user.email+':'+fixtures.user.password)
    },

    buildToken: (overrides = {}) => {
        let defaultConfig = {
            header: {
                alg: 'RS256',
                typ: 'JWT'
            },
            data: {
                iss: 'api.spira.io',
                aud: 'spira.io',
                sub: fixtures.user.userId,
                iat: Number(moment().format('X')),
                exp: Number(moment().add(1, 'hours').format('X')),
                jti: 'random-hash',
                '#user': fixtures.userResponse,
            },
            signature: 'this-is-the-signed-hash'
        };

        let token:IJwtToken = <any>_.merge(defaultConfig, overrides);

        return btoa(JSON.stringify(token.data))
            + '.' + btoa(JSON.stringify(token.data))
            + '.' + token.signature
        ;
    },

    get token(){
        if (!loadedToken){
            loadedToken = fixtures.buildToken(); //no customisations
        }
        return loadedToken; //this "caching" ensures the token is unchanged between tests if they take too long (otherwise the timestamps may differ)
    }
};


export function locationFactoryMock(hostname:string) {
    return () => {

        return {
            host: function () {
                return hostname;
            }
        };
    };
}

export function cookiesFactoryMock(allowDomain:string) {

    let cookieStore = {};

    return () => {

        return {
            /* If you need more then $location.host(), add more methods */
            put: (key, value, conf) => {

                if (conf.domain && conf.domain !== allowDomain || value.split('.')[2] == 'always-fail-domain'){
                    return false;
                }

                cookieStore[key] = {
                    value: value,
                    conf: conf
                };
            },

            get: (key) => {
                if (!cookieStore[key]){
                    return undefined;
                }
                return cookieStore[key].value;
            },

            getObject: (key) => {
                return cookieStore[key];
            },

            remove: (key) => {
                delete cookieStore[key];
            }
        };
    };
};
// @flow
import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import {
  Strategy as OAuth2Strategy
} from "passport-oauth2";
import accountProvisioner from "../../../commands/accountProvisioner";
import env from "../../../env";
import auth from "../../../middlewares/authentication";
import passportMiddleware from "../../../middlewares/passport";
import httpErrors from "http-errors";
import fetch from "fetch-with-proxy";

const router = new Router();
const providerName = "oauth2";
const MATTERMOST_AUTHORIZE_URL = process.env.MATTERMOST_AUTHORIZE_URL
const MATTERMOST_TOKEN_URL = process.env.MATTERMOST_TOKEN_URL
const MATTERMOST_CLIENT_ID = process.env.MATTERMOST_CLIENT_ID;
const MATTERMOST_CLIENT_SECRET = process.env.MATTERMOST_CLIENT_SECRET;

const scopes = [];

export async function request(endpoint: string, accessToken: string) {
  const response = await fetch(endpoint, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });
  return response.json();
}

export const config = {
  name: "Mattermost",
  enabled: !!MATTERMOST_CLIENT_ID,
};

// Define Errors
function MattermostError(
  message: string = "Mattermost API did not return required fields"
) {
  return httpErrors(400, message, {
    id: "mattermost_error"
  });
}

if (MATTERMOST_CLIENT_ID) {
  const strategy = new OAuth2Strategy({
      authorizationURL: MATTERMOST_AUTHORIZE_URL,
      tokenURL: MATTERMOST_TOKEN_URL,
      clientID: MATTERMOST_CLIENT_ID,
      clientSecret: MATTERMOST_CLIENT_SECRET,
      callbackURL: `${env.URL}/auth/oauth2.callback`,
      passReqToCallback: true,
      scope: scopes
    },
    async function (req, accessToken, refreshToken, _, done) {
      try {
        const profile = await request(
          `https://mattermost.swy.territoires.fyi/api/v4/users/me`,
          accessToken
        )
        if (!profile) {
          throw new MattermostError(
            "Unable to load user profile from Mattermost API"
          );
        }

        // TODO: Store image binary being sent by Mattermost; haven't found way to just use uri
        // const profileImage = await request(
        //   `https://mattermost.swy.territoires.fyi/api/v4/users/${profile.id}/image`,
        //   accessToken
        // )

        const result = await accountProvisioner({
          ip: req.ip,
          team: {
            name: 'Incubateur des Territoires',
            domain: 'incubateur.anct.gouv.fr',
            subdomain: 'incubateur'
          },
          user: {
            name: `${profile.first_name} ${profile.last_name}`,
            email: profile.email
          },
          authenticationProvider: {
            name: providerName,
            providerId: "mattermost"
          },
          authentication: {
            providerId: profile.id,
            accessToken,
            refreshToken,
            scopes
          },
        });
        return done(null, result.user, result);
      } catch (err) {
        return done(err, null);
      }
    });

  passport.use(strategy);

  router.get("oauth2", passport.authenticate(providerName));
  router.get("oauth2.callback", auth({
    required: false
  }), passportMiddleware(providerName));
}

export default router;

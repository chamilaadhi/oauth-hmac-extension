package com.sample.lahiru.wso2.hmac.oauth;

import com.sample.lahiru.wso2.hmac.HMACCalculator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;

/*
 * This is an extension for enhancing the OAuth token with HMAC(Hash-based message authentication code).
 * HMAC will be added to the original OAuth access token created in default. New token will also have
  * the expiry time stamp in the token..
 *
 * Following is an explanation of how the final access token issues from this extension.
 * <p>
 * Access token example : ba13cf7473cfbde970ae6e8b60973f64.0000015fc1ebabde.67830f2f2886256eb80faa9dab85c3d2c9be7db1
 * <p>
 * It has 3 parts, delimited by "."
 * Part 1 is the original access token issued from WSO2 Identity Server.
 * Part 2 has Hex value for token expiry time
 * Part 3 is HMAC calculation of: ("Part 1" + "." + "Part 2")
 */

public class OAuthHMACTokenIssuer implements OauthTokenIssuer {

    private static final Log LOGGER = LogFactory.getLog(OAuthHMACTokenIssuer.class);

    private static final String sharedKey = System.getenv("SHARED_HMAC_KEY");
    private static final String defaultHmacAlgo = "HmacSHA1";
    private static String hmacAlgorithm = System.getenv("HMAC_ALGORITHM");

    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

        return getHMACAccessToken(oAuthIssuerImpl.accessToken(), tokReqMsgCtx.getValidityPeriod());
    }

    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.refreshToken();
    }

    public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.authorizationCode();
    }

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        return getHMACAccessToken(oAuthIssuerImpl.accessToken(), oauthAuthzMsgCtx.getValidityPeriod());
    }

    public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.refreshToken();
    }

    private String getHMACAccessToken(String accessToken, long validityPeriod) throws OAuthSystemException {

        String hmacAccessToken;
        String tokenExpirationTime = String.format("%016x", System.currentTimeMillis() + validityPeriod);

        hmacAccessToken = accessToken + '.' + tokenExpirationTime;

        try {

            if (null == hmacAlgorithm) hmacAlgorithm = defaultHmacAlgo;

            String hmac = HMACCalculator.calculateRFC2104HMAC(hmacAccessToken, sharedKey, hmacAlgorithm);

            if (null != hmac) {
                hmacAccessToken = hmacAccessToken + '.' + hmac;
            } else {
                LOGGER.error("Error creating HMAC based access token. Shared key may be null");
                throw new OAuthSystemException();
            }
        } catch (Exception e) {

            LOGGER.error("Error occurred while creating HMAC based access token", e);
            throw new OAuthSystemException(e);
        }

        return hmacAccessToken;
    }
}
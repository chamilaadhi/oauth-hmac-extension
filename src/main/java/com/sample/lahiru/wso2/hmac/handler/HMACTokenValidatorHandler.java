package com.sample.lahiru.wso2.hmac.handler;

import com.sample.lahiru.wso2.hmac.HMACCalculator;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;

import java.util.Map;

/**
 * WSO2 Handler/Mediator validate HMAC based OAuth token before actual authentication happens
 * <p>
 * Access token example : ba13cf7473cfbde970ae6e8b60973f64.0000015fc1ebabde.67830f2f2886256eb80faa9dab85c3d2c9be7db1
 * <p>
 * It has 3 parts, delimited by "."
 * Part 1 is the original access token issued from WSO2 Identity Server.
 * Part 2 has Hex value for token expiry time
 * Part 3 is HMAC calculation of: ("Part 1" + "." + "Part 2")
 * <p>
 * This class will create the HMAC again, using Part 1 and Part 2 extracted from the token.
 * Then validate the HMAC by comparing the HMAC value included in the token(Part 3).
 * <p>
 * Same SHARED_HMAC_KEY and HMAC_ALGORITHM environment variables should be set in both WSO2 IS and WSO2 APIM,
 * in order to validate the HMAC properly.
 */
public class HMACTokenValidatorHandler extends AbstractHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(HMACTokenValidatorHandler.class);

    private static final String AUTHORIZATION = "Authorization";
    private static final String sharedKey = System.getenv("SHARED_HMAC_KEY");
    private static final String defaultHmacAlgo = "HmacSHA1";
    private static String hmacAlgorithm = System.getenv("HMAC_ALGORITHM");


    public boolean handleRequest(MessageContext messageContext) {

        Map<String, String> headers = (Map) ((Axis2MessageContext) messageContext).getAxis2MessageContext()
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String oauthToken = headers.get(AUTHORIZATION);

        if (oauthToken != null) {

            String tokenParts[] = oauthToken.split("\\.");

            if (tokenParts.length != 3) {

                LOGGER.error("OAuth token format is wrong for HMAC verification phase");
                handleHmacValidationFailure(messageContext
                        , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE
                        , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS
                        , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_DESCRIPTION);
                return false;
            }
            long tokenExpiryTime;
            try {
                tokenExpiryTime = Long.parseLong(tokenParts[1], 16);
            } catch (NumberFormatException e) {

                LOGGER.error("Expiry timestamp passed in the token is not parsable to number");
                handleHmacValidationFailure(messageContext, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE
                        , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS
                        , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_DESCRIPTION);
                return false;
            }

            if (tokenExpiryTime < System.currentTimeMillis()) {

                LOGGER.error("OAuth token is expired");
                handleHmacValidationFailure(messageContext, APISecurityConstants.API_AUTH_ACCESS_TOKEN_EXPIRED_MESSAGE
                        , APISecurityConstants.API_AUTH_ACCESS_TOKEN_EXPIRED
                        , APISecurityConstants.API_AUTH_ACCESS_TOKEN_EXPIRED_DESCRIPTION);
                return false;
            }

            String hmacFromRequest = tokenParts[2];

            // Remove Bearer part to get original access token
            String accessToken = tokenParts[0].split(" ")[1].trim();
            try {

                if (null == hmacAlgorithm) hmacAlgorithm = defaultHmacAlgo;

                String hmacCalculated = HMACCalculator.calculateRFC2104HMAC(accessToken + "." + tokenParts[1],
                        sharedKey, hmacAlgorithm);

                if (null != hmacFromRequest && null != hmacCalculated && hmacFromRequest.equalsIgnoreCase(hmacCalculated)) {

                    return true;
                } else {

                    LOGGER.error("HMAC validation failed");
                    handleHmacValidationFailure(messageContext, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE
                            , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS
                            , APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_DESCRIPTION);
                }

            } catch (Exception e) {

                LOGGER.error("Error occurred while creating HMAC based access token", e);
                handleHmacValidationFailure(messageContext, APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE
                        , APISecurityConstants.API_AUTH_GENERAL_ERROR
                        , APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE);
            }
        } else {
            LOGGER.error("OAuth token not available");
            handleHmacValidationFailure(messageContext, APISecurityConstants.API_AUTH_MISSING_CREDENTIALS_MESSAGE
                    , APISecurityConstants.API_AUTH_MISSING_CREDENTIALS
                    , APISecurityConstants.API_AUTH_MISSING_CREDENTIALS_DESCRIPTION);
        }
        return false;
    }
    
    public boolean mediate(MessageContext messageContext) {
        if (messageContext.isResponse()) {
            return handleResponse(messageContext);
        }
        return handleRequest(messageContext);
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    /*
    This method was extracted from APIAuthenticationHandler packed with WSO2 APIM in default and modified.
    This will make sure HMAC validation failure and other errors are handled properly and
     it sends a proper error message to the user
     */
    private void handleHmacValidationFailure(MessageContext messageContext, String errorMessage, int errorCode
            , String errorDescription) {

        messageContext.setProperty(SynapseConstants.ERROR_CODE, errorCode);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, errorMessage);
        messageContext.setProperty(SynapseConstants.ERROR_DETAIL, errorDescription);

        Mediator sequence = messageContext.getSequence(APISecurityConstants.API_AUTH_FAILURE_HANDLER);

        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling logic from getting executed
            return;
        }

        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {

            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {

            //In case of an error it is logged and the process is continued because we're setting a fault message in
            // the payload.
            LOGGER.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status;

        if (errorCode == APISecurityConstants.API_AUTH_GENERAL_ERROR) {

            status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
        } else {

            status = HttpStatus.SC_UNAUTHORIZED;
            Map<String, String> headers =
                    (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
            if (headers != null) {
                headers.put(HttpHeaders.WWW_AUTHENTICATE, "OAuth2 realm=\"WSO2 API Manager\"");
                axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
            }
        }

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {

            Utils.setFaultPayload(messageContext, getFaultPayload(errorMessage, errorCode, errorDescription));
            axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/json");
            axis2MC.setProperty("ContentType", "application/json");

        } else {
            Utils.setSOAPFault(messageContext, "Client", "Authentication Failure", errorMessage);
        }
        Utils.sendFault(messageContext, status);
    }

    private OMElement getFaultPayload(String message, int code, String detail) {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace ns = fac.createOMNamespace(APISecurityConstants.API_SECURITY_NS,
                APISecurityConstants.API_SECURITY_NS_PREFIX);
        OMElement payload = fac.createOMElement("fault", ns);

        OMElement errorCode = fac.createOMElement("code", ns);
        errorCode.setText(String.valueOf(code));
        OMElement errorMessage = fac.createOMElement("message", ns);
        errorMessage.setText(message);
        OMElement errorDetail = fac.createOMElement("description", ns);
        errorDetail.setText(detail);

        payload.addChild(errorCode);
        payload.addChild(errorMessage);
        payload.addChild(errorDetail);
        return payload;
    }
}

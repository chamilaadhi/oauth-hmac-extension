package com.sample.lahiru.wso2.hmac;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/*
 * Utility common class to calculate HMAC for given data, using the given key and algorithm
 */
public class HMACCalculator {

    /*
     * This static method will calculate HMAC for given data, using the given key and algorithm
     */
    public static String calculateRFC2104HMAC(String data, String key, String hmacAlgorithm)
            throws InvalidKeyException, NoSuchAlgorithmException, OAuthSystemException {

        if (null != data && null != key) {
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), hmacAlgorithm);
            Mac mac;
            mac = Mac.getInstance(hmacAlgorithm);
            mac.init(signingKey);

            return toHexString(mac.doFinal(data.getBytes()));
        } else {
            throw new OAuthSystemException("Error creating HMAC based access token. Shared key may be null");
        }
    }

    private static String toHexString(byte[] bytes) {

        try (Formatter formatter = new Formatter()) {
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }
    }
}

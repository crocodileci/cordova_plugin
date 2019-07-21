/*****************************************************************************************
 * Copyright (c) 2019, HiTRUST and/or its affiliates. All rights reserved.
 * HiTRUST PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 * Modify History:
 *  2019/07/17, Jackie - First release.
 *****************************************************************************************/
package com.hitrust.plugins;
import com.hitrust.plugins.CRYPTO;

import java.util.Arrays;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

//import javax.xml.bind.DatatypeConverter;
import android.util.Base64;

/**
 * Class {@code ChallengeResponse}
 * Object for challenge response mechanism, session key exchange & encrypt/decrypt communication dada.
 */
public class ChallengeResponse {
    // define the length, key type & algorithms
    private static final int CHALLEGE_VALUE_BYTES   = 16;
    private static final int SESSION_KEY_BYTES      = 32;
    private static final String keyType = CRYPTO.SECRETKEY_AES;
    private static final String hashAlg = CRYPTO.DIGEST_SHA256;
    private static final String encMode = CRYPTO.CIPHER_MODE_ECB;
    private static final String encPad  = CRYPTO.CIPHER_PADDING_PKCS5;
    private static final String rsaMode = CRYPTO.CIPHER_MODE_ECB;
    private static final String rsaPad  = CRYPTO.CIPHER_PADDING_PKCS1;
    private static final byte[] secret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // RSA 2048 bits key pair
    private static final String publicKeyB64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhWY1AqmM/oc0w+1wXNammI+wo/Igz+rqRxWoNUT/c+RCe9kMA0sJLLeAezeJgD0ShhZZotupxeVgV9HXAzNom5ThDGWXUyG8u8qFHxxcfI71Nn/3JhFl3nBTUTvAiKrp1sg1rNGFegPLzxcW+ezyXQ+7+Y0U+LHKrwPS4PR1ZHJzb0qG+un05lq87NG9JQ/bN18vDDZqXas9hwEW9j8HBqmtKygHWY1eIOPGzhJ5uxN/G6crymDXVcTsx8nyZOsHz51cjR8kc98hbqu87DsA1BbjgqVyFpCtPbGxfIUZqMqcAD6jKQndoPAXizSqVhHgYsdzrg31oqBOoFzQniB4OwIDAQAB";
    private static final String privateKeyB64 =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCFZjUCqYz+hzTD7XBc1qaYj7Cj8iDP6upHFag1RP9z5EJ72QwDSwkst4B7N4mAPRKGFlmi26nF5WBX0dcDM2iblOEMZZdTIby7yoUfHFx8jvU2f/cmEWXecFNRO8CIqunWyDWs0YV6A8vPFxb57PJdD7v5jRT4scqvA9Lg9HVkcnNvSob66fTmWrzs0b0lD9s3Xy8MNmpdqz2HARb2PwcGqa0rKAdZjV4g48bOEnm7E38bpyvKYNdVxOzHyfJk6wfPnVyNHyRz3yFuq7zsOwDUFuOCpXIWkK09sbF8hRmoypwAPqMpCd2g8BeLNKpWEeBix3OuDfWioE6gXNCeIHg7AgMBAAECggEAGupHUdUx3H0dOVbj7+djT67WPg3xbuIACP2mpbDZNeHdRC3DzbpLDJmts6698IDiBunlhgV6GLKyIKX3Eu9BcPq1+ZFZ2e0Zrm4rM96+DmettCRXkne6LQpO1ToQG8MYUTyuD8NqgfbYHV2URjL3p60wCSbdD1yX/33vA3JvaSefKP/pUZskbS2ZP5cCPXlEvNvejQASwNeIz16soH4J7WuxXml35nEIWVOo0EQU4lSI+/3cEWYTd4JBJheDCe9ehqoQA92Lp90/I7gCfG6D+x2GOi0NrEYky1QadKWorWTYC0Owl33xGKcBqIc/UU9Rj3OlEtHF5EVfeKHJeEY92QKBgQDVWdEroFSKCbHq14NIt5n3wDS4xYP4E4MLx/6/SS+LsEb2K7XA62Md2mXykoDTeD0Pt1H7mljS3zEEYeoLGff2eq6hm2h1Qwbgd9Ft1cFEv4ARqRnncr6fsFMBPNYyjmqXikaObk1QqPAyKbHyWkKeyvHun+VUpwM8OBXcyk9UXQKBgQCgEOJhOrU0zVNgM+3oozbFKg/Qf0tRxCPdR4cnT52ACHfXRO7t78N4x+Uc7oRxYWFC1XoRejKN7b7HJldLm9QaEASm90JWueDPl3FacZWp2aqPfSIlxFRxTmSi4C1WhR39mu7PapgkX5gUoPmmwvmebgMVYGxWSlO4mGHcdV01dwKBgQC847tcO6P9Xp4FxG64Z81KWwKSgFTZwzSnrpatdrdAnn4FHyfYuM5VNPJDtE+YaoDtNCnCb6GqeO5l6eaTk5dEwtNvwy7VetVQ0OQ7sR9epYlWmXeUwbNhoHOsydb+hbZ7mnHjUmbjPd8DGoUwg5cuDZHq6efZbdBgdWttwjRABQKBgGdtYYnn8GzU+7ne9CxtQhe2bQ+RIS8NaQszi85H8IJpdl5gCW8vjQP/TjkamfPVM46G+GBQsFfrNmniiWeuoifRD+B/RptZcj1RIwqI+GcO4dnjxmvW56VrPTXNWx5b15wmP4dA3lwqdM9nkMlDlR3dAhsO+hHr5xsRQ7K7F2ZTAoGBALOPdROHQx3XT22THIjbe+BUIitR6tJND4cHUxxj/aIs6rAOG3rcPm0BEe2BMZONjquM3XXTlXTdJTIymr7JoMDMHDGov58vnaORgsdYXkuEpZK2qm1Ony809J0BTe4mRTKHD+rJOdBX4a4TmkRaHeDeduujvwNP5+XMwfRd79Vp";

    // object variable for chellege & session key values
    private byte[] challengeValue = new byte[CHALLEGE_VALUE_BYTES];;
    private byte[] sessionKeyValue = new byte[SESSION_KEY_BYTES];

    /**
     * Generate challenge value, return in Base64 String
     */
    public String generateChallege() {
        // generate random challege value
        SecureRandom random = new SecureRandom();
        random.nextBytes(this.challengeValue);
        
        // return Base64 String
//        return DatatypeConverter.printBase64Binary(this.challengeValue);
        return Base64.encodeToString(this.challengeValue, Base64.DEFAULT);
    }

    /**
     * Verify response value
     * @param responseB64   response value in Base64 String.
     */
    public boolean verifyResponse(String responseB64) {
        // calculate response value
//        byte[] response = DatatypeConverter.parseBase64Binary(responseB64);
        byte[] response = Base64.decode(responseB64, Base64.DEFAULT);
        byte[] check = response(this.challengeValue);
        
        // compare response & check
        return Arrays.equals(response, check);
    }

    /**
     * Caculate response value, return in Base64 String
     * @param challengeB64  challenge value in Base64 String.
     */
    public String calculateResponse(String challengeB64) {
        // calculate response value
//        byte[] challenge = DatatypeConverter.parseBase64Binary(challengeB64);
        byte[] challenge = Base64.decode(challengeB64, Base64.DEFAULT);
        byte[] response = response(challenge);
        
        // return Base64 String
//        return DatatypeConverter.printBase64Binary(response);
        return Base64.encodeToString(response, Base64.DEFAULT);
    }

    /**
     * Generate session key & encrypted by public key, return in Base64 String
     * @param x509B64       the key value in Base64 String of X509EncodedKeySpec.
     */
    public String generateSessionKey(String x509B64) {
		// generate random session key.
        SecureRandom random = new SecureRandom();
        random.nextBytes(this.sessionKeyValue);
        
        // construct public key & encrypt session key
        try {
//            PublicKey pubKey = CRYPTO.newPublicKey(DatatypeConverter.parseBase64Binary(x509B64));
            PublicKey pubKey = CRYPTO.newPublicKey(Base64.decode(x509B64, Base64.DEFAULT));
            byte[] keyEnc = CRYPTO.encrypt(pubKey, ChallengeResponse.rsaMode, ChallengeResponse.rsaPad, this.sessionKeyValue);

            // return Base64 String
//            return DatatypeConverter.printBase64Binary(keyEnc);
            return Base64.encodeToString(keyEnc, Base64.DEFAULT);

        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

    /**
     * Decrypt encrypted session key by private key & store it.
     * @param pkcs8B64      the private key in Base64 String of PKCS8EncodedKeySpec.
     * @param encB64        the session key encrypted by public key in Base64 String.
     */
    public boolean storeSessionKey(String pkcs8B64, String encB64) {
        try {
            // construct private key
//            PrivateKey priKey = CRYPTO.newPrivateKey(DatatypeConverter.parseBase64Binary(pkcs8B64));
            PrivateKey priKey = CRYPTO.newPrivateKey(Base64.decode(pkcs8B64, Base64.DEFAULT));

            // decrypt by private key & store it.
//            byte[] keyEnc = DatatypeConverter.parseBase64Binary(encB64);
            byte[] keyEnc = Base64.decode(encB64, Base64.DEFAULT);
            this.sessionKeyValue = CRYPTO.decrypt(priKey, ChallengeResponse.rsaMode, ChallengeResponse.rsaPad, keyEnc);
            return true;

        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return false;
        }
    }

    /**
     * Encrypt plain String to Base64 String cipher
     * @param plain         plain text to be encrypted.
     */
    public String encrypt(String plain) {
        // encrypt
        byte[] enc = encrypt(plain.getBytes());
        if(enc == null) return null;
        
        // return Base64 String
//        return DatatypeConverter.printBase64Binary(enc);
        return Base64.encodeToString(enc, Base64.DEFAULT);
    }

    /**
     * Decrypt Base64 String cipher to plain String
     * @param cipherB64     cipher text in Base64 to be decrypted.
     */
    public String decrypt(String cipherB64) {
        // decrypt
//        byte[] dec = decrypt(DatatypeConverter.parseBase64Binary(cipherB64));
        byte[] dec = decrypt(Base64.decode(cipherB64, Base64.DEFAULT));
        if(dec == null) return null;

        // return Base64 String
        return new String(dec);
    }

    /**
     * RSA public key & private key in Base64 String
     * It has to change to HSM by customer requirement.
     * ========== create RSA key for test ============
     * KeyPair keyPair = CRYPTO.genKeyPair(2048);
     * byte[] pubKey = CRYPTO.x509PublicKey(keyPair.getPublic());
     * byte[] priKey = CRYPTO.pkcs8PrivateKey(keyPair.getPrivate());
     * String pubKeyB64 = DatatypeConverter.printBase64Binary(pubKey);
     * String priKeyB64 = DatatypeConverter.printBase64Binary(priKey);
     */
    public String publicKey() {
        return ChallengeResponse.publicKeyB64;
    }
    public String privateKey() {
        return ChallengeResponse.privateKeyB64;
    }


    // calculate response value with challenge.
    private byte[] response(byte[] challenge) {
        try {
            MessageDigest md = MessageDigest.getInstance(ChallengeResponse.hashAlg);
            md.update(challenge);
            md.update(ChallengeResponse.secret);
            return md.digest();
            
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

    // encrypt input with session key.
    private byte[] encrypt(byte[] input) {
        try {
            SecretKey key = CRYPTO.newSecretKey(ChallengeResponse.keyType, this.sessionKeyValue);
            return CRYPTO.encrypt(key, ChallengeResponse.encMode, ChallengeResponse.encPad, input);
            
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

    // decrypt input with session key.
    private byte[] decrypt(byte[] input) {
        try {
            SecretKey key = CRYPTO.newSecretKey(ChallengeResponse.keyType, this.sessionKeyValue);
            return CRYPTO.decrypt(key, ChallengeResponse.encMode, ChallengeResponse.encPad, input);
            
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

}
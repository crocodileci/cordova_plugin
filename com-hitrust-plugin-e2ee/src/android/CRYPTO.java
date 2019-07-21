/*****************************************************************************************
 * @(#)CRYPTO.java
 *
 * Copyright (c) 2019, HiTRUST and/or its affiliates. All rights reserved.
 * HiTRUST PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 * Modify History:
 *  2019/03/21, Jackie - First release.
 *****************************************************************************************/
package com.hitrust.plugins;

import java.io.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Base64;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

//import sun.security.pkcs10.PKCS10;
//import sun.security.pkcs10.PKCS10Attributes;
//import sun.security.x509.AlgorithmId;
//import sun.security.x509.X500Name;
//import sun.security.util.DerValue;
//import sun.security.util.DerOutputStream;

/**
 * Class {@code CRYPTO}
 * The utilities of key(DES/DES3/AES/RSA) & certificate management, and cryptographic operations.
 * Cryptographic operations include encrypt/decrypt sign/verify & digest.
 *
 * @since   2019/03/21
 * @author  Jackie Yang
 */
public class CRYPTO {
    // Secret (symmetric) key supported
    public static final String SECRETKEY_AES        = "AES";
    public static final String SECRETKEY_DES        = "DES";
    public static final String SECRETKEY_DES3       = "DESede";

    // Cipher mode & padding supported
    public static final String CIPHER_MODE_ECB      = "ECB";
    public static final String CIPHER_MODE_CBC      = "CBC";
    public static final String CIPHER_PADDING_NO    = "NoPadding";
    public static final String CIPHER_PADDING_PKCS1 = "PKCS1Padding";
    public static final String CIPHER_PADDING_PKCS5 = "PKCS5Padding";

    // Digest algorithms supported
    public static final String DIGEST_MD2       = "MD2";
    public static final String DIGEST_MD5       = "MD5";
    public static final String DIGEST_SHA1      = "SHA-1";
    public static final String DIGEST_SHA256    = "SHA-256";
    public static final String DIGEST_SHA384    = "SHA-384";
    public static final String DIGEST_SHA512    = "SHA-512";

    // Signature algorithms supported
    public static final String SIGNATURE_RSA_SHA1   = "SHA1withRSA";
    public static final String SIGNATURE_RSA_SHA256 = "SHA256withRSA";

    /**
     * Generate secret (symmetric) key with algorithm & key length.
     * @param algorithm     algorithms of secret key, support AES, DES, DESede
     * @param keyBits       length of the key to be generated in bits, DES & DES3 set to 0
     */
    public static SecretKeySpec genSecretKey(String algorithm, int keyBits) throws Exception {
        // calculate key length in bytes
        int keyLen = (algorithm.equals(SECRETKEY_DES)) ? (8) :
                ( (algorithm.equals(SECRETKEY_DES3)) ? (24) : (keyBits/8) );

        // prepare key with random value.
        SecureRandom random = new SecureRandom();
        byte[] keyValue = new byte[keyLen];
        random.nextBytes(keyValue);

        // new SecretKey with key value & algorithm
        return newSecretKey(algorithm, keyValue);
    }

    /**
     * Construct a new secret (symmetric) key with key value (material) & algorithm.
     * @param algorithm     algorithms of secret key, support AES, DES, DESede
     * @param keyValue      the key value (material) of the secret key.
     */
    public static SecretKeySpec newSecretKey(String algorithm, byte[] keyValue) throws Exception {
        // new SecretKeySpec with key value & algorithm
        SecretKeySpec spec = new SecretKeySpec(keyValue, algorithm);
        return spec;
    }

    /**
     * Generate RSA key pair.
     * @param keyBits       the key length to be generated in bits.
     */
    public static KeyPair genKeyPair(int keyBits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keyBits);
        KeyPair keys = generator.genKeyPair();
        return keys;
    }

    /**
     * Construct a new RSA public key with modulus & exponent.
     * @param modulus   the public key's modulus.
     * @param exponent  the public key's exponent.
     */
    public static PublicKey newPublicKey(byte[] modulus, byte[] exponent) throws Exception {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, modulus),  new BigInteger(1, exponent));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey key = factory.generatePublic(spec);
        return key;
    }

    /**
     * Construct a new RSA public key with X509EncodedKeySpec.
     * @param x509key       the key value of the public key of X509EncodedKeySpec.
     */
    public static PublicKey newPublicKey(byte[] x509key) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(x509key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }

    /**
     * Get RSA public key with X509EncodedKeySpec byte[].
     * @param key       the RSA public key.
     */
    public static byte[] x509PublicKey(PublicKey key) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key.getEncoded());
        byte[] x509key = spec.getEncoded();
        return x509key;
    }

    /**
     * Construct a new RSA private key with PKCS8EncodedKeySpec.
     * @param pkcs8key      the key value of the private key of X509EncodedKeySpec.
     */
    public static PrivateKey newPrivateKey(byte[] pkcs8key) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(spec);
        return key;
    }

    /**
     * Get RSA private key PKCS8EncodedKeySpec byte[].
     * @param key       the RSA private key.
     */
    public static byte[] pkcs8PrivateKey(PrivateKey key) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key.getEncoded());
        byte[] pkcs8key = spec.getEncoded();
        return pkcs8key;
    }

    /**
     * Construct a new X509 Certificate with DER-encoded/PKCS#7-formatted certificate.
     * @param filename  the file name of DER-encoded/PKCS#7-formatted certificate file.
     */
    public static X509Certificate newCertificate(String filename) throws Exception {
        return newCertificate(new FileInputStream(filename));
    }

    /**
     * Construct a new X509 Certificate with DER-encoded/PKCS#7-formatted certificate.
     * @param cert      the DER-encoded with/without Base64 encoded or /PKCS#7-formatted
     */
    public static X509Certificate newCertificate(byte[] cert) throws Exception {
        return newCertificate(new ByteArrayInputStream(cert));
    }

    // Construct a new X509 Certificate
    private static X509Certificate newCertificate(InputStream is) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection c = cf.generateCertificates(is);
        Iterator i = c.iterator();

        // return the first certificate if contains certificates.
        if(i.hasNext()) return (X509Certificate)i.next();

        // without certificate
        return null;
    }

    /**
     * Parse the X509Principal elements.
     * @param principal     the principal of issue or subject
     */
    public static String getPrincipalName(X500Principal principal, String name) throws Exception {
        StringTokenizer st = new StringTokenizer(principal.getName(), ",");
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            if(token.startsWith(name)) {
                StringTokenizer elem = new StringTokenizer(token, "=");
                String left = elem.nextToken();
                String right = elem.nextToken();
                if(left != null && right != null) {
                    if(left.equalsIgnoreCase(name)) return right;
                }
            }
        }
        return null;
    }

    /**
     * Encrypt plain text by secret/RSA key.
     * @param key       the encrypt key.
     * @param mode      the mode of cipher, support ECB/CBC.
     * @param padding   the padding type, support NoPadding/PKCS5Padding.
     * @param plain     plain text to be encrypted.
     */
    public static byte[] encrypt(Key key, String mode, String padding, byte[] plain) throws Exception {
        byte[] iv = (mode.equals(CIPHER_MODE_CBC)) ? (defaultIV(key.getAlgorithm())) : (null);
        return encrypt(key, mode, padding, iv, plain);
    }

    /**
     * Encrypt plain text by secret/RSA key.
     * @param key       the encrypt key.
     * @param mode      the mode of cipher, support ECB/CBC.
     * @param padding   the padding type, support NoPadding/PKCS5Padding.
     * @param plain     plain text to be encrypted.
     * @param iv        initial vector for CBC mode.
     */
    public static byte[] encrypt(Key key, String mode, String padding, byte[] iv, byte[] plain) throws Exception {
        String transformation = key.getAlgorithm() + "/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(transformation);
        if(mode.equals(CIPHER_MODE_CBC)) {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        return cipher.doFinal(plain);
    }


    /**
     * Decrypt cipher data by secret/RSA key.
     * @param key       the decrypt key.
     * @param mode      the mode of cipher, support ECB/CBC.
     * @param padding   the padding type, support NoPadding/PKCS5Padding.
     * @param enc       the encrypted data to be decrypted.
     */
    public static byte[] decrypt(Key key, String mode, String padding, byte[] enc) throws Exception {
        byte[] iv = (mode.equals(CIPHER_MODE_CBC)) ? (defaultIV(key.getAlgorithm())) : (null);
        return decrypt(key, mode, padding, iv, enc);
    }

    /**
     * Decrypt cipher data by secret/RSA key.
     * @param key       the decrypt key.
     * @param mode      the mode of cipher, support ECB/CBC.
     * @param padding   the padding type, support NoPadding/PKCS5Padding.
     * @param iv        initial vector for CBC mode.
     * @param enc       the encrypted data to be decrypted.
     */
    public static byte[] decrypt(Key key, String mode, String padding, byte[] iv, byte[] enc) throws Exception {
        String transformation = key.getAlgorithm() + "/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(transformation);
        if(mode.equals(CIPHER_MODE_CBC)) {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        return cipher.doFinal(enc);
    }

    // Default initial vector for Cipher.
    private static byte[] defaultIV(String algorithm) {
        int len = (algorithm.equals(SECRETKEY_AES)) ? (16) : (8);
        byte[] iv = new byte[len];
        Arrays.fill(iv, (byte)0);
        return iv;
    }

    /**
     * Get digest of message by hash algorithm.
     * @param algorithm     hash algorithm, support MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512.
     * @param message       message to be hashed.
     */
    public static byte[] digest(String algorithm, byte[] message) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(message);
        return md.digest();
    }

    /**
     * Sign data with RSA private key.
     * @param key           the RSA private key.
     * @param algorithm     the Signature algorithm.
     * @param data          data to be signed.
     */
    public static byte[] sign(PrivateKey key, String algorithm, byte[] data) throws Exception {
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    /**
     * Verify data with RSA public key.
     * @param key           the RSA public key.
     * @param algorithm     the Signature algorithm.
     * @param data          data to be verified.
     * @param value         the signed value to verify.
     */
    public static boolean verify(PublicKey key, String algorithm, byte[] data, byte[] value) throws Exception {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(value);
    }

    /**
     * Padding data to block size of algorithm (PKCS5_PADDING).
     * @param algorithm     the algorithm of Cipher.
     * @param data          data to be padding.
     */
    public static byte[] padding(String algorithm, byte[] data) {
        // set block size in bytes by algorithm
        int blksize = (algorithm.equals(SECRETKEY_AES)) ? (16) : (8);

        // if is time of block size, no padding needed.
        if((data.length % blksize) == 0) return data;

        // new padded data by length & set padding value
        int len = blksize * ((data.length / blksize) + 1);
        byte[] pdata = Arrays.copyOf(data, len);
        byte pbyte = (byte) (pdata.length - data.length);
        for(int i=data.length; i < pdata.length; i++) pdata[i] = pbyte;
        return pdata;
    }

    /**
     * Un-padding data[] to original data[] (PKCS5_PADDING).
     * @param data          data to be un-padding.
     */
    public static byte[] unpadding(byte[] data) {
        // get the bytes count to be un-padded
        int uplen = unpadLength(data);

        // not padding data, return itself
        if(uplen == 0) return data;

        // new & return the un-padding data by remove the last padding bytes
        return Arrays.copyOf(data, data.length-uplen);
    }

    /**
     * Get the un-padding bytes count (PKCS5_PADDING).
     * @param data          data to be un-padding.
     */
    public static int unpadLength(byte[] data) {
        // last byte of data[] is the padding value
        byte pbyte = data[data.length-1];
        for(int i=1; i <= (int)pbyte; i++) {
            // not padding data, return 0
            if(data[data.length -i] != pbyte) {
                return 0;
            }
        }
        // return the bytes count to be un-padded
        return (int)pbyte;
    }

//    /**
//     * Generate CSR by keypair & CN in dname.
//     * @param dname     the X.500 Distinguished Name
//     * @param keyPair   the RSA key pair.
//     */
//    public static byte[] generateCSR(String dname, String algorithm, KeyPair keyPair) throws Exception {
//        // Prepare X500Name & Signature for sign
//        X500Name x500Name = new X500Name(dname);
//        Signature sig = Signature.getInstance(algorithm);
//        sig.initSign(keyPair.getPrivate());
//
//        // sign & encode CSR
//        PKCS10 pkcs10 = new PKCS10(keyPair.getPublic());
//        pkcs10.encodeAndSign(x500Name, sig);
//
//        // Output to byte[]
//        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(outStream);
//        pkcs10.print(printStream);
//        byte[] csr = outStream.toByteArray();
//
//        // close Streams & return
//        outStream.close();
//        printStream.close();
//        return csr;
//    }
//
//    // Generate CSR info
//    public static byte[] infoCSR(String dname, PublicKey key) throws Exception {
//        // Encode cert request info, wrap in a sequence for signing
//        DerOutputStream scratch = new DerOutputStream();
//        scratch.putInteger(BigInteger.ZERO);    // PKCS #10 v1.0
//        X500Name subject = new X500Name(dname);
//        subject.encode(scratch);                // X.500 name
//        scratch.write(key.getEncoded());     // public key
//        //
//        PKCS10Attributes attrSet = new PKCS10Attributes();
//        attrSet.encode(scratch);
//
//        // wrap it!
//        DerOutputStream out = new DerOutputStream();
//        out.write(DerValue.tag_Sequence, scratch);
//        byte[] csrInfo = out.toByteArray();
//        return csrInfo;
//    }
//
//    // Generate CSR encode String
//    public static String encodeCSR(String algorithm, byte[] csrInfo, byte[] sig) throws Exception {
//        // cert request info
//        DerOutputStream scratch = new DerOutputStream();
//        scratch.write(csrInfo);
//
//        // Build guts of SIGNED macro
//        AlgorithmId algId = AlgorithmId.get(algorithm);
//        algId.encode(scratch);     // sig algorithm
//        scratch.putBitString(sig); // signature
//
//        // Wrap those guts in a sequence
//        DerOutputStream out = new DerOutputStream();
//        out.write(DerValue.tag_Sequence, scratch);
//        byte[] encoded = out.toByteArray();
//
//        // Conver to Base64 String
//        byte[] lineEndings = new byte[] {'\r', '\n'}; // CRLF
//        String csrContent =
//                "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
//                Base64.getMimeEncoder(64, lineEndings).encodeToString(encoded) + "\n" +
//                "-----END NEW CERTIFICATE REQUEST-----\n";
//        return csrContent;
//    }

}
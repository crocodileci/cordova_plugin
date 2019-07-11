/* global cordova:false */
/* globals window */

var exec = cordova.require('cordova/exec'),
    utils = cordova.require('cordova/utils');

var template = {
    echo: function(successCallback, errorCallback, message, forceAsync) {
        var action = 'echo';

        if (forceAsync) {
            action += 'Async';
        }

        exec(successCallback, errorCallback, 'E2EE', action, [message]);
    },
    //產生challenge值
    //參數 aesKey: AES256的key, Hex string
    //使用success callback 回傳challenge值
    //challenge產生的方式為
    //產生一把random AES 256 Key當作Session Key
    // session key = random AES256Key
    //組合一個byte array 格式為 "HiTRUST".getbytes() + session key 作為challenge值
    // challenge: byte[] = "HiTRUST".getbytes() + session key
    //使用內埋的AES 256 Key 加密該字串: A key Enc(challenge, pkcs5Padding)
    // encrypt_challenge: byte[] = AkeyEnc(challenge, pkcs5Padding)
    //回傳HexString(encrypt_challenge)
    generateChallenge: function (successCallback, errorCallback, aesKey) {
        exec(successCallback, errorCallback, 'E2EE', "generateChallenge", [aesKey]);
    },
    //驗證response
    //參數 response: response, Hex string
    //使用success callback 回傳驗證結果 Boolen, true: 驗證通過, false: 驗證失敗
    //驗證演算法
    //將Hex string 轉為byte array
    //將該byte array使用public key 解密取得明文
    //比對解密後的明文為generateChallenge產生的那把random key則回傳true，若不是則回傳false
    verifyResponse: function (successCallback, errorCallback, response) {
        exec(successCallback, errorCallback, 'E2EE', "verifyResponse", [response]);
    },
    //使用generateChallenge 產生的session key加密明文
    //參數 plainText: 明文 string
    //使用success callback 回傳加密後之密文 Base64 encoded string
    sessionKeyEncrypt: function (successCallback, errorCallback, plainText) {
        exec(successCallback, errorCallback, 'E2EE', "sessionKeyEncrypt", [plainText]);
    },
    //使用generateChallenge 產生的session key解密密文
    //參數 cipherText: 密文 base64 encoded string
    //使用success callback 回傳解密後之明文 string
    sessionKeyDecrypt: function (successCallback, errorCallback, cipherText) {
        exec(successCallback, errorCallback, 'E2EE', "sessionKeyDecrypt", [cipherText]);
    }
};

module.exports = template;

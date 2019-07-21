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
    //演算法
    //隨機產生一個資料長度為 16 bytes長度的 challenge
    // challenge_base64 = Base64_encode(challenge)
    //使用success傳回結果: Object, {clientChallenge: challenge_base64}
    generateChallenge: function (successCallback, errorCallback) {
        exec(successCallback, errorCallback, 'E2EE', "generateChallenge", []);
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

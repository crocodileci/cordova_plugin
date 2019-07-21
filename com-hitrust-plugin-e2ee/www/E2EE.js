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
    //模擬伺服器回覆challenge
    //參數 clientChallenge: Object, {clientChallenge: challenge_base64}
    //使用success傳回結果: Object, {serverResponse: base64String, serverChallenge: base64String, publicKey: base64String}
    mockServerChallengeResponse: function (clientChallenge, successCallback, errorCallback) {
        exec(successCallback, errorCallback, 'E2EE', "mockServerChallengeResponse", [clientChallenge]);
    },
    //驗證response
    //參數 serverResponse: Object, {serverResponse: base64String, serverChallenge: base64String, publicKey: base64String}
    //使用success傳回結果: {sessionKey: base64String, clientResponse: base64String}
    verifyResponse: function (serverResponse, successCallback, errorCallback, ) {
        exec(successCallback, errorCallback, 'E2EE', "verifyResponse", [serverResponse]);
    },
    //模擬伺服器回傳response
    //參數 clientResponse: {sessionKey: base64String, clientResponse: base64String}
    //使用success傳回結果: {answer: base64String}
    mockServerResponseResponse: function(clientResponse, successCallback, errorCallback){
        exec(successCallback, errorCallback, 'E2EE', "mockServerResponseResponse", [clientResponse]);
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

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

        exec(successCallback, errorCallback, 'cardReader', action, [message]);
    },
    //檢查讀卡機是否存在
    //使用success傳回結果為true: 存在, false: 不存在
    isReaderExisted : function (success, error) {
        exec(success, error, 'cardReader', 'isReaderExisted', []);
    },
    //檢查卡片是否存在
    //使用success傳回結果為boolen, true: 存在, false: 不存在
    isCardExisted: function (success, error) {
        exec(success, error, 'cardReader', 'isCardExisted', []);
    },
    //取得卡片資訊
    //使用success傳回結果 object, {issuer:, mainAccount:}
    getCardInfo:function (success, error) {
        exec(success, error, 'cardReader', 'getCardInfo', []);
    },
    //取得TAC值
    //使用success傳回結果 object, {tac:, serial:}
    getTAC : function (text, success, error) {
        exec(success, error, 'cardReader', 'getTAC', [text]);
    },
    //驗證密碼
    //使用success傳回結果 Boolean, true: 驗證成功, false: 驗證失敗
    verifyPin: function (pincode, success, error) {
        exec(success, error, 'cardReader', 'verifyPin', [pincode]);
    }
    //修改密碼
    //使用success傳回結果 Boolen, true: 驗證成功, false: 變更失敗
    ,modifyPin : function (pincode_orig, pingcode_new, success, error) {
        exec(success, error, 'cardReader', 'modifyPin', [pincode_orig, pingcode_new]);
    }
};

module.exports = template;

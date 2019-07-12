/* global cordova:false */
/* globals window */

var exec = cordova.require('cordova/exec'),
    utils = cordova.require('cordova/utils');
var channel = require('cordova/channel');

var CardReader = function () {
    var me = this;

    this.channels = {
        readerattached: cordova.addWindowEventHandler('readerattached'),
        readerdetached: cordova.addWindowEventHandler('readerdetached'),
        cardattached: cordova.addWindowEventHandler('cardattached'),
        carddetached: cordova.addWindowEventHandler('carddetached')
    };

    channel.onCordovaReady.subscribe(function () {
        exec(me.eventHandler, me.error, 'cardReader', "eventHandler", []);
    })
}

CardReader.prototype.echo = function (successCallback, errorCallback, message, forceAsync) {
    var action = 'echo';

    if (forceAsync) {
        action += 'Async';
    }

    exec(successCallback, errorCallback, 'cardReader', action, [message]);
}

//檢查讀卡機是否存在
//使用success傳回結果為true: 存在, false: 不存在
CardReader.prototype.isReaderExisted = function (success, error) {
    exec(success, error, 'cardReader', 'isReaderExisted', []);
}

//檢查卡片是否存在
//使用success傳回結果為boolen, true: 存在, false: 不存在
CardReader.prototype.isCardExisted = function (success, error) {
    exec(success, error, 'cardReader', 'isCardExisted', []);
}

//取得卡片資訊
//使用success傳回結果 object, {issuer:, mainAccount:}
CardReader.prototype.getCardInfo = function (success, error) {
    exec(success, error, 'cardReader', 'getCardInfo', []);
}

//取得TAC值
//使用success傳回結果 object, {tac:, serial:}
CardReader.prototype.getTAC = function (text, success, error) {
    exec(success, error, 'cardReader', 'getTAC', [text]);
}

//驗證密碼
//使用success傳回結果 Boolean, true: 驗證成功, false: 驗證失敗
CardReader.prototype.verifyPin = function (pincode, success, error) {
    exec(success, error, 'cardReader', 'verifyPin', [pincode]);
}

//修改密碼
//使用success傳回結果 Boolen, true: 驗證成功, false: 變更失敗
CardReader.prototype.modifyPin = function (pincode_orig, pingcode_new, success, error) {
    exec(success, error, 'cardReader', 'modifyPin', [pincode_orig, pingcode_new]);
}

//事件處理
//使用success傳回結果 String, "readerattached": 讀卡機接入, 
//                          "readerdetached": 讀卡機拔出,
//                          "cardattached": 卡片插入,
//                          "carddetached":卡片拔出
CardReader.prototype.eventHandler = function (event) {
    cordova.fireWindowEvent(event);
}

CardReader.prototype.error = function (error) {

}

var cardReader = new CardReader();

module.exports = cardReader;
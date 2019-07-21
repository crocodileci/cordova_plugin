
package com.hitrust.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.SuppressLint;
import android.util.Base64;
import android.util.Log;

/**
* This class exposes methods in Cordova that can be called from JavaScript.
*/
public class E2EE extends CordovaPlugin {

    private final String TAG = "E2EE";

     private volatile boolean bulkEchoing;
     private ChallengeResponse crClientObject;
     private ChallengeResponse crMockServerObject;

     /**
     * Executes the request and returns PluginResult.
     *
     * @param action            The action to execute.
     * @param args              JSONArry of arguments for the plugin.
     * @param callbackContext   The callback context from which we were invoked.
     */
    @SuppressLint("NewApi")
    public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if (action.equals("echo")) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, args.getString(0)));
        } else if(action.equals("echoAsync")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    callbackContext.sendPluginResult( new PluginResult(PluginResult.Status.OK, args.optString(0)));
                }
            });
        } else if(action.equals("generateChallenge")){

            LOG.e(TAG, "Plugin generateChallenge");
            JSONObject challenge = generateChallenge();

            callbackContext.sendPluginResult( new PluginResult(PluginResult.Status.OK, challenge));

        } else if(action.equals("mockServerChallengeResponse")){

            LOG.e(TAG, "Plugin mockServerChallengeResponse");
            JSONObject clientChallenge = args.getJSONObject(0);

            JSONObject mockServerChallengeResponse_obj = mockServerChallengeResponse(clientChallenge);

            callbackContext.sendPluginResult( new PluginResult(PluginResult.Status.OK, mockServerChallengeResponse_obj));

        } else if(action.equals("verifyResponse")){
            LOG.e(TAG, "Plugin verifyResponse");

            JSONObject serverChallenge = args.getJSONObject(0);

            JSONObject clientResponse = verifyResponse(serverChallenge);

            if(clientResponse != null) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, clientResponse));
            }else{
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Something wrong"));
            }

        } else if(action.equals("mockServerResponseResponse")){

            LOG.e(TAG, "Plugin mockServerResponseResponse");

            JSONObject clientResponse = args.getJSONObject(0);

            JSONObject mockServerResponse = mockServerResponseResponse(clientResponse);

            if(clientResponse != null) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, mockServerResponse));
            }else{
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Something wrong"));
            }

        } if(action.equals("sessionKeyDecrypt")){
            LOG.e(TAG, "Plugin sessionKeyDecrypt");

            String cipherText = args.getString(0);

            String plainText = sessionKeyDecrypt(cipherText);


            if(plainText != null) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, plainText));
            }else{
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Something wrong"));
            }


        } else {
            return false;
        }
        return true;
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        LOG.e(TAG, "initialize");

        this.crClientObject = new ChallengeResponse();

        LOG.e(TAG, this.crClientObject.toString());

        this.crMockServerObject = new ChallengeResponse();

        LOG.e(TAG, this.crMockServerObject.toString());

    }

    private JSONObject generateChallenge() throws JSONException{
        JSONObject ret = new JSONObject();
        String challenge = this.crClientObject.generateChallege();

        ret.put("clientChallenge", challenge);

        return ret;
    }

    private JSONObject mockServerChallengeResponse(JSONObject clientChallenge_obj) throws JSONException{

        JSONObject ret = new JSONObject();

        String clientChallenge = clientChallenge_obj.getString("clientChallenge");

        String serverResponse   = crMockServerObject.calculateResponse(clientChallenge);
        String serverChallenge  = crMockServerObject.generateChallege();
        String publicKey        = crMockServerObject.publicKey();

        ret.put("serverResponse", serverResponse);
        ret.put("serverChallenge", serverChallenge);
        ret.put("publicKey", publicKey);

        return ret;
    }

    private JSONObject verifyResponse(JSONObject serverResponse_obj) throws JSONException{

        JSONObject ret = new JSONObject();

        String serverResponse = serverResponse_obj.getString("serverResponse");
        String serverChallenge = serverResponse_obj.getString("serverChallenge");
        String publicKey = serverResponse_obj.getString("publicKey");

        if (serverResponse == null) LOG.e(TAG, "Without serverResponse!");
        if (serverChallenge == null) LOG.e(TAG, "Without serverChallenge!");
        if (publicKey == null) LOG.e(TAG, "Without publicKey!");
        if ((serverResponse == null) || (serverChallenge == null) || (publicKey == null)) {
            return null;
        }

        // 1.2) Verify server response value
        LOG.e(TAG,"Verify server response value...");
        if (!crClientObject.verifyResponse(serverResponse)) {
            LOG.e(TAG,"Server response value verify fail, is not authorized server.");
            return null;
        }

        // 2.1) Generate session key, calculate response value & request to server
        LOG.e(TAG, "Generate session key, calculate response value & request to server...");
        String sessionKey = crClientObject.generateSessionKey(publicKey);
        if(sessionKey == null) {
            LOG.e(TAG, "Generate session key failure, maybe has wrong public key!");
            return null;
        }
        String clientResponse = crClientObject.calculateResponse(serverChallenge);

        ret.put("sessionKey", sessionKey);
        ret.put("clientResponse", clientResponse);

        return ret;

    }

    private JSONObject mockServerResponseResponse(JSONObject clientResponse_obj) throws JSONException{

        JSONObject ret = new JSONObject();

        String clientResponse = clientResponse_obj.getString("clientResponse");
        String sessionKey = clientResponse_obj.getString("sessionKey");

        if (clientResponse == null) {
            LOG.e(TAG, "Without clientResponse");
            return null;
        }
        if (sessionKey == null) {
            LOG.e(TAG, "Without sessionKey");
            return null;
        }

        // verify client response
        if (!crMockServerObject.verifyResponse(clientResponse)) {
            LOG.e(TAG, "Client response verify error");
            return null;
        }

        // load session key to crObj
        String priKeyB64 = crMockServerObject.privateKey();
        if (!crMockServerObject.storeSessionKey(priKeyB64, sessionKey)) {
            LOG.e(TAG, "Decrypt session error");
        }

        // response encrypted answer to client
        String answer = crMockServerObject.encrypt("Synchronize session key complete");
        ret.put("answer", answer);

        return ret;

    }


    private String sessionKeyDecrypt(String cipherText) throws JSONException{

        String ret = crClientObject.decrypt(cipherText);

        return ret;
    }
}

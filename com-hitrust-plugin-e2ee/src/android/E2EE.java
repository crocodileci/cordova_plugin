
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
     private ChallengeResponse crObject;

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

        } else {
            return false;
        }
        return true;
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        LOG.e(TAG, "initialize");

        this.crObject = new ChallengeResponse();

        LOG.e(TAG, crObject.toString());

    }

    private JSONObject generateChallenge() throws JSONException{
        JSONObject ret = new JSONObject();
        String challenge = this.crObject.generateChallege();

        ret.put("clientChallenge", challenge);

        return ret;
    }
}

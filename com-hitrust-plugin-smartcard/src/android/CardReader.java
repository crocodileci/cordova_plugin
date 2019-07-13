
package com.hitrust.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.util.Base64;

import com.acs.smartcard.Reader;

/**
 * This class exposes methods in Cordova that can be called from JavaScript.
 */
public class CardReader extends CordovaPlugin {

    private final String TAG = "CardReader";
    private UsbManager mManager;
    private Reader mReader;
    private static final String ACTION_USB_PERMISSION = "com.android.example.USB_PERMISSION";

    private CallbackContext eventCallbackContext = null;

    private volatile boolean bulkEchoing;

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArry of arguments for the plugin.
     * @param callbackContext The callback context from which we were invoked.
     */
    @SuppressLint("NewApi")
    public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext)
            throws JSONException {
        if (action.equals("echo")) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, args.getString(0)));
        } else if (action.equals("echoAsync")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, args.optString(0)));
                }
            });
        } else if (action.equals("eventHandler")) {
            LOG.e(TAG, "connect eventHandler");
            eventCallbackContext = callbackContext;

            // Don't return any result now, since status results will be sent when events
            // come in from broadcast receiver
            PluginResult pluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
            pluginResult.setKeepCallback(true);
            callbackContext.sendPluginResult(pluginResult);
        } else {
            return false;
        }
        return true;
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        Context context = this.cordova.getActivity().getApplicationContext();

        super.initialize(cordova, webView);
        // your init code here
        LOG.e(TAG, "initialize");

        // Get USB manager
        mManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);

        // Initialize reader
        mReader = new Reader(mManager);
        LOG.e(TAG, "mReader: " + mReader.toString());

        // Register receiver for USB permission
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_USB_PERMISSION);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        this.cordova.getActivity().getApplicationContext().registerReceiver(mReceiver, filter);
    }

    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {

        public void onReceive(Context context, Intent intent) {

            String action = intent.getAction();

            if (ACTION_USB_PERMISSION.equals(action)) {

                synchronized (this) {

                    UsbDevice device = (UsbDevice) intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);

                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {

                        if (device != null) {

                            // Open reader
                            LOG.e(TAG, "Opening reader: " + device.getDeviceName() + "...");
                            // new OpenTask().execute(device);
                        }

                    } else {

                        LOG.e(TAG, "Permission denied for device " + device.getDeviceName());
                    }
                }

            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {

                LOG.e(TAG, "Reader detached:...");

                // callback to js
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, "readerdetached");
                pluginResult.setKeepCallback(true);
                eventCallbackContext.sendPluginResult(pluginResult);

                synchronized (this) {

                    // Update reader list
                    for (UsbDevice device : mManager.getDeviceList().values()) {
                        LOG.e(TAG, "Reader detached: " + device.getDeviceName() + "...");
                        if (mReader.isSupported(device)) {
                            // mReaderAdapter.add(device.getDeviceName());
                            LOG.e(TAG, "Found reader: " + device.getDeviceName() + "...");
                        }
                    }

                    UsbDevice device = (UsbDevice) intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);

                    if (device != null && device.equals(mReader.getDevice())) {

                        // Close reader
                        LOG.e(TAG, "Closing reader...");
                        // new CloseTask().execute();
                    }
                }
            } else if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                LOG.e(TAG, "Reader attached:...");

                // callback to js
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, "readerattached");
                pluginResult.setKeepCallback(true);
                eventCallbackContext.sendPluginResult(pluginResult);

                // Update reader list
                for (UsbDevice device : mManager.getDeviceList().values()) {
                    if (mReader.isSupported(device)) {
                        LOG.e(TAG, "The reader is supported: " + device.getDeviceName() + "...");
                    }
                }
            }
        }
    };
}

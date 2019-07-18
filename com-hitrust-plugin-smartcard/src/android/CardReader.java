
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
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.AsyncTask;
import android.util.Base64;

import com.acs.smartcard.Reader;
import com.acs.smartcard.ReaderException;

/**
 * This class exposes methods in Cordova that can be called from JavaScript.
 */
public class CardReader extends CordovaPlugin {

    private final String TAG = "CardReader";
    private UsbManager mManager;
    private Reader mReader;
    private PendingIntent mPermissionIntent;

    private Boolean isReaderExisted = false;
    private Boolean isCardExisted = false;
    private String mIssuer;
    private String mMainAccount;
    private String mPin;

    private static final String ACTION_USB_PERMISSION = "com.android.example.USB_PERMISSION";
    private CallbackContext eventCallbackContext = null;
    private static final String[] stateStrings = {"Unknown", "Absent",
            "Present", "Swallowed", "Powered", "Negotiable", "Specific"};

    private static final String READER_DETACHED_EVENT = "readerdetached";
    private static final String READER_ATTACHED_EVENT = "readerattached";
    private static final String CARD_DETACHED_EVENT = "carddetached";
    private static final String CARD_ATTACHED_EVENT = "cardattached";

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
        } else if (action.equals("isReaderExisted")) {

            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, isReaderExisted);
            pluginResult.setKeepCallback(true);
            callbackContext.sendPluginResult(pluginResult);

        } else if (action.equals("isCardExisted")) {

            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, isCardExisted);
            pluginResult.setKeepCallback(true);
            callbackContext.sendPluginResult(pluginResult);

        } else if (action.equals("getCardInfo")) {
            JSONObject result = getCardInfo();

            if(mReader.getState(0) != Reader.CARD_SPECIFIC){

                PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR);
                callbackContext.sendPluginResult(pluginResult);

            }else{

                result.put("issuer", mIssuer);
                result.put("mainAccount", mMainAccount);

                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, result);
                callbackContext.sendPluginResult(pluginResult);

            }

        } else if(action.equals("verifyPin")){

            String pincode = args.getString(0);
            LOG.e(TAG, "pincode: " + pincode);

            mPin = pincode;

            int result = VerifyPin(pincode);

            LOG.e(TAG, "verify " + (result == 0x9000 ? "success" : "failed") );

            boolean isVerified = (result == 0x9000);

            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, isVerified);
            callbackContext.sendPluginResult(pluginResult);


        } else if(action.equals("modifyPin")){
            LOG.e(TAG, "modifyPin");

            String pincode_orig = args.getString(0);
            String pincode_new = args.getString(1);

            LOG.e(TAG, "pincode_orig: " + pincode_orig);
            LOG.e(TAG, "pincode_new: " + pincode_new);

            int result = VerifyPin(pincode_orig);

            if(result == 0x9000){

                result = ChangePin(pincode_new);

            }

            boolean isSuccess = (result == 0x9000);


            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, isSuccess);
            callbackContext.sendPluginResult(pluginResult);

        } else if(action.equals("getTAC")){
            LOG.e(TAG, "getTAC");

            String plainText = args.getString(0);
            LOG.e(TAG, "plainText: " + plainText);

            byte []baP1P2 = new byte[2];
            baP1P2[0] = 0x10;
            baP1P2[1] = (byte)0x80;

            byte[] plainText_bin = plainText.getBytes();
            int plainText_bin_count = plainText_bin.length;

            if(mPin != null) {
                int result = VerifyPin(mPin);

                if (result == 0x9000) {

                    byte[] response = FISC_WriteRecordWithSNUMTAC(baP1P2, (byte) plainText_bin_count, plainText_bin);

                    if (response != null) {
                        LOG.e(TAG, "response: " + byte2Hex(response));

                        JSONObject TAC_info = parseTSAC(response);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, TAC_info);
                        callbackContext.sendPluginResult(pluginResult);

                    }
                }else{

                    PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, "Internel error");
                    callbackContext.sendPluginResult(pluginResult);

                }


            }else{

                PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, "please verify pincode first");
                callbackContext.sendPluginResult(pluginResult);
            }

            return true;

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

        //Add card detached or attached eventHandler
        mReader.setOnStateChangeListener(new Reader.OnStateChangeListener() {

            @Override
            public void onStateChange(int slotNum, int prevState, int currState) {

                if (prevState < Reader.CARD_UNKNOWN
                        || prevState > Reader.CARD_SPECIFIC) {
                    prevState = Reader.CARD_UNKNOWN;
                }

                if (currState < Reader.CARD_UNKNOWN
                        || currState > Reader.CARD_SPECIFIC) {
                    currState = Reader.CARD_UNKNOWN;
                }

                // Create output string
                final String outputString = "Slot " + slotNum + ": "
                        + stateStrings[prevState] + " -> "
                        + stateStrings[currState];

                LOG.e(TAG, outputString);

                if ( currState == Reader.CARD_PRESENT ) {

                    try {
                        byte[] atr = mReader.power(slotNum, Reader.CARD_WARM_RESET);
                        LOG.e(TAG, "Power reader: " + byte2Hex(atr));

                        int protocol = mReader.getProtocol(slotNum);
                        LOG.e(TAG, "Current protocol: " + protocol);

                        int state = mReader.getState(slotNum);
                        LOG.e(TAG, "Current state: " + stateStrings[state]);

                    } catch (ReaderException e) {

                        e.printStackTrace();
                        LOG.e(TAG, "ReaderException: " + e.toString());
                    }

                    isCardExisted = true;

                    mIssuer = GetIssuerId();
                    mMainAccount = GetMainAccount();

                    LOG.e(TAG, "issuer: " + mIssuer);
                    LOG.e(TAG, "mainAccount: " + mMainAccount);

                    // callback to js
                    if (eventCallbackContext != null) {

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, CARD_ATTACHED_EVENT);
                        pluginResult.setKeepCallback(true);
                        eventCallbackContext.sendPluginResult(pluginResult);
                    }

                } else if ( currState == Reader.CARD_ABSENT) {

                    isCardExisted = false;

                    //清除卡片資訊
                    clearCardInfo();

                    if (eventCallbackContext != null) {

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, CARD_DETACHED_EVENT);
                        pluginResult.setKeepCallback(true);
                        eventCallbackContext.sendPluginResult(pluginResult);
                    }

                } else if (currState == Reader.CARD_SPECIFIC){

                    String issuer = GetIssuerId();
                    String mainaccount = GetMainAccount();

                    LOG.e(TAG, "issuer: " + issuer);
                    LOG.e(TAG, "mainAccount: " + mainaccount);

                }

            }
        });

        // Register receiver for USB permission
        mPermissionIntent = PendingIntent.getBroadcast(context, 0, new Intent(
                ACTION_USB_PERMISSION), 0);

        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_USB_PERMISSION);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        this.cordova.getActivity().getApplicationContext().registerReceiver(mReceiver, filter);

        //if have some device, try to open it
        for (UsbDevice device : mManager.getDeviceList().values()) {
            if (mReader.isSupported(device)) {

                isReaderExisted = true;

                LOG.e(TAG, "The reader is supported: " + device.getDeviceName() + "...");
                // Request permission
                mManager.requestPermission(device,
                        mPermissionIntent);
            }
        }
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
                            new OpenTask().execute(device);
                        }

                    } else {

                        LOG.e(TAG, "Permission denied for device " + device.getDeviceName());
                    }
                }

            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {

                LOG.e(TAG, "Reader detached:...");

                isReaderExisted = false;
                isCardExisted = false;

                clearCardInfo();

                // callback to js
                if (eventCallbackContext != null) {

                    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, READER_DETACHED_EVENT);
                    pluginResult.setKeepCallback(true);
                    eventCallbackContext.sendPluginResult(pluginResult);
                }

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
                        new CloseTask().execute();
                    }
                }
            } else if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                LOG.e(TAG, "Reader attached:...");

                isReaderExisted = true;

                // callback to js
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, READER_ATTACHED_EVENT);
                pluginResult.setKeepCallback(true);
                eventCallbackContext.sendPluginResult(pluginResult);

                // Update reader list
                for (UsbDevice device : mManager.getDeviceList().values()) {
                    if (mReader.isSupported(device)) {
                        LOG.e(TAG, "The reader is supported: " + device.getDeviceName() + "...");
                        // Request permission
                        mManager.requestPermission(device,
                                mPermissionIntent);
                    }
                }
            }
        }
    };

    private class OpenTask extends AsyncTask<UsbDevice, Void, Exception> {

        @Override
        protected Exception doInBackground(UsbDevice... params) {

            Exception result = null;

            try {

                mReader.open(params[0]);

            } catch (Exception e) {

                result = e;
            }

            return result;
        }

        @Override
        protected void onPostExecute(Exception result) {

            if (result != null) {

                LOG.e(TAG, "OpenTask error: " + result.toString());

            } else {

                LOG.e(TAG, "Reader name: " + mReader.getReaderName());

                int numSlots = mReader.getNumSlots();

                LOG.e(TAG, "Number of slots: " + numSlots);

            }
        }
    }

    private class CloseTask extends AsyncTask<Void, Void, Void> {

        @Override
        protected Void doInBackground(Void... params) {

            mReader.close();
            return null;
        }

        @Override
        protected void onPostExecute(Void result) {
        }

    }

    public String byte2Hex(byte[] b) {
        String result = "";

        for (int i = 0; i < b.length; i++) {
            if (i == 0) {
                result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1).toUpperCase();
            } else {
                result += " " + Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1).toUpperCase();
            }
        }

        return result;
    }

    public String bin2hex(byte[] b) {
        String result = "";

        for (int i = 0; i < b.length; i++) {
            if (i == 0) {
                result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1).toUpperCase();
            } else {
                result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1).toUpperCase();
            }
        }

        return result;
    }

    public byte[] hex2bin(String hex) throws NumberFormatException {
        if (hex.length() % 2 > 0) {
            throw new NumberFormatException("Hexadecimal input string must have an even length.");
        }
        byte[] r = new byte[hex.length() / 2];
        for (int i = hex.length(); i > 0;) {
            r[i / 2 - 1] = (byte) (digit(hex.charAt(--i)) | (digit(hex.charAt(--i)) << 4));
        }
        return r;
    }

    private int digit(char ch) {
        //TODO Optimize this
        int r = Character.digit(ch, 16);
        if (r < 0) {
            throw new NumberFormatException("Invalid hexadecimal string: " + ch);
        }
        return r;
    }

    public JSONObject getCardInfo() throws JSONException {

        JSONObject result = new JSONObject();
        result.put("issuer", "123");
        result.put("mainAccount", "");


        return result;
    }

    private int FISC_SelectEF(byte[] baEFID) {
        int uiSW12 = 0;

        int ulSendLen = 0;
        byte[] baSendBuf = new byte[64];
        byte[] baRecBuf = new byte[1024];
        int ulRecLen = baRecBuf.length;
        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = (byte) 0xA4;
        baSendBuf[ulSendLen++] = 0x02;
        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = 0x02;
        baSendBuf[ulSendLen++] = baEFID[0];
        baSendBuf[ulSendLen++] = baEFID[1];

        try {

            int receiveLength = mReader.transmit(0, baSendBuf, ulSendLen, baRecBuf, ulRecLen);

            if (receiveLength >= 2) {
                LOG.e(TAG, "receiveLength: " + receiveLength);
                LOG.e(TAG, "baRecBuf: " + byte2Hex(baRecBuf));

                int uiSW12_high = (baRecBuf[receiveLength-2] << 8) & 0xFFFF;
                int uiSW12_low = baRecBuf[receiveLength-1];

                LOG.e(TAG, "uiSW12_high: " + uiSW12_high);
                LOG.e(TAG, "uiSW12_low: " + uiSW12_low);

                uiSW12 = uiSW12_high | uiSW12_low;

                LOG.e(TAG, "result: " + uiSW12);
            }

        } catch (ReaderException e) {

            LOG.e(TAG, "FISC_SelectEF excption: " + e.toString());

        }

        return uiSW12;
    }

    private byte[] FISC_ReadRecord(byte bRecID, byte bLen) {

        LOG.e(TAG, "FISC_ReadRecord");

        byte[] ret = null;

        int ulSendLen = 0;
        byte[] baSendBuf = new byte[1024];
        byte[] baRecBuf = new byte[1024];
        int ulRecLen = baRecBuf.length;
        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = (byte)0xB2;
        baSendBuf[ulSendLen++] = bRecID;
        baSendBuf[ulSendLen++] = 0x04;
        baSendBuf[ulSendLen++] = bLen;

        try {

            int receiveLength = mReader.transmit(0, baSendBuf, ulSendLen, baRecBuf, ulRecLen);

            LOG.e(TAG, "receiveLength: " + receiveLength);

            if (receiveLength >= 2) {
                ret = new byte[receiveLength - 2];

                for (int i = 0; i < (receiveLength - 2); i++) {
                    ret[i] = baRecBuf[i];
                }
            }

        } catch (ReaderException e) {

            LOG.e(TAG, "FISC_ReadRecord excption: " + e.toString());

        }

        return ret;

    }

    private String GetIssuerId(){
        LOG.e(TAG, "GetIssuerId");

        String retStr = null;

        //select EF 1001
        byte[] bRecData = new byte[256];
        byte[] bLen = new byte[2];
        byte[] EFID = new byte[8];
        EFID[0] = 0x10;
        EFID[1] = 0x01;

        int result;
        byte[] ret = null;

        result = FISC_SelectEF(EFID);

        if(result == 0x9000) {

            ret = FISC_ReadRecord((byte)0x01, (byte)0x00);

            LOG.e(TAG, byte2Hex(ret));

            if (ret != null && ret[0] != 0) {

                byte[] data = new byte[ret.length - 2];

                for(int i = 2; i < ret.length; i++){
                    data[i - 2] = ret[i];
                }

                LOG.e(TAG, byte2Hex(data));

                retStr = new String(data);
            }
        }

        return retStr;
    }

    private String GetMainAccount(){
        LOG.e(TAG, "GetMainAccount");

        String retStr = null;

        //select EF 1001
        byte[] bRecData = new byte[256];
        byte[] bLen = new byte[2];
        byte[] EFID = new byte[8];
        EFID[0] = 0x10;
        EFID[1] = 0x01;

        int result = 0;
        byte[] ret = null;

        result = FISC_SelectEF(EFID);

        if(result == 0x9000) {

            ret = FISC_ReadRecord((byte)0x03, (byte)0x00);

            LOG.e(TAG, byte2Hex(ret));

            if (ret != null && ret[0] != 0) {

                byte[] data = new byte[ret.length - 2];

                for(int i = 2; i < ret.length; i++){
                    data[i - 2] = ret[i];
                }

                LOG.e(TAG, byte2Hex(data));

                retStr = new String(data);
            }
        }

        return retStr;
    }

    private int FISC_VerifyPIN(int bPq, byte[] baBuf){
        int uiSW12 = 0;
        int ulSendLen = 0;
        byte[] baSendBuf = new byte[64];
        byte[] baRecBuf = new byte[1024];
        int ulRecLen = baRecBuf.length;
        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = 0x20;
        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = (byte)bPq;
        baSendBuf[ulSendLen++] = 0x08;

        for(int i = 0; i < 8; i++){
            baSendBuf[ulSendLen++] = baBuf[i];
        }

        LOG.e(TAG, "ulSendLen: " + ulSendLen);
        LOG.e(TAG, "baSendBuf: " + byte2Hex(baSendBuf));

        try {

            int receiveLength = mReader.transmit(0, baSendBuf, ulSendLen, baRecBuf, ulRecLen);
//            int receiveLength = 0;

            if (receiveLength >= 2) {
                LOG.e(TAG, "receiveLength: " + receiveLength);
                LOG.e(TAG, "baRecBuf: " + byte2Hex(baRecBuf));

                int uiSW12_high = (baRecBuf[receiveLength-2] << 8) & 0xFFFF;
                int uiSW12_low = baRecBuf[receiveLength-1];

                LOG.e(TAG, "uiSW12_high: " + uiSW12_high);
                LOG.e(TAG, "uiSW12_low: " + uiSW12_low);

                uiSW12 = uiSW12_high | uiSW12_low;

                LOG.e(TAG, "result: " + uiSW12);
            }

        }catch (ReaderException e) {

            LOG.e(TAG, "FISC_VerifyPIN excption: " + e.toString());

        }

        return uiSW12;
    }

    public int VerifyPin(String pincode){

        int ret = 0;

        byte[] bPIN = null;
        String blankHexString = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        String pincode_hex = (pincode + blankHexString).substring(0, 16);
        LOG.e(TAG, "pincode hex string: " + pincode_hex);

        bPIN = hex2bin(pincode_hex);
        LOG.e(TAG, "bPIN: " + byte2Hex(bPIN));


        ret = FISC_VerifyPIN((0x02<<3), bPIN);

        return ret;
    }

    private int FISC_UpdateRecord(byte bRecID, byte bLen, byte[] baBuf)
    {
        LOG.e(TAG, "FISC_UpdateRecord");

        int uiSW12 = 0;
        int ulSendLen = 0;
        byte[] baSendBuf = new byte[64];
        byte[] baRecBuf = new byte[1024];
        int ulRecLen = baRecBuf.length;
        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = (byte)0xd2;
        baSendBuf[ulSendLen++] = bRecID;
        baSendBuf[ulSendLen++] = 0x04;
        baSendBuf[ulSendLen++] = bLen;

        for(int i = 0; i < bLen; i++){
            baSendBuf[ulSendLen++] = baBuf[i];
        }

        LOG.e(TAG, "baSendBuf: " + byte2Hex(baSendBuf));
        LOG.e(TAG, "ulSendLen: " + ulSendLen);

        try {


            int receiveLength = mReader.transmit(0, baSendBuf, ulSendLen, baRecBuf, ulRecLen);

            if(receiveLength >= 2){

                LOG.e(TAG, "receiveLength: " + receiveLength);
                LOG.e(TAG, "baRecBuf: " + byte2Hex(baRecBuf));

                int uiSW12_high = (baRecBuf[receiveLength-2] << 8) & 0xFFFF;
                int uiSW12_low = baRecBuf[receiveLength-1];

                LOG.e(TAG, "uiSW12_high: " + uiSW12_high);
                LOG.e(TAG, "uiSW12_low: " + uiSW12_low);

                uiSW12 = uiSW12_high | uiSW12_low;

                LOG.e(TAG, "result: " + uiSW12);

            }

        }catch (ReaderException e){

            LOG.e(TAG, "FISC_UpdateRecord excption: " + e.toString());

        }

        return uiSW12;
    }

    private int FISC_ChangePIN(byte bPq, byte[] baBuf){
        int uiSW12 = 0;
        byte[] EFID = new byte[32];
        EFID[0] = 0x00;
        EFID[1] = (byte)0xC2;

        int result = 0;

        result = FISC_SelectEF(EFID);

        if(result == 0x9000)
        {
            uiSW12 = FISC_UpdateRecord((byte)0x01, bPq, baBuf);
        }

        return uiSW12;
    }

    public int ChangePin(String newPin){
        int uiSW12 = 0;
        byte[] bPIN = null;
        String blankHexString = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        String newpincode_hex = (newPin + blankHexString).substring(0, 16);
        LOG.e(TAG, "newpincode_hex hex string: " + newpincode_hex);

        bPIN = hex2bin(newpincode_hex);
        LOG.e(TAG, "bPIN: " + byte2Hex(bPIN));

        uiSW12 = FISC_ChangePIN((byte)0x08, bPIN);

        return uiSW12;
    }

    private byte[] FISC_WriteRecordWithSNUMTAC(byte[] baP1P2, byte bLc, byte[] baBuf)
    {
        LOG.e(TAG, "FISC_WriteRecordWithSNUMTAC");

        int uiSW12 = 0;
        int ulSendLen = 0;
        byte[] baSendBuf = new byte[1024];
        byte[] baRecBuf = new byte[1024];
        int ulRecLen = baRecBuf.length;

        byte []result = null;

        baSendBuf[ulSendLen++] = 0x00;
        baSendBuf[ulSendLen++] = (byte)0xE2;
        baSendBuf[ulSendLen++] = baP1P2[0];
        baSendBuf[ulSendLen++] = baP1P2[1];
        baSendBuf[ulSendLen++] = bLc;

        for(int i = 0; i < bLc; i++){
            baSendBuf[ulSendLen++] = baBuf[i];
        }

        baSendBuf[ulSendLen++] =0x00;

        LOG.e(TAG, "baSendBuf: " + byte2Hex(baSendBuf));
        LOG.e(TAG, "ulSendLen: " + ulSendLen);

        try {


            int receiveLength = mReader.transmit(0, baSendBuf, ulSendLen, baRecBuf, ulRecLen);

            if(receiveLength >= 2){

                LOG.e(TAG, "receiveLength: " + receiveLength);
                LOG.e(TAG, "baRecBuf: " + byte2Hex(baRecBuf));

                int uiSW12_high = (baRecBuf[receiveLength-2] << 8) & 0xFFFF;
                int uiSW12_low = baRecBuf[receiveLength-1];

                LOG.e(TAG, "uiSW12_high: " + uiSW12_high);
                LOG.e(TAG, "uiSW12_low: " + uiSW12_low);

                uiSW12 = uiSW12_high | uiSW12_low;

                LOG.e(TAG, "result: " + uiSW12);

                result = new byte[receiveLength - 2];

                for (int i = 0; i < (receiveLength - 2); i++) {
                    result[i] = baRecBuf[i];
                }

            }

        }catch (ReaderException e){

            LOG.e(TAG, "FISC_UpdateRecord excption: " + e.toString());

        }

        return result;
    }

    public JSONObject parseTSAC(byte[] in) throws JSONException
    {
        JSONObject ret = new JSONObject();

        long rtn = 0;

        String SNUM = null;
        String TSAC = null;
        byte[] bSNUM = null;
        byte[] bTSAC = null;

        //in sample: 08 30 30 30 30 30 31 35 36 00 08 EF FA DF 0A 50 08 FA 4D

        //get SNUM
        int length = in[0];
        bSNUM = new byte[length];

        for(int i = 0; i < length; i++){
            bSNUM[i] = in[i + 1];
        }

        int offset = 1 + length;
        length = in[offset] * 16 + in[offset + 1];
        offset += 2;

        bTSAC = new byte[length];

        for(int i = 0; i < length; i++){
            bTSAC[i] = in[offset + i];
        }

        SNUM = new String(bSNUM);
        TSAC = bin2hex(bTSAC);

        ret.put("serial", SNUM);
        ret.put("tac", TSAC);


        return ret;
    }

    private void clearCardInfo(){
        mIssuer = null;
        mMainAccount = null;
        mPin = null;
    }

}

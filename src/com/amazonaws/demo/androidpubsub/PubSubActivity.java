/**
 * Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://aws.amazon.com/apache2.0
 *
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and
 * limitations under the License.
 */

package com.amazonaws.demo.androidpubsub;

import android.annotation.TargetApi;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.amazonaws.auth.CognitoCachingCredentialsProvider;
import com.amazonaws.mobileconnectors.iot.AWSIotKeystoreHelper;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttClientStatusCallback;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttLastWillAndTestament;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttManager;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttNewMessageCallback;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttQos;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

@TargetApi(18)


public class PubSubActivity extends Activity {

    static final String LOG_TAG = PubSubActivity.class.getCanonicalName();
    DateFormat df = new SimpleDateFormat("dd/MM/yy HH:mm:ss");


    // --- Constants to modify per your configuration ---

    // IoT endpoint
    // AWS Iot CLI describe-endpoint call returns: XXXXXXXXXX.iot.<region>.amazonaws.com
    private static final String CUSTOMER_SPECIFIC_ENDPOINT = "a1y7d41s0oj85v.iot.us-east-1.amazonaws.com";
    // Cognito pool ID. For this app, pool needs to be unauthenticated pool with
    // AWS IoT permissions.
    private static final String COGNITO_POOL_ID = "us-east-1:a21a5917-5f3b-47e5-8111-daa8992b6604";
    // Name of the AWS IoT policy to attach to a newly created certificate
    private static final String AWS_IOT_POLICY_NAME = "AndroidAppP001";

    // Region of AWS IoT
    private static final Regions MY_REGION = Regions.US_EAST_1;
    // Filename of KeyStore file on the filesystem
    private static final String KEYSTORE_NAME = "iot_keystore";
    // Password for the private key in the KeyStore
    private static final String KEYSTORE_PASSWORD = "password";
    // Certificate and key aliases in the KeyStore
    private static final String CERTIFICATE_ID = "default";

    EditText txtSubcribe;
    EditText txtTopic;
    EditText txtMessage;

    TextView tvLastMessage;
    TextView tvClientId;
    TextView tvStatus;

    Button btnConnect;
    Button btnSubscribe;
    Button btnPublish;
    Button btnDisconnect;

    AWSIotClient mIotAndroidClient;
    AWSIotMqttManager mqttManager;
    String clientId;
    String keystorePath;
    String keystoreName;
    String keystorePassword;

    KeyStore clientKeyStore = null;
    String certificateId;

    CognitoCachingCredentialsProvider credentialsProvider;

    private BluetoothAdapter mBluetoothAdapter;
    private long mAdvertisementCount = 0;


    public byte[] getSensmitterData() {
        return SensmitterData;
    }

    public void setSensmitterData(byte[] sensmitterData) {
        SensmitterData = sensmitterData;
    }

    public byte[] getSensmitterDataD9() {
        return SensmitterDataD9;
    }

    public void setSensmitterDataD9(byte[] sensmitterDataD9) {
        SensmitterDataD9 = sensmitterDataD9;
    }

    public byte[] getSensmitterDataE9() {
        return SensmitterDataE9;
    }

    public void setSensmitterDataE9(byte[] sensmitterDataE9) {
        SensmitterDataE9 = sensmitterDataE9;
    }

    public byte[] getSensmitterDataF3() {
        return SensmitterDataF3;
    }

    public void setSensmitterDataF3(byte[] sensmitterDataF3) {
        SensmitterDataF3 = sensmitterDataF3;
    }

    static  private byte[] SensmitterData;

    static  public byte[] SensmitterDataD9;
    static private byte[] SensmitterDataF3;
    static private byte[] SensmitterDataE9;


    private BluetoothAdapter.LeScanCallback mLeScanCallback =
            new BluetoothAdapter.LeScanCallback() {



                @Override
                public void onLeScan(final BluetoothDevice device, int rssi,
                                     byte[] scanRecord) {

                    StringBuilder sb = new StringBuilder();
                    for(byte b : scanRecord) {
                        sb.append(IntToHex2(b & 0xff));

                    }

                    if ((device.getAddress().contains("D9:1C:71:34:A1:C3"))) {

                        setSensmitterDataD9(scanRecord);

                    } else if ((device.getAddress().contains("F3:E5:7F:73:4F:81"))) {
                        setSensmitterDataF3(scanRecord);
                    } else if ((device.getAddress().contains("E9:3F:38:D8:45:AE"))) {
                        setSensmitterDataE9(scanRecord);
                    }





                    Log.d("asdasd",getSensmitterDataD9()+" "+getSensmitterDataE9()+" "+getSensmitterDataF3());





                }
            };

    public static String IntToHex2(int i) {
        char hex_2[] = {Character.forDigit((i>>4) & 0x0f,16),Character.forDigit(i&0x0f, 16)};
        String hex_2_str = new String(hex_2);
        return hex_2_str.toUpperCase();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // BLE
        final BluetoothManager bluetoothManager =
                (BluetoothManager) getSystemService(this.BLUETOOTH_SERVICE);
        mBluetoothAdapter = bluetoothManager.getAdapter();
        mBluetoothAdapter.startLeScan(mLeScanCallback);

        txtSubcribe = (EditText) findViewById(R.id.txtSubcribe);
        txtTopic = (EditText) findViewById(R.id.txtTopic);
        txtMessage = (EditText) findViewById(R.id.txtMessage);

        tvLastMessage = (TextView) findViewById(R.id.tvLastMessage);
        tvClientId = (TextView) findViewById(R.id.tvClientId);
        tvStatus = (TextView) findViewById(R.id.tvStatus);

        btnConnect = (Button) findViewById(R.id.btnConnect);
        btnConnect.setOnClickListener(connectClick);
        btnConnect.setEnabled(false);

        btnSubscribe = (Button) findViewById(R.id.btnSubscribe);
        btnSubscribe.setOnClickListener(subscribeClick);

        btnPublish = (Button) findViewById(R.id.btnPublish);
        btnPublish.setOnClickListener(publishClick);

        btnDisconnect = (Button) findViewById(R.id.btnDisconnect);
        btnDisconnect.setOnClickListener(disconnectClick);

        // MQTT client IDs are required to be unique per AWS IoT account.
        // This UUID is "practically unique" but does not _guarantee_
        // uniqueness.
        clientId = UUID.randomUUID().toString();
        tvClientId.setText(clientId);

        // Initialize the AWS Cognito credentials provider
        credentialsProvider = new CognitoCachingCredentialsProvider(
                getApplicationContext(), // context
                COGNITO_POOL_ID, // Identity Pool ID
                MY_REGION // Region
        );

        Region region = Region.getRegion(MY_REGION);

        // MQTT Client
        mqttManager = new AWSIotMqttManager(clientId, CUSTOMER_SPECIFIC_ENDPOINT);

        // Set keepalive to 10 seconds.  Will recognize disconnects more quickly but will also send
        // MQTT pings every 10 seconds.
        mqttManager.setKeepAlive(10);

        // Set Last Will and Testament for MQTT.  On an unclean disconnect (loss of connection)
        // AWS IoT will publish this message to alert other clients.
        AWSIotMqttLastWillAndTestament lwt = new AWSIotMqttLastWillAndTestament("my/lwt/topic",
                "Android client lost connection", AWSIotMqttQos.QOS0);
        mqttManager.setMqttLastWillAndTestament(lwt);

        // IoT Client (for creation of certificate if needed)
        mIotAndroidClient = new AWSIotClient(credentialsProvider);
        mIotAndroidClient.setRegion(region);

        keystorePath = getFilesDir().getPath();
        keystoreName = KEYSTORE_NAME;
        keystorePassword = KEYSTORE_PASSWORD;
        certificateId = CERTIFICATE_ID;

        // To load cert/key from keystore on filesystem
        try {
            if (AWSIotKeystoreHelper.isKeystorePresent(keystorePath, keystoreName)) {
                if (AWSIotKeystoreHelper.keystoreContainsAlias(certificateId, keystorePath,
                        keystoreName, keystorePassword)) {
                    Log.i(LOG_TAG, "Certificate " + certificateId
                            + " found in keystore - using for MQTT.");
                    // load keystore from file into memory to pass on connection
                    clientKeyStore = AWSIotKeystoreHelper.getIotKeystore(certificateId,
                            keystorePath, keystoreName, keystorePassword);
                    btnConnect.setEnabled(true);
                } else {
                    Log.i(LOG_TAG, "Key/cert " + certificateId + " not found in keystore.");
                }
            } else {
                Log.i(LOG_TAG, "Keystore " + keystorePath + "/" + keystoreName + " not found.");
            }
        } catch (Exception e) {
            Log.e(LOG_TAG, "An error occurred retrieving cert/key from keystore.", e);
        }

        if (clientKeyStore == null) {
            Log.i(LOG_TAG, "Cert/key was not found in keystore - creating new key and certificate.");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Create a new private key and certificate. This call
                        // creates both on the server and returns them to the
                        // device.
                        CreateKeysAndCertificateRequest createKeysAndCertificateRequest =
                                new CreateKeysAndCertificateRequest();
                        createKeysAndCertificateRequest.setSetAsActive(true);
                        final CreateKeysAndCertificateResult createKeysAndCertificateResult;
                        createKeysAndCertificateResult =
                                mIotAndroidClient.createKeysAndCertificate(createKeysAndCertificateRequest);
                        Log.i(LOG_TAG,
                                "Cert ID: " +
                                        createKeysAndCertificateResult.getCertificateId() +
                                        " created.");

                        // store in keystore for use in MQTT client
                        // saved as alias "default" so a new certificate isn't
                        // generated each run of this application
                        AWSIotKeystoreHelper.saveCertificateAndPrivateKey(certificateId,
                                createKeysAndCertificateResult.getCertificatePem(),
                                createKeysAndCertificateResult.getKeyPair().getPrivateKey(),
                                keystorePath, keystoreName, keystorePassword);

                        // load keystore from file into memory to pass on
                        // connection
                        clientKeyStore = AWSIotKeystoreHelper.getIotKeystore(certificateId,
                                keystorePath, keystoreName, keystorePassword);

                        // Attach a policy to the newly created certificate.
                        // This flow assumes the policy was already created in
                        // AWS IoT and we are now just attaching it to the
                        // certificate.
                        AttachPrincipalPolicyRequest policyAttachRequest =
                                new AttachPrincipalPolicyRequest();
                        policyAttachRequest.setPolicyName(AWS_IOT_POLICY_NAME);
                        policyAttachRequest.setPrincipal(createKeysAndCertificateResult
                                .getCertificateArn());
                        mIotAndroidClient.attachPrincipalPolicy(policyAttachRequest);

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                btnConnect.setEnabled(true);
                            }
                        });
                    } catch (Exception e) {
                        Log.e(LOG_TAG,
                                "Exception occurred when generating new private key and certificate.",
                                e);
                    }
                }
            }).start();
        }
        //publishBLE();
    }


    View.OnClickListener connectClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            Log.d(LOG_TAG, "clientId = " + clientId);

            try {
                mqttManager.connect(clientKeyStore, new AWSIotMqttClientStatusCallback() {
                    @Override
                    public void onStatusChanged(final AWSIotMqttClientStatus status,
                            final Throwable throwable) {
                        Log.d(LOG_TAG, "Status = " + String.valueOf(status));

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                if (status == AWSIotMqttClientStatus.Connecting) {
                                    tvStatus.setText("Connecting...");

                                } else if (status == AWSIotMqttClientStatus.Connected) {
                                    tvStatus.setText("Connected");
                                        Timer timer = new Timer();
                                        timer.scheduleAtFixedRate(new SendTimerTask(), 1000, 1000);



                                } else if (status == AWSIotMqttClientStatus.Reconnecting) {
                                    if (throwable != null) {
                                        Log.e(LOG_TAG, "Connection error.", throwable);
                                    }
                                    tvStatus.setText("Reconnecting");
                                } else if (status == AWSIotMqttClientStatus.ConnectionLost) {
                                    if (throwable != null) {
                                        Log.e(LOG_TAG, "Connection error.", throwable);
                                    }
                                    tvStatus.setText("Disconnected");
                                } else {
                                    tvStatus.setText("Disconnected");

                                }
                            }
                        });
                    }
                });
            } catch (final Exception e) {
                Log.e(LOG_TAG, "Connection error.", e);
                tvStatus.setText("Error! " + e.getMessage());
            }
        }
    };

    View.OnClickListener subscribeClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            final String topic = txtSubcribe.getText().toString();

            Log.d(LOG_TAG, "topic = " + topic);

            try {
                mqttManager.subscribeToTopic(topic, AWSIotMqttQos.QOS0,
                        new AWSIotMqttNewMessageCallback() {
                            @Override
                            public void onMessageArrived(final String topic, final byte[] data) {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            String message = new String(data, "UTF-8");
                                            Log.d(LOG_TAG, "Message arrived:");
                                            Log.d(LOG_TAG, "   Topic: " + topic);
                                            Log.d(LOG_TAG, " Message: " + message);

                                            tvLastMessage.setText(message);

                                        } catch (UnsupportedEncodingException e) {
                                            Log.e(LOG_TAG, "Message encoding error.", e);
                                        }
                                    }
                                });
                            }
                        });
            } catch (Exception e) {
                Log.e(LOG_TAG, "Subscription error.", e);
            }
        }
    };

    View.OnClickListener publishClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            final String topic = txtTopic.getText().toString();
            final String msg = txtMessage.getText().toString();

            try {
                mqttManager.publishString(msg, topic, AWSIotMqttQos.QOS0);
            } catch (Exception e) {
                Log.e(LOG_TAG, "Publish error.", e);
            }

        }
    };

    View.OnClickListener disconnectClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            try {
                mqttManager.disconnect();
            } catch (Exception e) {
                Log.e(LOG_TAG, "Disconnect error.", e);
            }

        }
    };

    private class SendTimerTask extends TimerTask {
        @Override
        public void run() {
            try {
                mqttManager.publishString(getSensmitterDataJSON(getSensmitterDataF3()), "F3", AWSIotMqttQos.QOS0);
                mqttManager.publishString(getSensmitterDataJSON(getSensmitterDataE9()), "E9", AWSIotMqttQos.QOS0);

                mqttManager.publishString(getSensmitterDataJSON(getSensmitterDataD9()), "D9", AWSIotMqttQos.QOS0);

                //Log.d("aassdd",tvStatus.getText()+"");
            } catch (Exception e) {
                Log.e(LOG_TAG, "Publish error.", e);
            }
        }
    }


    public  String getSensmitterDataJSON( byte[] state) {

        String modelName;
        String jsonMessage ="";
        Date dateobj = new Date();
        String datetime=df.format(dateobj);


        StringBuilder name1 = new StringBuilder();
        name1.append(IntToHex2(state[33] & 0xff));
        name1.append(IntToHex2(state[34] & 0xff));

        StringBuilder value1 = new StringBuilder();
        value1.append(IntToHex2(state[35] & 0xff));
        value1.append(IntToHex2(state[36] & 0xff));

        Integer temp = Integer.parseInt(value1.toString(), 16);
        float tempV=temp/10.00f;


        StringBuilder name2 = new StringBuilder();
        name2.append(IntToHex2(state[37] & 0xff));
        name2.append(IntToHex2(state[38] & 0xff));

        StringBuilder value2 = new StringBuilder();
        value2.append(IntToHex2(state[39] & 0xff));
        value2.append(IntToHex2(state[40] & 0xff));

        Integer humidity = Integer.parseInt(value2.toString(), 16);
        float humidityV=humidity/10.00f;

        StringBuilder name3 = new StringBuilder();
        name3.append(IntToHex2(state[41] & 0xff));
        name3.append(IntToHex2(state[42] & 0xff));

        StringBuilder value3 = new StringBuilder();
        value3.append(IntToHex2(state[43] & 0xff));
        value3.append(IntToHex2(state[44] & 0xff));

        Integer light = Integer.parseInt(value3.toString(), 16);


        StringBuilder name4 = new StringBuilder();
        name4.append(IntToHex2(state[45] & 0xff));
        name4.append(IntToHex2(state[46] & 0xff));
        float valueD=0.00f;
        if(name4.toString().equals("0008")){
            StringBuilder value4 = new StringBuilder();

            value4.append(IntToHex2(state[47] & 0xff));

            valueD = Integer.parseInt(value4.toString(), 16);

        }
        else if(name4.toString().equals("0009")){
            StringBuilder value4 = new StringBuilder();
            value4.append(IntToHex2(state[47] & 0xff));
            value4.append(IntToHex2(state[48] & 0xff));

            valueD = Integer.parseInt(value4.toString(), 16)/10.00f;
        }


        if(state==getSensmitterDataD9()){
            modelName="D9";
            jsonMessage="{\"d\":{" +
                    "\""+modelName+"Temp\":\"" + tempV + "\"," +
                    "\""+modelName+"Humidity\":\"" + humidityV + "\"," +
                    "\""+modelName+"LightLvl\":\"" + light + "\"," +
                    "\""+modelName+"PIR\":\"" + valueD + "\"," +
                    "\"D9Time\":\"" + datetime + "\"" +
                    " } }";
        }
        else if(state==getSensmitterDataE9()){
            modelName="E9";
            jsonMessage="{\"d\":{" +
                    "\""+modelName+"Temp\":\"" + tempV + "\"," +
                    "\""+modelName+"Humidity\":\"" + humidityV + "\"," +
                    "\""+modelName+"LightLvl\":\"" + light + "\"," +
                    "\""+modelName+"PIR\":\"" + valueD + "\"," +
                    "\"E9Time\":\"" + datetime + "\"" +
                    " } }";
        }
        else if(state==getSensmitterDataF3()){
            modelName="F3";
            jsonMessage="{\"d\":{" +
                    "\""+modelName+"Temp\":\"" + tempV + "\"," +
                    "\""+modelName+"Humidity\":\"" + humidityV + "\"," +
                    "\""+modelName+"LightLvl\":\"" + light + "\"," +
                    "\""+modelName+"Pressure\":\"" + valueD + "\"," +
                    "\"F3Time\":\"" + datetime + "\"" +
                    " } }";
        }
        return jsonMessage;
    }
}

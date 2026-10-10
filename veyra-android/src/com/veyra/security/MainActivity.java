package com.veyra.security;

import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.util.Locale;

public class MainActivity extends Activity {
    public static final int SMS_PERMISSION_REQ = 101;
    public static final int NOTIF_PERMISSION_REQ = 102;

    private WebView webView;
    private DatabaseHelper dbHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        dbHelper = DatabaseHelper.getInstance(this);

        // Apply saved language before layout inflation
        applySavedLanguage();

        setContentView(R.layout.activity_main);

        // Create Android Notification Channels
        createNotificationChannels();

        // Setup WebView
        webView = findViewById(R.id.webView);
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setLoadsImagesAutomatically(true);

        // Add Native Bridge
        VeyraNativeBridge bridge = new VeyraNativeBridge(this);
        webView.addJavascriptInterface(bridge, "VeyraNative");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                handleIncomingIntent(getIntent());
            }
        });

        // Load local on-device UI
        webView.loadUrl("file:///android_asset/ui/index.html");
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent != null && intent.hasExtra("finding_id") && webView != null) {
            long findingId = intent.getLongExtra("finding_id", -1);
            String action = intent.getStringExtra("action");
            if (action == null) action = "view_details";
            webView.evaluateJavascript("if (window.handleNotificationClick) window.handleNotificationClick(" + findingId + ", '" + action + "');", null);
        }
    }

    private void createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                // High priority threat alert channel
                NotificationChannel alertChannel = new NotificationChannel(
                        "veyra_security_alerts",
                        getString(R.string.channel_alerts_name),
                        NotificationManager.IMPORTANCE_HIGH
                );
                alertChannel.setDescription(getString(R.string.channel_alerts_desc));
                alertChannel.enableVibration(true);
                alertChannel.setVibrationPattern(new long[]{0, 400, 200, 400});
                nm.createNotificationChannel(alertChannel);

                // Service status channel
                NotificationChannel statusChannel = new NotificationChannel(
                        "veyra_service_status",
                        getString(R.string.channel_status_name),
                        NotificationManager.IMPORTANCE_LOW
                );
                statusChannel.setDescription(getString(R.string.channel_status_desc));
                nm.createNotificationChannel(statusChannel);
            }
        }
    }

    public void requestSmsPermission() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (Build.VERSION.SDK_INT >= 23) {
                    requestPermissions(new String[]{"android.permission.RECEIVE_SMS"}, SMS_PERMISSION_REQ);
                }
            }
        });
    }

    public void requestNotificationPermission() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (Build.VERSION.SDK_INT >= 33) {
                    requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, NOTIF_PERMISSION_REQ);
                } else {
                    openAppDetailsSettings();
                }
            }
        });
    }

    public void openAppDetailsSettings() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } catch (Exception e) {
                    Intent intent = new Intent(Settings.ACTION_SETTINGS);
                    startActivity(intent);
                }
            }
        });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean isGranted = (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED);

        if (requestCode == SMS_PERMISSION_REQ) {
            if (isGranted) {
                dbHelper.setSetting("sms_protection_enabled", "1");
            }
            if (webView != null) {
                webView.evaluateJavascript("if (window.onPermissionResult) window.onPermissionResult('sms', " + isGranted + ");", null);
            }
        } else if (requestCode == NOTIF_PERMISSION_REQ) {
            if (webView != null) {
                webView.evaluateJavascript("if (window.onPermissionResult) window.onPermissionResult('notification', " + isGranted + ");", null);
            }
        }
    }

    public void changeLanguage(String langCode) {
        dbHelper.setSetting("selected_language", langCode);
        applyLanguage(langCode);
        if (webView != null) {
            webView.evaluateJavascript("if (window.setUiLanguage) window.setUiLanguage('" + langCode + "');", null);
        }
    }

    private void applySavedLanguage() {
        String lang = dbHelper.getSetting("selected_language", "en");
        applyLanguage(lang);
    }

    private void applyLanguage(String langCode) {
        Locale locale = new Locale(langCode);
        Locale.setDefault(locale);
        Resources res = getResources();
        Configuration config = new Configuration(res.getConfiguration());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            config.setLocale(locale);
        } else {
            config.locale = locale;
        }
        res.updateConfiguration(config, res.getDisplayMetrics());
    }

    @Override
    public void onBackPressed() {
        if (webView != null) {
            webView.evaluateJavascript("if (window.handleBackPress && window.handleBackPress()) { true; } else { false; }",
                    new android.webkit.ValueCallback<String>() {
                        @Override
                        public void onReceiveValue(String value) {
                            if (!"true".equals(value)) {
                                MainActivity.super.onBackPressed();
                            }
                        }
                    });
        } else {
            super.onBackPressed();
        }
    }
}

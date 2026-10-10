package com.veyra.security;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;
import org.json.JSONArray;
import org.json.JSONObject;

public class SecurityCheckupManager {
    private final Context context;

    public SecurityCheckupManager(Context context) {
        this.context = context;
    }

    public JSONObject runCheckup() {
        JSONObject result = new JSONObject();
        JSONArray checks = new JSONArray();
        int passedCount = 0;
        int totalChecks = 3;

        try {
            // 1. Screen Lock / Keyguard Check
            KeyguardManager km = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            boolean isLockSecure = (km != null && km.isDeviceSecure());
            JSONObject check1 = new JSONObject();
            check1.put("id", "screen_lock");
            check1.put("title", "Screen Lock & Biometric Protection");
            check1.put("passed", isLockSecure);
            check1.put("status", isLockSecure ? "Configured (PIN/Biometrics Active)" : "Not Configured (Device Unlocked)");
            check1.put("recommendation", isLockSecure ? "Device authentication is active." : "Enable a PIN, password, or fingerprint to prevent physical device theft.");
            check1.put("action_intent", Settings.ACTION_SECURITY_SETTINGS);
            checks.put(check1);
            if (isLockSecure) passedCount++;

            // 2. Notification Listener Permission Check
            boolean isNotificationAccessGranted = isNotificationServiceEnabled();
            JSONObject check2 = new JSONObject();
            check2.put("id", "notification_access");
            check2.put("title", "Real-Time Scam Notification Shield");
            check2.put("passed", isNotificationAccessGranted);
            check2.put("status", isNotificationAccessGranted ? "Enabled (Monitoring Active)" : "Permission Disabled");
            check2.put("recommendation", isNotificationAccessGranted ? "VEYRA is actively scanning supported incoming alerts." : "Grant notification access in Settings to enable real-time threat alerts.");
            check2.put("action_intent", "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS");
            checks.put(check2);
            if (isNotificationAccessGranted) passedCount++;

            // 3. Developer Options Check
            int devOptions = 0;
            try {
                devOptions = Settings.Global.getInt(context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
            } catch (Exception ignored) {}
            boolean devOptionsSafe = (devOptions == 0);
            JSONObject check3 = new JSONObject();
            check3.put("id", "developer_options");
            check3.put("title", "Developer Options & USB Debugging");
            check3.put("passed", devOptionsSafe);
            check3.put("status", devOptionsSafe ? "Disabled (Recommended Posture)" : "Enabled (Elevated Attack Surface)");
            check3.put("recommendation", devOptionsSafe ? "Standard Android security sandbox maintained." : "Disable developer options if not actively testing code to prevent ADB abuse.");
            check3.put("action_intent", Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
            checks.put(check3);
            if (devOptionsSafe) passedCount++;

            result.put("passedCount", passedCount);
            result.put("totalChecks", totalChecks);
            result.put("checks", checks);
            result.put("overallScore", (int) ((passedCount / (double) totalChecks) * 100));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public boolean isNotificationServiceEnabled() {
        String pkgName = context.getPackageName();
        final String flat = Settings.Secure.getString(context.getContentResolver(), "enabled_notification_listeners");
        if (flat != null && !flat.isEmpty()) {
            final String[] names = flat.split(":");
            for (String name : names) {
                if (name.contains(pkgName)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isSmsPermissionGranted() {
        return context.checkSelfPermission("android.permission.RECEIVE_SMS") == android.content.pm.PackageManager.PERMISSION_GRANTED;
    }

    public boolean isPostNotificationsGranted() {
        if (Build.VERSION.SDK_INT >= 33) {
            return context.checkSelfPermission("android.permission.POST_NOTIFICATIONS") == android.content.pm.PackageManager.PERMISSION_GRANTED;
        } else {
            android.app.NotificationManager nm = (android.app.NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            return nm != null && nm.areNotificationsEnabled();
        }
    }
}

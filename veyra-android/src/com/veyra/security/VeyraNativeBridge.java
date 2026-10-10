package com.veyra.security;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.webkit.JavascriptInterface;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.List;

public class VeyraNativeBridge {
    private final MainActivity activity;
    private final DetectionEngine detectionEngine;
    private final DatabaseHelper dbHelper;
    private final SecurityCheckupManager checkupManager;
    private final AuthManager authManager;

    public VeyraNativeBridge(MainActivity activity) {
        this.activity = activity;
        this.detectionEngine = DetectionEngine.getInstance(activity);
        this.dbHelper = DatabaseHelper.getInstance(activity);
        this.checkupManager = new SecurityCheckupManager(activity);
        this.authManager = new AuthManager(activity);
    }

    // --- Device Setup & Installation Identification ---

    @JavascriptInterface
    public String getInstallationId() {
        return dbHelper.getInstallationId();
    }

    @JavascriptInterface
    public String getDeviceInfo() {
        return dbHelper.getDeviceInfo().toString();
    }

    @JavascriptInterface
    public void completeDeviceSetup() {
        dbHelper.completeDeviceSetup();
    }

    // --- Core Scan & Threat Evaluation ---

    @JavascriptInterface
    public String scanContent(String text) {
        dbHelper.incrementMetric("manual_scans_completed");
        dbHelper.incrementMetric("messages_checked");

        DetectionEngine.ScanResult result = detectionEngine.analyze(text, null);

        long findingId = -1;
        String actionStatus = "Safe";
        String threatType = "Normal Message";

        if ("HIGH".equals(result.riskLevel)) {
            dbHelper.incrementMetric("high_risk_alerts");
            if ("PHISHING".equals(result.predictedClass)) {
                dbHelper.incrementMetric("phishing_found");
                threatType = "Phishing Link/Message";
            } else {
                dbHelper.incrementMetric("scams_found");
                threatType = "Possible Scam";
            }
            actionStatus = "High Risk Warning";
        } else if ("MEDIUM".equals(result.riskLevel)) {
            if ("PHISHING".equals(result.predictedClass)) {
                dbHelper.incrementMetric("phishing_found");
                threatType = "Suspicious Link";
            } else {
                dbHelper.incrementMetric("scams_found");
                threatType = "Suspicious Message";
            }
            actionStatus = "Suspicious Warning";
        } else {
            dbHelper.incrementMetric("normal_messages");
            actionStatus = "Safe";
            threatType = "Normal Content";
        }

        findingId = dbHelper.saveFinding(
                "Scam Check",
                result.riskLevel,
                result.riskScore,
                threatType,
                result.indicators,
                actionStatus
        );

        JSONObject res = result.toJson();
        try {
            res.put("findingId", findingId);
        } catch (Exception ignored) {}
        return res.toString();
    }

    @JavascriptInterface
    public String scanEmail(String emailText) {
        dbHelper.incrementMetric("manual_scans_completed");
        dbHelper.incrementMetric("messages_checked");

        DetectionEngine.ScanResult result = detectionEngine.analyze(emailText, null);

        // Check for common phishing email traits
        String lower = emailText.toLowerCase();
        if (lower.contains("wire transfer") || lower.contains("reply-to:") || lower.contains("payroll") || lower.contains("ceo")) {
            if (!result.indicators.contains("Potential display name or reply-to mismatch")) {
                result.indicators.add("Potential display name or reply-to mismatch");
            }
        }

        String threatType = "Email Submission";
        String actionStatus = "Safe";
        if ("HIGH".equals(result.riskLevel)) {
            dbHelper.incrementMetric("high_risk_alerts");
            dbHelper.incrementMetric("phishing_found");
            threatType = "Phishing Email";
            actionStatus = "High Risk Warning";
        } else if ("MEDIUM".equals(result.riskLevel)) {
            dbHelper.incrementMetric("phishing_found");
            threatType = "Suspicious Email";
            actionStatus = "Suspicious Warning";
        } else {
            dbHelper.incrementMetric("normal_messages");
        }

        long findingId = dbHelper.saveFinding(
                "Email Guard",
                result.riskLevel,
                result.riskScore,
                threatType,
                result.indicators,
                actionStatus
        );

        JSONObject res = result.toJson();
        try {
            res.put("findingId", findingId);
            res.put("isEmailAnalysis", true);
            res.put("blockingNotice", "Analysis completed locally on device. Provider-level mailbox blocking is not available via standard Android permissions. The email itself has not been blocked.");
        } catch (Exception ignored) {}
        return res.toString();
    }

    // --- Live Event-Based Dashboard Summary ---

    @JavascriptInterface
    public String getDashboardSummary() {
        boolean notifGranted = checkupManager.isPostNotificationsGranted();
        boolean smsGranted = checkupManager.isSmsPermissionGranted();
        return dbHelper.getDashboardSummary(notifGranted, smsGranted).toString();
    }

    // --- SMS Protection & Permissions Controls ---

    @JavascriptInterface
    public boolean isSmsPermissionGranted() {
        return checkupManager.isSmsPermissionGranted();
    }

    @JavascriptInterface
    public boolean isNotificationPermissionGranted() {
        return checkupManager.isPostNotificationsGranted();
    }

    @JavascriptInterface
    public boolean isSmsProtectionEnabled() {
        return "1".equals(dbHelper.getSetting("sms_protection_enabled", "1"));
    }

    @JavascriptInterface
    public void setSmsProtectionEnabled(boolean enabled) {
        dbHelper.setSetting("sms_protection_enabled", enabled ? "1" : "0");
    }

    @JavascriptInterface
    public void requestSmsPermission() {
        activity.requestSmsPermission();
    }

    @JavascriptInterface
    public void requestNotificationPermission() {
        activity.requestNotificationPermission();
    }

    @JavascriptInterface
    public void openAppDetailsSettings() {
        activity.openAppDetailsSettings();
    }

    // --- Notification & Protection Posture ---

    @JavascriptInterface
    public String getNotificationStatus() {
        JSONObject status = new JSONObject();
        try {
            boolean isPermissionGranted = checkupManager.isPostNotificationsGranted();
            boolean isSmsGranted = checkupManager.isSmsPermissionGranted();
            boolean isConnected = VeyraNotificationService.isConnected();
            boolean isPaused = dbHelper.isMonitoringPaused();
            boolean smsEnabled = isSmsProtectionEnabled();

            status.put("isPermissionGranted", isPermissionGranted);
            status.put("isSmsPermissionGranted", isSmsGranted);
            status.put("isSmsProtectionEnabled", smsEnabled);
            status.put("isConnected", isConnected);
            status.put("isPaused", isPaused);
            status.put("supportedSources", new JSONArray(Arrays.asList("SMS Messages", "WhatsApp", "Telegram", "Email Alerts", "Banking Notifications", "Courier Tracking")));
            status.put("unsupportedSources", new JSONArray(Arrays.asList("Private In-App Encrypted Chat DBs", "Accessibility Keystroke Loggers")));
            status.put("coverageExplanation", "VEYRA detects incoming SMS messages locally via Android's official Telephony API and inspects active notifications on-device. Zero personal message content leaves your phone.");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return status.toString();
    }

    @JavascriptInterface
    public void openNotificationSettings() {
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    Intent intent = new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS");
                    activity.startActivity(intent);
                } catch (Exception e) {
                    Intent intent = new Intent(Settings.ACTION_SETTINGS);
                    activity.startActivity(intent);
                }
            }
        });
    }

    @JavascriptInterface
    public String getPermissionStatuses() {
        JSONObject perms = new JSONObject();
        try {
            boolean notifPost = checkupManager.isPostNotificationsGranted();
            boolean notifAccess = checkupManager.isNotificationServiceEnabled();
            boolean smsGranted = checkupManager.isSmsPermissionGranted();
            boolean smsEnabled = isSmsProtectionEnabled();

            perms.put("notificationAccess", notifAccess ? "Enabled" : "Allow Access");
            perms.put("notificationPermission", notifPost ? "Enabled" : "Allow Access");
            perms.put("smsFunctionality", (smsGranted && smsEnabled) ? "Enabled" : (smsGranted ? "Paused" : "Allow Access"));
            perms.put("linkScanning", "Enabled");
            perms.put("emailIntegration", "Checked on Your Phone");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return perms.toString();
    }

    // --- Notification Preferences ---

    @JavascriptInterface
    public String getNotificationSettings() {
        return dbHelper.getNotificationSettings().toString();
    }

    @JavascriptInterface
    public void saveNotificationSettings(String jsonStr) {
        try {
            JSONObject obj = new JSONObject(jsonStr);
            dbHelper.saveNotificationSettings(obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- Appearance & Theme ---

    @JavascriptInterface
    public String getThemePreference() {
        return dbHelper.getThemePreference();
    }

    @JavascriptInterface
    public void setThemePreference(String theme) {
        dbHelper.setThemePreference(theme);
    }

    // --- Safety Checkup & Incident Recovery ---

    @JavascriptInterface
    public String runSecurityCheckup() {
        return checkupManager.runCheckup().toString();
    }

    @JavascriptInterface
    public void openSecuritySetting(final String actionIntent) {
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    Intent intent = new Intent(actionIntent);
                    activity.startActivity(intent);
                } catch (Exception e) {
                    Intent intent = new Intent(Settings.ACTION_SETTINGS);
                    activity.startActivity(intent);
                }
            }
        });
    }

    @JavascriptInterface
    public String getIncidentAdvice(String incidentType) {
        dbHelper.incrementMetric("recovery_workflows_opened");
        return IncidentRecoveryManager.getRecoveryGuidance(incidentType).toString();
    }

    // --- Findings & Threat History ---

    @JavascriptInterface
    public String getFindingsHistory(int limit) {
        return dbHelper.getFindings(limit).toString();
    }

    @JavascriptInterface
    public void clearHistory() {
        dbHelper.clearHistory();
    }

    @JavascriptInterface
    public void submitFeedback(String feedbackType, long findingId) {
        dbHelper.recordFeedback(feedbackType, findingId);
    }

    // --- Authentication & Access Control ---

    @JavascriptInterface
    public String login(String username, String password) {
        JSONObject res = authManager.login(username, password);
        try {
            if (res.optBoolean("success", false)) {
                dbHelper.recordAccessLog("LOGIN_SUCCESS", "AUTH_PORTAL", "127.0.0.1", "Valid credentials for " + username, "ACCESS GRANTED");
            } else {
                dbHelper.recordAccessLog("LOGIN_FAILURE", "AUTH_PORTAL", "127.0.0.1", "Failed login for " + username, "ACCESS DENIED");
            }
        } catch (Exception ignored) {}
        return res.toString();
    }

    @JavascriptInterface
    public String register(String username, String password, String adminToken) {
        if (adminToken != null && !adminToken.isEmpty() && !"VEYRA-ADMIN-SETUP-2026".equals(adminToken)) {
            dbHelper.recordAccessLog("ADMIN_PROVISION_DENIED", "ADMIN_SETUP", "127.0.0.1", "Invalid admin setup key: " + adminToken, "ACCESS DENIED");
            JSONObject err = new JSONObject();
            try {
                err.put("success", false);
                err.put("error", "Invalid administrator authorization setup key.");
            } catch (Exception ignored) {}
            return err.toString();
        }
        return authManager.register(username, password, adminToken).toString();
    }

    @JavascriptInterface
    public String getCurrentUser() {
        JSONObject u = authManager.getCurrentUser();
        return u != null ? u.toString() : "null";
    }

    @JavascriptInterface
    public void logout() {
        authManager.logout();
    }

    @JavascriptInterface
    public String recordAccessAttempt(String action, String resource, String details, String outcome) {
        dbHelper.recordAccessLog(action, resource, "127.0.0.1", details, outcome);
        JSONObject res = new JSONObject();
        try {
            res.put("recorded", true);
        } catch (Exception ignored) {}
        return res.toString();
    }

    @JavascriptInterface
    public String getAccessLogs() {
        return dbHelper.getAccessLogs(50).toString();
    }

    @JavascriptInterface
    public String getRegisteredDevices() {
        return dbHelper.getRegisteredDevices().toString();
    }

    @JavascriptInterface
    public String getAdminMetrics() {
        if (!authManager.isAdmin()) {
            dbHelper.recordAccessLog("UNAUTHORIZED_ADMIN_ACCESS", "ADMIN_METRICS", "127.0.0.1", "Unauthenticated request for admin metrics", "ACCESS DENIED");
            JSONObject err = new JSONObject();
            try {
                err.put("error", "Unauthorized access. Administrator privileges required.");
            } catch (Exception ignored) {}
            return err.toString();
        }

        JSONObject metrics = dbHelper.getMetrics();
        try {
            metrics.put("total_registered_accounts", dbHelper.getUserCount());
            metrics.put("model_version", "Veyra-Hybrid-v1.2.0-Mobile");
            metrics.put("text_model_accuracy", "98.31%");
            metrics.put("text_model_precision", "95.92%");
            metrics.put("text_model_recall", "91.56%");
            metrics.put("url_model_accuracy", "89.98%");
            metrics.put("application_health", "Healthy (On-Device Local Operation)");
            metrics.put("privacy_status", "Zero Raw Text Transmitted / Zero Cloud Exfiltration");
        } catch (Exception ignored) {}
        return metrics.toString();
    }

    // --- Language Controls ---

    @JavascriptInterface
    public void setLanguage(final String langCode) {
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                activity.changeLanguage(langCode);
            }
        });
    }

    @JavascriptInterface
    public String getSelectedLanguage() {
        return dbHelper.getSetting("selected_language", "en");
    }

    @JavascriptInterface
    public void togglePauseMonitoring() {
        boolean current = dbHelper.isMonitoringPaused();
        dbHelper.setSetting("monitoring_paused", current ? "0" : "1");
    }

    @JavascriptInterface
    public boolean isMonitoringPaused() {
        return dbHelper.isMonitoringPaused();
    }

    @JavascriptInterface
    public String getExcludedApps() {
        return dbHelper.getSetting("excluded_apps", "");
    }

    @JavascriptInterface
    public void setExcludedApps(String appsCsv) {
        dbHelper.setSetting("excluded_apps", appsCsv);
    }
}

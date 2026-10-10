package com.veyra.security;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "veyra_secure.db";
    private static final int DATABASE_VERSION = 2;
    private static DatabaseHelper instance;

    public static synchronized DatabaseHelper getInstance(Context context) {
        if (instance == null) {
            instance = new DatabaseHelper(context.getApplicationContext());
        }
        return instance;
    }

    private DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        createTables(db);
        initializeMetrics(db);
        seedAdminUser(db);
    }

    @Override
    public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
        createTables(db);
        seedAdminUser(db);
    }

    private void createTables(SQLiteDatabase db) {
        // Findings History (Sanitized Metadata Only)
        db.execSQL("CREATE TABLE IF NOT EXISTS findings (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "source TEXT, " +
                "risk_level TEXT, " +
                "risk_score INTEGER, " +
                "threat_type TEXT, " +
                "sanitized_evidence TEXT, " +
                "action_status TEXT, " +
                "timestamp INTEGER)");

        // Users & Authentication
        db.execSQL("CREATE TABLE IF NOT EXISTS users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username TEXT UNIQUE, " +
                "password_hash TEXT, " +
                "salt TEXT, " +
                "role TEXT, " +
                "created_at INTEGER)");

        // Audit & Dashboard Metrics
        db.execSQL("CREATE TABLE IF NOT EXISTS metrics (" +
                "metric_key TEXT PRIMARY KEY, " +
                "count_value INTEGER, " +
                "last_updated INTEGER)");

        // User Voluntary Feedback
        db.execSQL("CREATE TABLE IF NOT EXISTS feedback (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "feedback_type TEXT, " +
                "finding_id INTEGER, " +
                "timestamp INTEGER)");

        // App Settings
        db.execSQL("CREATE TABLE IF NOT EXISTS settings (" +
                "setting_key TEXT PRIMARY KEY, " +
                "setting_value TEXT)");

        // Connected Devices Registry
        db.execSQL("CREATE TABLE IF NOT EXISTS devices (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "installation_id TEXT UNIQUE, " +
                "device_name TEXT, " +
                "platform TEXT, " +
                "app_version TEXT, " +
                "status TEXT, " +
                "last_seen INTEGER)");

        // Security Access Logs (Tracks authorized & blocked attempts)
        db.execSQL("CREATE TABLE IF NOT EXISTS access_logs (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "action TEXT, " +
                "resource TEXT, " +
                "ip TEXT, " +
                "details TEXT, " +
                "outcome TEXT, " +
                "timestamp INTEGER)");
    }

    private void initializeMetrics(SQLiteDatabase db) {
        String[] keys = {
                "messages_checked",
                "scams_found",
                "phishing_found",
                "normal_messages",
                "high_risk_alerts",
                "notifications_analyzed",
                "suspicious_detected",
                "high_risk_warnings",
                "manual_scans_completed",
                "blocked_attempts",
                "recovery_workflows_opened",
                "feedback_helped_count",
                "feedback_avoided_link"
        };
        for (String k : keys) {
            ContentValues cv = new ContentValues();
            cv.put("metric_key", k);
            cv.put("count_value", 0);
            cv.put("last_updated", System.currentTimeMillis());
            db.insertWithOnConflict("metrics", null, cv, SQLiteDatabase.CONFLICT_IGNORE);
        }
    }

    private void seedAdminUser(SQLiteDatabase db) {
        Cursor c = db.rawQuery("SELECT COUNT(*) FROM users WHERE role = 'admin'", null);
        boolean hasAdmin = false;
        if (c.moveToNext()) {
            hasAdmin = c.getInt(0) > 0;
        }
        c.close();

        if (!hasAdmin) {
            try {
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                String saltHex = bytesToHex(salt);
                String hashHex = hashPassword("AdminVeyra@2026!", salt);

                ContentValues cv = new ContentValues();
                cv.put("username", "admin");
                cv.put("password_hash", hashHex);
                cv.put("salt", saltHex);
                cv.put("role", "admin");
                cv.put("created_at", System.currentTimeMillis());
                db.insertWithOnConflict("users", null, cv, SQLiteDatabase.CONFLICT_IGNORE);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        createTables(db);
        initializeMetrics(db);
        seedAdminUser(db);
    }

    // --- Device Setup & Installation Identification ---

    public String getInstallationId() {
        String id = getSetting("installation_id", null);
        if (id == null || id.trim().isEmpty()) {
            byte[] randBytes = new byte[4];
            new SecureRandom().nextBytes(randBytes);
            StringBuilder sb = new StringBuilder("VYR-");
            for (byte b : randBytes) {
                sb.append(String.format("%02X", b));
            }
            id = sb.toString();
            setSetting("installation_id", id);
            registerDeviceLocally(id, "Android Device", "1.0.0", "Saved Locally");
        }
        return id;
    }

    public void registerDeviceLocally(String installId, String devName, String version, String status) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("installation_id", installId);
        cv.put("device_name", devName);
        cv.put("platform", "Android");
        cv.put("app_version", version);
        cv.put("status", status);
        cv.put("last_seen", System.currentTimeMillis());
        db.insertWithOnConflict("devices", null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public JSONObject getDeviceInfo() {
        JSONObject obj = new JSONObject();
        try {
            String installId = getInstallationId();
            String devName = getSetting("device_name", "Android Device");
            String version = "1.0.0";
            String regStatus = getSetting("registration_status", "Saved Locally");
            boolean setupDone = "1".equals(getSetting("device_setup_completed", "0"));

            obj.put("installationId", installId);
            obj.put("deviceName", devName);
            obj.put("appVersion", version);
            obj.put("registrationStatus", regStatus);
            obj.put("platform", "Android");
            obj.put("isSetupCompleted", setupDone);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return obj;
    }

    public void completeDeviceSetup() {
        setSetting("device_setup_completed", "1");
    }

    // --- Findings Operations (Privacy-Preserving) ---

    public long saveFinding(String source, String riskLevel, int riskScore, String threatType,
                            List<String> evidenceList, String actionStatus) {
        if (!isHistoryEnabled()) {
            return -1; // History is disabled by user
        }
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("source", source);
        cv.put("risk_level", riskLevel);
        cv.put("risk_score", riskScore);
        cv.put("threat_type", threatType);

        JSONArray arr = new JSONArray();
        if (evidenceList != null) {
            for (String e : evidenceList) arr.put(e);
        }
        cv.put("sanitized_evidence", arr.toString());
        cv.put("action_status", actionStatus);
        cv.put("timestamp", System.currentTimeMillis());

        return db.insert("findings", null, cv);
    }

    public JSONArray getFindings(int limit) {
        JSONArray results = new JSONArray();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT id, source, risk_level, risk_score, threat_type, sanitized_evidence, action_status, timestamp FROM findings ORDER BY timestamp DESC LIMIT ?",
                new String[]{String.valueOf(limit)});
        try {
            while (c.moveToNext()) {
                JSONObject obj = new JSONObject();
                obj.put("id", c.getLong(0));
                obj.put("source", c.getString(1));
                obj.put("riskLevel", c.getString(2));
                obj.put("riskScore", c.getInt(3));
                obj.put("threatType", c.getString(4));
                obj.put("sanitizedEvidence", new JSONArray(c.getString(5)));
                obj.put("actionStatus", c.getString(6));
                obj.put("timestamp", c.getLong(7));
                results.put(obj);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            c.close();
        }
        return results;
    }

    public void clearHistory() {
        SQLiteDatabase db = getWritableDatabase();
        db.delete("findings", null, null);
    }

    // --- Metrics & Real Dashboard Summary ---

    public void incrementMetric(String key) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("metric_key", key);
        cv.put("count_value", 1);
        cv.put("last_updated", System.currentTimeMillis());
        db.insertWithOnConflict("metrics", null, cv, SQLiteDatabase.CONFLICT_IGNORE);

        db.execSQL("UPDATE metrics SET count_value = count_value + 1, last_updated = ? WHERE metric_key = ?",
                new Object[]{System.currentTimeMillis(), key});
    }

    public JSONObject getMetrics() {
        JSONObject obj = new JSONObject();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT metric_key, count_value FROM metrics", null);
        try {
            while (c.moveToNext()) {
                obj.put(c.getString(0), c.getInt(1));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            c.close();
        }
        return obj;
    }

    public JSONObject getDashboardSummary(boolean isNotificationGranted, boolean isSmsGranted) {
        JSONObject obj = new JSONObject();
        SQLiteDatabase db = getReadableDatabase();
        try {
            JSONObject m = getMetrics();

            // 1. Messages Checked (total messages inspected via SMS + notifications + manual scans)
            Cursor cScans = db.rawQuery("SELECT COUNT(*) FROM findings", null);
            int totalFindings = 0;
            if (cScans.moveToNext()) totalFindings = cScans.getInt(0);
            cScans.close();

            int metricMessagesChecked = m.optInt("messages_checked", 0);
            int metricManual = m.optInt("manual_scans_completed", 0);
            int messagesChecked = Math.max(totalFindings, metricMessagesChecked + metricManual);

            // 2. Possible Scams Found
            Cursor cScams = db.rawQuery("SELECT COUNT(*) FROM findings WHERE threat_type LIKE '%Scam%' OR risk_level IN ('HIGH', 'HIGH RISK') AND threat_type NOT LIKE '%Phish%'", null);
            int scamsCount = 0;
            if (cScams.moveToNext()) scamsCount = cScams.getInt(0);
            cScams.close();
            int metricScams = m.optInt("scams_found", 0);
            int possibleScamsFound = Math.max(scamsCount, metricScams);

            // 3. Phishing Messages Found
            Cursor cPhish = db.rawQuery("SELECT COUNT(*) FROM findings WHERE threat_type LIKE '%Phish%' OR threat_type LIKE '%Link%' OR threat_type LIKE '%URL%'", null);
            int phishCount = 0;
            if (cPhish.moveToNext()) phishCount = cPhish.getInt(0);
            cPhish.close();
            int metricPhish = m.optInt("phishing_found", 0);
            int phishingMessagesFound = Math.max(phishCount, metricPhish);

            // 4. Normal Messages
            Cursor cNormal = db.rawQuery("SELECT COUNT(*) FROM findings WHERE risk_level IN ('LOW', 'NO KNOWN THREAT DETECTED') OR action_status = 'Safe'", null);
            int normalCount = 0;
            if (cNormal.moveToNext()) normalCount = cNormal.getInt(0);
            cNormal.close();
            int metricNormal = m.optInt("normal_messages", 0);
            int normalMessages = Math.max(normalCount, metricNormal);

            // 5. High-Risk Alerts
            Cursor cHigh = db.rawQuery("SELECT COUNT(*) FROM findings WHERE risk_level IN ('HIGH', 'HIGH RISK')", null);
            int highCount = 0;
            if (cHigh.moveToNext()) highCount = cHigh.getInt(0);
            cHigh.close();
            int metricHigh = m.optInt("high_risk_alerts", 0);
            int highRiskAlerts = Math.max(highCount, metricHigh);

            // 6. Blocked Attempts
            Cursor cBlocked = db.rawQuery("SELECT COUNT(*) FROM access_logs WHERE outcome = 'ACCESS DENIED'", null);
            int blockedAttempts = 0;
            if (cBlocked.moveToNext()) blockedAttempts = cBlocked.getInt(0);
            cBlocked.close();
            int metricBlocked = m.optInt("blocked_attempts", 0);
            if (metricBlocked > blockedAttempts) blockedAttempts = metricBlocked;

            // 7. Protection Status
            boolean isPaused = isMonitoringPaused();
            boolean activeMonitoring = (!isPaused && (isSmsGranted || isNotificationGranted));
            String protectionStatus = activeMonitoring ? "Live Protection" : "Attention Needed";

            // Most Recent Scan Timestamp
            Cursor cTime = db.rawQuery("SELECT MAX(timestamp) FROM findings", null);
            long lastScanTime = 0;
            if (cTime.moveToNext()) lastScanTime = cTime.getLong(0);
            cTime.close();

            // Canonical Section 6 keys
            obj.put("messages_checked", messagesChecked);
            obj.put("scams_found", possibleScamsFound);
            obj.put("phishing_found", phishingMessagesFound);
            obj.put("normal_messages", normalMessages);
            obj.put("high_risk_alerts", highRiskAlerts);
            obj.put("blocked_attempts", blockedAttempts);
            obj.put("protection_status", protectionStatus);
            obj.put("last_scan_time", lastScanTime);
            obj.put("active_monitoring", activeMonitoring);
            obj.put("is_notification_granted", isNotificationGranted);
            obj.put("is_sms_granted", isSmsGranted);
            obj.put("recent_findings", getFindings(4));

            // Legacy backward-compatibility aliases
            obj.put("total_scans", messagesChecked);
            obj.put("threats_detected", possibleScamsFound + phishingMessagesFound);
            obj.put("phishing_links", phishingMessagesFound);
            obj.put("suspicious_messages", possibleScamsFound);
            obj.put("high_risk_threats", highRiskAlerts);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return obj;
    }

    // --- Access Logs & Authorization Events ---

    public void recordAccessLog(String action, String resource, String ip, String details, String outcome) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("action", action);
        cv.put("resource", resource);
        cv.put("ip", ip);
        cv.put("details", details);
        cv.put("outcome", outcome);
        cv.put("timestamp", System.currentTimeMillis());
        db.insert("access_logs", null, cv);

        if ("ACCESS DENIED".equals(outcome)) {
            incrementMetric("blocked_attempts");
        }
    }

    public JSONArray getAccessLogs(int limit) {
        JSONArray arr = new JSONArray();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT id, action, resource, ip, details, outcome, timestamp FROM access_logs ORDER BY timestamp DESC LIMIT ?",
                new String[]{String.valueOf(limit)});
        try {
            while (c.moveToNext()) {
                JSONObject obj = new JSONObject();
                obj.put("id", c.getLong(0));
                obj.put("action", c.getString(1));
                obj.put("resource", c.getString(2));
                obj.put("ip", c.getString(3));
                obj.put("details", c.getString(4));
                obj.put("outcome", c.getString(5));
                obj.put("timestamp", c.getLong(6));
                arr.put(obj);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            c.close();
        }
        return arr;
    }

    public JSONArray getRegisteredDevices() {
        JSONArray arr = new JSONArray();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT id, installation_id, device_name, platform, app_version, status, last_seen FROM devices ORDER BY last_seen DESC", null);
        try {
            while (c.moveToNext()) {
                JSONObject obj = new JSONObject();
                obj.put("id", c.getLong(0));
                obj.put("installationId", c.getString(1));
                obj.put("deviceName", c.getString(2));
                obj.put("platform", c.getString(3));
                obj.put("appVersion", c.getString(4));
                obj.put("status", c.getString(5));
                obj.put("lastSeen", c.getLong(6));
                arr.put(obj);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            c.close();
        }
        return arr;
    }

    // --- User Feedback ---

    public void recordFeedback(String feedbackType, long findingId) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("feedback_type", feedbackType);
        cv.put("finding_id", findingId);
        cv.put("timestamp", System.currentTimeMillis());
        db.insert("feedback", null, cv);

        if ("helped".equals(feedbackType)) {
            incrementMetric("feedback_helped_count");
        } else if ("avoided_link".equals(feedbackType)) {
            incrementMetric("feedback_avoided_link");
        }
    }

    // --- User & Admin Authentication ---

    public boolean registerUser(String username, String password, String role) {
        SQLiteDatabase db = getWritableDatabase();
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            String saltHex = bytesToHex(salt);
            String hashHex = hashPassword(password, salt);

            ContentValues cv = new ContentValues();
            cv.put("username", username.trim());
            cv.put("password_hash", hashHex);
            cv.put("salt", saltHex);
            cv.put("role", role);
            cv.put("created_at", System.currentTimeMillis());

            long id = db.insertOrThrow("users", null, cv);
            return id > 0;
        } catch (Exception e) {
            return false;
        }
    }

    public JSONObject authenticateUser(String username, String password) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT id, username, password_hash, salt, role FROM users WHERE username = ?",
                new String[]{username.trim()});
        try {
            if (c.moveToNext()) {
                String storedHash = c.getString(2);
                String saltHex = c.getString(3);
                String role = c.getString(4);
                byte[] salt = hexToBytes(saltHex);
                String computedHash = hashPassword(password, salt);

                if (storedHash.equals(computedHash)) {
                    JSONObject user = new JSONObject();
                    user.put("id", c.getLong(0));
                    user.put("username", c.getString(1));
                    user.put("role", role);
                    return user;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            c.close();
        }
        return null;
    }

    public int getUserCount() {
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT COUNT(*) FROM users", null);
        int count = 0;
        if (c.moveToNext()) count = c.getInt(0);
        c.close();
        return count;
    }

    // --- Settings & Preferences ---

    public void setSetting(String key, String value) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("setting_key", key);
        cv.put("setting_value", value);
        db.insertWithOnConflict("settings", null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public String getSetting(String key, String defaultValue) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT setting_value FROM settings WHERE setting_key = ?", new String[]{key});
        String val = defaultValue;
        if (c.moveToNext()) val = c.getString(0);
        c.close();
        return val;
    }

    public JSONObject getNotificationSettings() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("security_notifications", "1".equals(getSetting("pref_security_notifications", "1")));
            obj.put("high_risk_alerts", "1".equals(getSetting("pref_high_risk_alerts", "1")));
            obj.put("suspicious_link_alerts", "1".equals(getSetting("pref_suspicious_link_alerts", "1")));
            obj.put("suspicious_message_alerts", "1".equals(getSetting("pref_suspicious_message_alerts", "1")));
            obj.put("permission_warnings", "1".equals(getSetting("pref_permission_warnings", "1")));
            obj.put("sound_alerts", "1".equals(getSetting("pref_sound_alerts", "1")));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return obj;
    }

    public void saveNotificationSettings(JSONObject obj) {
        if (obj == null) return;
        setSetting("pref_security_notifications", obj.optBoolean("security_notifications", true) ? "1" : "0");
        setSetting("pref_high_risk_alerts", obj.optBoolean("high_risk_alerts", true) ? "1" : "0");
        setSetting("pref_suspicious_link_alerts", obj.optBoolean("suspicious_link_alerts", true) ? "1" : "0");
        setSetting("pref_suspicious_message_alerts", obj.optBoolean("suspicious_message_alerts", true) ? "1" : "0");
        setSetting("pref_permission_warnings", obj.optBoolean("permission_warnings", true) ? "1" : "0");
        setSetting("pref_sound_alerts", obj.optBoolean("sound_alerts", true) ? "1" : "0");
    }

    public String getThemePreference() {
        return getSetting("theme_preference", "dark");
    }

    public void setThemePreference(String theme) {
        setSetting("theme_preference", theme);
    }

    public boolean isHistoryEnabled() {
        return "1".equals(getSetting("history_enabled", "1"));
    }

    public boolean isMonitoringPaused() {
        return "1".equals(getSetting("monitoring_paused", "0"));
    }

    // --- Cryptographic Helpers ---

    private String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashed);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}

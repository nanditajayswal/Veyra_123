package com.veyra.security;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.provider.Telephony;
import android.telephony.SmsMessage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VeyraSmsReceiver extends BroadcastReceiver {
    private static final String SMS_RECEIVED_ACTION = "android.provider.Telephony.SMS_RECEIVED";
    private static final long COOLDOWN_MILLIS = 5 * 60 * 1000; // 5-minute de-duplication window
    private static final Map<String, Long> processedSmsCache = new ConcurrentHashMap<>();
    private static final ExecutorService backgroundExecutor = Executors.newSingleThreadExecutor();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !SMS_RECEIVED_ACTION.equals(intent.getAction())) {
            return;
        }

        DatabaseHelper dbHelper = DatabaseHelper.getInstance(context);

        // 1. Check if user enabled SMS protection
        String smsProtection = dbHelper.getSetting("sms_protection_enabled", "1");
        if (!"1".equals(smsProtection)) {
            return;
        }

        // 2. Check if monitoring is temporarily paused
        if (dbHelper.isMonitoringPaused()) {
            return;
        }

        // 3. Verify Android permission is granted
        if (context.checkSelfPermission("android.permission.RECEIVE_SMS") != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        // 4. Extract SMS messages using supported official Android Telephony API
        SmsMessage[] messages;
        try {
            messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        if (messages == null || messages.length == 0) {
            return;
        }

        // Combine multipart messages from same sender
        StringBuilder bodyBuilder = new StringBuilder();
        String originatingAddress = "";
        for (SmsMessage msg : messages) {
            if (msg != null) {
                if (originatingAddress.isEmpty()) {
                    originatingAddress = msg.getDisplayOriginatingAddress();
                    if (originatingAddress == null) originatingAddress = msg.getOriginatingAddress();
                }
                String body = msg.getMessageBody();
                if (body != null) {
                    bodyBuilder.append(body);
                }
            }
        }

        final String fullText = bodyBuilder.toString().trim();
        if (fullText.isEmpty()) {
            return;
        }

        final String sender = (originatingAddress != null && !originatingAddress.isEmpty()) ? originatingAddress : "SMS";

        // 5. De-duplication: Prevent the same SMS from being processed or alerted twice
        String hash = computeHash(sender + ":" + fullText);
        long now = System.currentTimeMillis();
        Long lastSeen = processedSmsCache.get(hash);
        if (lastSeen != null && (now - lastSeen) < COOLDOWN_MILLIS) {
            return; // Duplicate broadcast suppressed
        }
        processedSmsCache.put(hash, now);

        // Clean cache periodically
        if (processedSmsCache.size() > 200) {
            java.util.Iterator<Map.Entry<String, Long>> it = processedSmsCache.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Long> entry = it.next();
                if ((now - entry.getValue()) > COOLDOWN_MILLIS) {
                    it.remove();
                }
            }
        }

        // 6. Asynchronous On-Device Processing
        final Context appContext = context.getApplicationContext();
        backgroundExecutor.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    DetectionEngine detectionEngine = DetectionEngine.getInstance(appContext);
                    DatabaseHelper db = DatabaseHelper.getInstance(appContext);

                    // Process text locally on device
                    DetectionEngine.ScanResult result = detectionEngine.analyze(fullText, null);

                    // Increment general Messages Checked counter
                    db.incrementMetric("messages_checked");

                    String threatType;
                    String actionStatus;

                    if ("HIGH".equals(result.riskLevel)) {
                        db.incrementMetric("high_risk_alerts");
                        if ("PHISHING".equals(result.predictedClass)) {
                            db.incrementMetric("phishing_found");
                            threatType = "Phishing Message";
                        } else {
                            db.incrementMetric("scams_found");
                            threatType = "Possible Scam";
                        }
                        actionStatus = "High Risk Warning";

                        // Save event metadata (sanitized only, no raw private text)
                        long findingId = db.saveFinding(
                                "SMS (" + sender + ")",
                                result.riskLevel,
                                result.riskScore,
                                threatType,
                                result.indicators,
                                actionStatus
                        );

                        // Trigger Instant Security Notification
                        VeyraNotificationService.showSmsThreatNotification(appContext, sender, result, findingId);

                    } else if ("MEDIUM".equals(result.riskLevel)) {
                        if ("PHISHING".equals(result.predictedClass)) {
                            db.incrementMetric("phishing_found");
                            threatType = "Suspicious Link/Message";
                        } else {
                            db.incrementMetric("scams_found");
                            threatType = "Suspicious Message";
                        }
                        actionStatus = "Suspicious Warning";

                        long findingId = db.saveFinding(
                                "SMS (" + sender + ")",
                                result.riskLevel,
                                result.riskScore,
                                threatType,
                                result.indicators,
                                actionStatus
                        );

                        // Trigger Instant Security Notification for suspicious threshold
                        VeyraNotificationService.showSmsThreatNotification(appContext, sender, result, findingId);

                    } else {
                        // BENIGN / Normal message
                        db.incrementMetric("normal_messages");
                        threatType = "Normal Message";
                        actionStatus = "Safe";

                        // Normal messages: Do not trigger alarming notifications!
                        // Record benign finding silently if history is active
                        if (db.isHistoryEnabled()) {
                            db.saveFinding(
                                    "SMS",
                                    "LOW",
                                    result.riskScore,
                                    threatType,
                                    result.indicators,
                                    actionStatus
                            );
                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private static String computeHash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return String.valueOf(input.hashCode());
        }
    }
}

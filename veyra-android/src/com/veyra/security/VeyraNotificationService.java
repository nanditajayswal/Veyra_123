package com.veyra.security;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VeyraNotificationService extends NotificationListenerService {
    public static final String CHANNEL_ALERTS_ID = "veyra_security_alerts";
    private static final long COOLDOWN_MILLIS = 5 * 60 * 1000; // 5-minute duplicate cooldown

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final Map<String, Long> processedCache = new ConcurrentHashMap<>();

    private DetectionEngine detectionEngine;
    private DatabaseHelper dbHelper;
    private static boolean isServiceConnected = false;

    public static boolean isConnected() {
        return isServiceConnected;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        detectionEngine = DetectionEngine.getInstance(this);
        dbHelper = DatabaseHelper.getInstance(this);
        createNotificationChannel(this);
    }

    @Override
    public void onListenerConnected() {
        super.onListenerConnected();
        isServiceConnected = true;
    }

    @Override
    public void onListenerDisconnected() {
        super.onListenerDisconnected();
        isServiceConnected = false;
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null || sbn.getNotification() == null) return;

        // Skip internal VEYRA notifications
        String packageName = sbn.getPackageName();
        if (getPackageName().equals(packageName)) return;

        // Check if monitoring is paused by user
        if (dbHelper.isMonitoringPaused()) return;

        // Check if package is in excluded list
        String excludedStr = dbHelper.getSetting("excluded_apps", "");
        if (!excludedStr.isEmpty()) {
            List<String> excludedList = Arrays.asList(excludedStr.split(","));
            if (excludedList.contains(packageName)) return;
        }

        // Extract available text content from notification
        Notification notification = sbn.getNotification();
        Bundle extras = notification.extras;
        if (extras == null) return;

        CharSequence titleCs = extras.getCharSequence(Notification.EXTRA_TITLE);
        CharSequence textCs = extras.getCharSequence(Notification.EXTRA_TEXT);
        CharSequence bigTextCs = extras.getCharSequence(Notification.EXTRA_BIG_TEXT);

        String title = titleCs != null ? titleCs.toString() : "";
        String text = bigTextCs != null ? bigTextCs.toString() : (textCs != null ? textCs.toString() : "");

        final String fullContent = (title + " " + text).trim();
        if (fullContent.isEmpty()) return;

        // Duplicate suppression: Compute hash of (packageName + content)
        String contentHash = computeHash(packageName + ":" + fullContent);
        long now = System.currentTimeMillis();
        Long lastSeen = processedCache.get(contentHash);
        if (lastSeen != null && (now - lastSeen) < COOLDOWN_MILLIS) {
            return; // Duplicate notification within cooldown window
        }
        processedCache.put(contentHash, now);

        if (processedCache.size() > 500) {
            Iterator<Map.Entry<String, Long>> it = processedCache.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Long> entry = it.next();
                if ((now - entry.getValue()) > COOLDOWN_MILLIS) {
                    it.remove();
                }
            }
        }

        // Process analysis asynchronously on background thread
        executor.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    dbHelper.incrementMetric("messages_checked");

                    // Run on-device 3-class ML detection
                    DetectionEngine.ScanResult result = detectionEngine.analyze(fullContent, null);

                    if ("HIGH".equals(result.riskLevel) || "MEDIUM".equals(result.riskLevel)) {
                        String threatType = "PHISHING".equals(result.predictedClass) ? "Phishing Alert" : "Possible Scam";
                        String actionStatus = "HIGH".equals(result.riskLevel) ? "High Risk Warning" : "Suspicious Warning";

                        if ("HIGH".equals(result.riskLevel)) {
                            dbHelper.incrementMetric("high_risk_alerts");
                        }
                        if ("PHISHING".equals(result.predictedClass)) {
                            dbHelper.incrementMetric("phishing_found");
                        } else {
                            dbHelper.incrementMetric("scams_found");
                        }

                        // Save sanitized metadata only (zero raw private text stored)
                        long findingId = dbHelper.saveFinding(
                                packageName,
                                result.riskLevel,
                                result.riskScore,
                                threatType,
                                result.indicators,
                                actionStatus
                        );

                        // Show real Android warning notification
                        showNotificationAlert(getApplicationContext(), packageName, result, findingId, false);
                    } else {
                        dbHelper.incrementMetric("normal_messages");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public static void showSmsThreatNotification(Context context, String sender, DetectionEngine.ScanResult result, long findingId) {
        showNotificationAlert(context, sender, result, findingId, true);
    }

    private static void showNotificationAlert(Context context, String source, DetectionEngine.ScanResult result, long findingId, boolean isSms) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        createNotificationChannel(context);

        DatabaseHelper db = DatabaseHelper.getInstance(context);
        String lang = db.getSetting("selected_language", "en");

        // Intent for "Why Is It Risky?"
        Intent whyIntent = new Intent(context, MainActivity.class);
        whyIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        whyIntent.putExtra("finding_id", findingId);
        whyIntent.putExtra("action", "why_risky");

        PendingIntent piWhy = PendingIntent.getActivity(
                context,
                (int) (findingId * 10 + 1),
                whyIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        // Intent for "View Details"
        Intent detailsIntent = new Intent(context, MainActivity.class);
        detailsIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        detailsIntent.putExtra("finding_id", findingId);
        detailsIntent.putExtra("action", "view_details");

        PendingIntent piDetails = PendingIntent.getActivity(
                context,
                (int) (findingId * 10 + 2),
                detailsIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        // Localized Strings
        String title;
        String heading;
        String message;
        String whyFlaggedHeader;
        String advice;
        String btnWhy;
        String btnDetails;
        String btnDismiss;

        if ("hi".equals(lang)) {
            title = "VEYRA सुरक्षा चेतावनी";
            if ("HIGH".equals(result.riskLevel)) {
                heading = "उच्च जोखिम — संभावित धोखाधड़ी!";
                message = "यह संदेश आपकी बैंकिंग या व्यक्तिगत जानकारी चुराने का प्रयास कर सकता है।";
            } else {
                heading = "संदेहास्पद संदेश — कृपया सावधानी से जांचें";
                message = "इस संदेश में असामान्य और संदेहास्पद संकेत पाए गए हैं।";
            }
            whyFlaggedHeader = "इसे क्यों चिह्नित किया गया:";
            advice = "सलाह:\nअपना बैंक विवरण, पासवर्ड या ओटीपी कभी साझा न करें।";
            btnWhy = "यह जोखिम भरा क्यों है?";
            btnDetails = "विवरण देखें";
            btnDismiss = "खारिज करें";
        } else if ("gu".equals(lang)) {
            title = "VEYRA સુરક્ષા ચેતવણી";
            if ("HIGH".equals(result.riskLevel)) {
                heading = "ઉચ્ચ જોખમ — સંભવિત છેતરપિંડી!";
                message = "આ સંદેશ તમારી બેંકિંગ અથવા અંગત વિગતો ચોરવાનો પ્રયાસ કરી શકે છે.";
            } else {
                heading = "શંકાસ્પદ સંદેશો — કૃપા કરીને કાળજીપૂર્વક તપાસો";
                message = "આ સંદેશમાં અસામાન્ય સંકેતો જણાયા છે.";
            }
            whyFlaggedHeader = "શા માટે ફ્લેગ કરવામાં આવ્યું:";
            advice = "સલાહ:\nતમારી બેંક વિગતો, પાસવર્ડ અથવા ઓટીપી ક્યારેય શેર કરશો નહીં.";
            btnWhy = "આ શા માટે જોખમી છે?";
            btnDetails = "વિગતો જુઓ";
            btnDismiss = "બંધ કરો";
        } else {
            title = "VEYRA SECURITY ALERT";
            if ("HIGH".equals(result.riskLevel)) {
                heading = "HIGH RISK — Possible Scam Detected!";
                message = "This message may be trying to steal your banking information.";
            } else {
                heading = "Suspicious Message — Please Check Carefully";
                message = "This message looks unusual. Check it carefully before responding.";
            }
            whyFlaggedHeader = "Why it was flagged:";
            advice = "Advice:\nDo not share your bank details, passwords or OTP.";
            btnWhy = "Why Is It Risky?";
            btnDetails = "View Details";
            btnDismiss = "Dismiss";
        }

        // Format Indicators
        StringBuilder indicatorsText = new StringBuilder();
        if (result.indicators != null && !result.indicators.isEmpty()) {
            for (String ind : result.indicators) {
                indicatorsText.append("• ").append(ind).append("\n");
            }
        } else {
            indicatorsText.append("• ").append(result.explanation).append("\n");
        }

        String fullExpandedText = message + "\n\n" +
                whyFlaggedHeader + "\n" +
                indicatorsText.toString().trim() + "\n\n" +
                advice;

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(context, CHANNEL_ALERTS_ID);
        } else {
            builder = new Notification.Builder(context);
        }

        builder.setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(title)
                .setContentText(heading)
                .setStyle(new Notification.BigTextStyle()
                        .setBigContentTitle(heading)
                        .setSummaryText(title)
                        .bigText(fullExpandedText))
                .setContentIntent(piDetails)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setVibrate(new long[]{0, 400, 200, 400});

        // Add Interactive Actions (Why Is It Risky? / View Details)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) {
            Notification.Action actionWhy = new Notification.Action.Builder(
                    0, btnWhy, piWhy
            ).build();
            Notification.Action actionDetails = new Notification.Action.Builder(
                    0, btnDetails, piDetails
            ).build();
            builder.addAction(actionWhy);
            builder.addAction(actionDetails);
        }

        nm.notify((int) findingId, builder.build());
    }

    public static void createNotificationChannel(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                NotificationChannel channel = new NotificationChannel(
                        CHANNEL_ALERTS_ID,
                        context.getString(R.string.channel_alerts_name),
                        NotificationManager.IMPORTANCE_HIGH
                );
                channel.setDescription(context.getString(R.string.channel_alerts_desc));
                channel.enableVibration(true);
                channel.setVibrationPattern(new long[]{0, 400, 200, 400});
                nm.createNotificationChannel(channel);
            }
        }
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

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}

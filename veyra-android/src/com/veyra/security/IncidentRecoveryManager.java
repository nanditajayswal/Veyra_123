package com.veyra.security;

import org.json.JSONArray;
import org.json.JSONObject;

public class IncidentRecoveryManager {

    public static JSONObject getRecoveryGuidance(String incidentType) {
        JSONObject res = new JSONObject();
        try {
            JSONArray steps = new JSONArray();
            String title;
            String urgency;
            String primaryHelpline = "National Cybercrime Helpline: 1930 (Immediate 2-Hour Golden Window)";
            String portal = "Official Portal: https://cybercrime.gov.in";

            if ("payment_made".equals(incidentType)) {
                title = "Emergency: Fraudulent Payment or Fund Transfer";
                urgency = "CRITICAL (Action Required Within Minutes)";
                steps.put("1. Call 1930 Cybercrime Helpline immediately to register an emergency financial freeze (CFCFRMS protocol).");
                steps.put("2. Contact your bank's 24x7 fraud prevention helpline and request an urgent transaction recall / beneficiary account freeze.");
                steps.put("3. Temporarily block the affected debit/credit card and de-link your UPI app (Google Pay, PhonePe, Paytm).");
                steps.put("4. Capture screenshots of transaction reference numbers (UTR, UPI Ref, SMS notices) as legal evidence.");
                steps.put("5. File an official complaint on https://cybercrime.gov.in with bank statement records.");
            } else if ("shared_otp".equals(incidentType)) {
                title = "Compromised: One-Time Password (OTP) Shared";
                urgency = "HIGH URGENCY";
                steps.put("1. Immediately change the password of the service associated with the OTP using an official app or clean device.");
                steps.put("2. Check for unauthorized active sessions or devices and click 'Log Out of All Other Sessions'.");
                steps.put("3. If the OTP was related to banking or UPI, call your bank immediately to block NetBanking and card transactions.");
                steps.put("4. Beware of follow-up calls: fraudsters often call claiming to be 'cyber police' or 'bank managers' asking for a second OTP.");
                steps.put("5. Report the incident via Helpline 1930 if unauthorized debits occur.");
            } else if ("shared_bank".equals(incidentType)) {
                title = "Compromised: Bank, Card, or UPI Details Shared";
                urgency = "HIGH URGENCY";
                steps.put("1. Immediately freeze the compromised card via your mobile banking app or SMS shortcode.");
                steps.put("2. Reset your NetBanking password, transaction PIN, and UPI MPIN immediately.");
                steps.put("3. Turn off international transactions and lower online transaction limits to zero temporarily.");
                steps.put("4. Monitor SMS and email for any unexpected debit notifications over the next 48 hours.");
                steps.put("5. If unauthorized debits happen, call 1930 immediately to block money movement.");
            } else if ("entered_password".equals(incidentType)) {
                title = "Compromised: Password Entered on Fake Site";
                urgency = "HIGH URGENCY";
                steps.put("1. Immediately navigate to the REAL official service website and change your password.");
                steps.put("2. If you reuse this password on other accounts (email, bank, shopping), change it on EVERY other service immediately.");
                steps.put("3. Enable App-Based Multi-Factor Authentication (MFA/2FA) like Google Authenticator or Microsoft Authenticator.");
                steps.put("4. Review recent login history and revoke access to all unknown devices.");
            } else if ("installed_apk".equals(incidentType)) {
                title = "Malicious Software: Suspicious APK Installed";
                urgency = "HIGH URGENCY";
                steps.put("1. Turn on Airplane Mode immediately to prevent the malicious app from exfiltrating data or receiving remote commands.");
                steps.put("2. Boot your phone into Android Safe Mode (Hold Power -> Long-press 'Power Off' -> Select 'Safe Mode').");
                steps.put("3. In Safe Mode, open Android Settings -> Apps -> Locate and uninstall the suspicious app.");
                steps.put("4. Check Settings -> Security -> Device Admin Apps, and revoke permissions for any unknown application.");
                steps.put("5. Restart phone and run Play Protect scan from Google Play Store.");
            } else { // clicked_link
                title = "Precautionary: Clicked a Suspicious Link";
                urgency = "MODERATE CAUTION";
                steps.put("1. Close the browser tab immediately and clear browser history and cookies.");
                steps.put("2. Do not enter any passwords, phone numbers, OTPs, or personal details on the page.");
                steps.put("3. Check your downloads folder to ensure no automatic APK or executable files were downloaded.");
                steps.put("4. If no information was submitted and no file was installed, your device remains safe.");
            }

            res.put("title", title);
            res.put("urgency", urgency);
            res.put("steps", steps);
            res.put("helpline", primaryHelpline);
            res.put("portal", portal);
            res.put("disclaimer", "VEYRA provides security guidance but cannot guarantee financial recovery. Always contact your bank and official authorities promptly.");

        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }
}

package com.veyra.security;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DetectionEngine {
    private static DetectionEngine instance;
    private final Context context;

    // ML Text 3-Class Model (BENIGN, SCAM, PHISHING)
    private final Map<String, Integer> vocabulary = new HashMap<>();
    private final List<Double> idfWeights = new ArrayList<>();
    private final List<List<Double>> classWeights = new ArrayList<>(); // 3 classes
    private final List<Double> classBiases = new ArrayList<>();         // 3 biases
    private List<String> classNames = Arrays.asList("BENIGN", "SCAM", "PHISHING");

    // ML URL Phishing Model (11 lexical features)
    private final List<String> urlFeatureNames = new ArrayList<>();
    private final List<Double> urlMeans = new ArrayList<>();
    private final List<Double> urlStds = new ArrayList<>();
    private final List<Double> urlWeights = new ArrayList<>();
    private double urlBias = -1.2;

    private boolean isModelLoaded = false;
    private String modelVersion = "Veyra-3Class-v2.0.0-Mobile";

    // Regex patterns for heuristics
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://|www\\.)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[a-zA-Z0-9_.~:/?#\\[\\]@!$&'()*+,;=-]*)?",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern OTP_PATTERN = Pattern.compile(
            "(?:otp|one[- ]time[- ]password|verification[- ]code|pin|code)\\s*(?:is|:)?\\s*(\\d{4,8})",
            Pattern.CASE_INSENSITIVE
    );

    private static final Set<String> HIGH_RISK_TLDS = new HashSet<>(Arrays.asList(
            ".xyz", ".top", ".club", ".work", ".buzz", ".fit", ".live", ".click", ".link", ".site", ".online"
    ));

    private static final Set<String> BRAND_KEYWORDS = new HashSet<>(Arrays.asList(
            "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "bhim",
            "amazon", "flipkart", "netflix", "apple", "google", "microsoft",
            "indiapost", "bluedart", "fedex", "dhl", "whatsapp", "telegram"
    ));

    public static synchronized DetectionEngine getInstance(Context ctx) {
        if (instance == null) {
            instance = new DetectionEngine(ctx.getApplicationContext());
        }
        return instance;
    }

    private DetectionEngine(Context ctx) {
        this.context = ctx;
        loadModelWeights();
    }

    private void loadModelWeights() {
        try {
            InputStream is = context.getAssets().open("veyra_ml_weights.json");
            byte[] buffer = new byte[is.available()];
            int read = is.read(buffer);
            is.close();

            if (read > 0) {
                String jsonStr = new String(buffer, StandardCharsets.UTF_8);
                JSONObject root = new JSONObject(jsonStr);

                modelVersion = root.optString("version", "Veyra-3Class-v2.0.0-Mobile");

                // Load Classes
                if (root.has("classes")) {
                    JSONArray cArr = root.getJSONArray("classes");
                    classNames = new ArrayList<>();
                    for (int i = 0; i < cArr.length(); i++) {
                        classNames.add(cArr.getString(i));
                    }
                }

                // Load Text Vocabulary & IDF
                JSONObject vocabObj = root.getJSONObject("vocabulary");
                Iterator<String> keys = vocabObj.keys();
                while (keys.hasNext()) {
                    String k = keys.next();
                    vocabulary.put(k, vocabObj.getInt(k));
                }

                JSONArray idfArr = root.getJSONArray("idf");
                for (int i = 0; i < idfArr.length(); i++) {
                    idfWeights.add(idfArr.getDouble(i));
                }

                // Load 3-Class Weights or Fallback to Legacy
                if (root.has("class_weights") && root.has("biases")) {
                    JSONArray cwArr = root.getJSONArray("class_weights");
                    for (int c = 0; c < cwArr.length(); c++) {
                        JSONArray wRow = cwArr.getJSONArray(c);
                        List<Double> row = new ArrayList<>();
                        for (int i = 0; i < wRow.length(); i++) {
                            row.add(wRow.getDouble(i));
                        }
                        classWeights.add(row);
                    }

                    JSONArray bArr = root.getJSONArray("biases");
                    for (int c = 0; c < bArr.length(); c++) {
                        classBiases.add(bArr.getDouble(c));
                    }
                } else if (root.has("weights")) {
                    // Legacy binary weights
                    JSONArray weightsArr = root.getJSONArray("weights");
                    List<Double> row = new ArrayList<>();
                    for (int i = 0; i < weightsArr.length(); i++) {
                        row.add(weightsArr.getDouble(i));
                    }
                    classWeights.add(new ArrayList<Double>()); // benign placeholder
                    classWeights.add(row); // scam/threat
                    classWeights.add(row); // phishing
                    classBiases.add(0.0);
                    classBiases.add(root.optDouble("bias", -2.5));
                    classBiases.add(root.optDouble("bias", -2.5));
                }

                // Load URL Model
                if (root.has("url_model_trained")) {
                    JSONObject urlObj = root.getJSONObject("url_model_trained");
                    JSONArray fNames = urlObj.getJSONArray("feature_names");
                    for (int i = 0; i < fNames.length(); i++) urlFeatureNames.add(fNames.getString(i));

                    JSONArray mArr = urlObj.getJSONArray("means");
                    for (int i = 0; i < mArr.length(); i++) urlMeans.add(mArr.getDouble(i));

                    JSONArray sArr = urlObj.getJSONArray("stds");
                    for (int i = 0; i < sArr.length(); i++) urlStds.add(sArr.getDouble(i));

                    JSONArray wArr = urlObj.getJSONArray("weights");
                    for (int i = 0; i < wArr.length(); i++) urlWeights.add(wArr.getDouble(i));

                    urlBias = urlObj.optDouble("bias", -1.2);
                }

                isModelLoaded = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            isModelLoaded = false;
        }
    }

    public static class ScanResult {
        public String predictedClass;  // "BENIGN", "SCAM", "PHISHING"
        public String riskLevel;       // "LOW", "MEDIUM", "HIGH"
        public int riskScore;          // 0 to 100
        public List<String> indicators;
        public String explanation;
        public String recommendedAction;
        public String modelVersion;
        public double mlTextConfidence;
        public double mlUrlConfidence;
        public String targetSample;
        public Map<String, Double> classProbabilities = new HashMap<>();

        public JSONObject toJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("predictedClass", predictedClass);
                obj.put("riskLevel", riskLevel);
                obj.put("riskScore", riskScore);
                obj.put("indicators", new JSONArray(indicators));
                obj.put("explanation", explanation);
                obj.put("recommendedAction", recommendedAction);
                obj.put("modelVersion", modelVersion);
                obj.put("mlTextConfidence", (int)(mlTextConfidence * 100));
                obj.put("mlUrlConfidence", (int)(mlUrlConfidence * 100));
                obj.put("targetSample", targetSample);

                JSONObject probs = new JSONObject();
                for (Map.Entry<String, Double> e : classProbabilities.entrySet()) {
                    probs.put(e.getKey(), Math.round(e.getValue() * 100.0) / 100.0);
                }
                obj.put("classProbabilities", probs);
                return obj;
            } catch (Exception e) {
                return new JSONObject();
            }
        }
    }

    public ScanResult analyze(String text, List<String> extractedUrls) {
        ScanResult result = new ScanResult();
        result.indicators = new ArrayList<>();
        result.modelVersion = this.modelVersion;
        result.targetSample = (text != null && text.length() > 60) ? text.substring(0, 60) + "..." : text;

        if (text == null || text.trim().isEmpty()) {
            result.predictedClass = "BENIGN";
            result.riskLevel = "LOW";
            result.riskScore = 0;
            result.explanation = "No content was provided for analysis.";
            result.recommendedAction = "Paste text or a URL to check.";
            return result;
        }

        String lowerText = text.toLowerCase(Locale.ROOT);

        // 1. Extract URLs from text if not provided
        if (extractedUrls == null) {
            extractedUrls = new ArrayList<>();
        }
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        while (urlMatcher.find()) {
            String u = urlMatcher.group();
            if (!extractedUrls.contains(u)) {
                extractedUrls.add(u);
            }
        }

        // 2. ML 3-Class Text Inference
        double[] textProbs = predictText3Class(text);
        double pBenign = textProbs[0];
        double pScam = textProbs[1];
        double pPhishing = textProbs[2];

        result.classProbabilities.put("BENIGN", pBenign);
        result.classProbabilities.put("SCAM", pScam);
        result.classProbabilities.put("PHISHING", pPhishing);

        int maxClassIdx = 0;
        double maxProb = pBenign;
        if (pScam > maxProb) {
            maxProb = pScam;
            maxClassIdx = 1;
        }
        if (pPhishing > maxProb) {
            maxProb = pPhishing;
            maxClassIdx = 2;
        }
        result.predictedClass = classNames.get(maxClassIdx);
        result.mlTextConfidence = maxProb;

        // 3. ML URL Inference
        double maxUrlMlScore = 0.0;
        for (String url : extractedUrls) {
            double uScore = predictUrl(url);
            if (uScore > maxUrlMlScore) {
                maxUrlMlScore = uScore;
            }
        }
        result.mlUrlConfidence = maxUrlMlScore;

        // 4. Local Context & Heuristic Analysis
        boolean hasPrizeClaim = false;
        boolean hasOtpRequest = false;
        boolean hasUrgency = false;
        boolean hasBankingLure = false;
        boolean hasDeliveryLure = false;
        boolean hasUtilityLure = false;
        boolean hasSuspiciousUrl = false;
        boolean isLegitCollegeOrWork = false;
        boolean isLegitBankAlert = false;

        // Prize / Lottery Claim Check
        if (lowerText.contains("won rs") || lowerText.contains("won a prize") || lowerText.contains("cash reward") ||
            lowerText.contains("claim your prize") || lowerText.contains("lucky draw") || lowerText.contains("grant")) {
            hasPrizeClaim = true;
            result.indicators.add("Unexpected prize or reward claim");
        }

        // Legitimate transaction debit/credit alerts
        if ((lowerText.contains("debited") || lowerText.contains("credited") || lowerText.contains("was successful")) &&
            (lowerText.contains("inr") || lowerText.contains("rs") || lowerText.contains("a/c")) &&
            !lowerText.contains("http") && !lowerText.contains("click") && !lowerText.contains("verify now")) {
            isLegitBankAlert = true;
        }

        // Legitimate college or work schedule
        if ((lowerText.contains("meeting starts") || lowerText.contains("class starts") || lowerText.contains("timetable") ||
             lowerText.contains("fee receipt") || lowerText.contains("college portal") || lowerText.contains("office")) &&
            !lowerText.contains("http") && !lowerText.contains("otp") && !lowerText.contains("won")) {
            isLegitCollegeOrWork = true;
        }

        // Check OTP pattern & solicitation
        Matcher otpMatcher = OTP_PATTERN.matcher(text);
        if (otpMatcher.find() || lowerText.contains("otp") || lowerText.contains("pin")) {
            if (lowerText.contains("share") || lowerText.contains("give") || lowerText.contains("send us") || lowerText.contains("agent to unlock")) {
                hasOtpRequest = true;
                result.indicators.add("Request for sensitive OTP or verification PIN");
            } else if (lowerText.contains("do not share") || lowerText.contains("never share") || lowerText.contains("don't share")) {
                result.indicators.add("Standard safety advisory: Do not share OTP");
            }
        }

        // Urgency / Pressure to act quickly
        if (lowerText.contains("immediately") || lowerText.contains("act now") || lowerText.contains("blocked today") ||
            lowerText.contains("in 30 minutes") || lowerText.contains("suspended") || lowerText.contains("within 24 hours") ||
            lowerText.contains("deactivated today") || lowerText.contains("frozen")) {
            hasUrgency = true;
            result.indicators.add("Pressure to act quickly");
        }

        // Banking / Account credentials request
        if (lowerText.contains("bank details") || lowerText.contains("card details") || lowerText.contains("netbanking") ||
            lowerText.contains("kyc") || lowerText.contains("verify your details") || lowerText.contains("enter bank") ||
            lowerText.contains("password")) {
            hasBankingLure = true;
            result.indicators.add("Request for sensitive banking or login details");
        }

        // Delivery lures
        if (lowerText.contains("failed delivery") || lowerText.contains("parcel is on hold") || lowerText.contains("release fee")) {
            hasDeliveryLure = true;
            result.indicators.add("Courier redelivery fee or address update lure");
        }

        // Utility lures
        if (lowerText.contains("electricity will be disconnected") || lowerText.contains("power disconnected")) {
            hasUtilityLure = true;
            result.indicators.add("Urgent utility disconnection threat");
        }

        // URL Analysis (Domain, TLD, Subdomains)
        for (String url : extractedUrls) {
            String cleanUrl = url.toLowerCase(Locale.ROOT);
            for (String tld : HIGH_RISK_TLDS) {
                if (cleanUrl.contains(tld)) {
                    hasSuspiciousUrl = true;
                    result.indicators.add("Dangerous link using high-risk web domain (" + tld + ")");
                    break;
                }
            }
            if (cleanUrl.contains(".example.invalid") || cleanUrl.contains("urgent-update") || cleanUrl.contains("reward-claim") || cleanUrl.contains("wallet-recovery")) {
                hasSuspiciousUrl = true;
                result.indicators.add("Deceptive link attempting to mimic an official service");
            }
            for (String brand : BRAND_KEYWORDS) {
                if (cleanUrl.contains(brand) && !isOfficialDomain(cleanUrl, brand)) {
                    hasSuspiciousUrl = true;
                    result.indicators.add("Deceptive link mimicking brand (" + brand.toUpperCase(Locale.ROOT) + ")");
                    break;
                }
            }
        }

        // 5. Final Risk Scoring & Classification Decision
        double combinedThreatProb = pScam + pPhishing;
        int score = 0;

        if ((isLegitBankAlert || isLegitCollegeOrWork) && !hasSuspiciousUrl && !hasOtpRequest && !hasPrizeClaim && combinedThreatProb < 0.25) {
            // High confidence normal / benign
            result.predictedClass = "BENIGN";
            result.riskLevel = "LOW";
            result.riskScore = 5;
            result.explanation = "No obvious warning signs found in this message.";
            result.recommendedAction = "Standard vigilance is recommended. No action required.";
            return result;
        }

        // Base score calculated from model output probabilities
        score = (int) (combinedThreatProb * 70.0 + maxUrlMlScore * 30.0);

        // Add heuristic risk weights
        if (hasPrizeClaim) score += 25;
        if (hasOtpRequest) score += 35;
        if (hasBankingLure) score += 25;
        if (hasUrgency) score += 15;
        if (hasSuspiciousUrl) score += 25;
        if (hasDeliveryLure) score += 20;
        if (hasUtilityLure) score += 20;

        score = Math.min(Math.max(score, 0), 100);
        result.riskScore = score;

        // Calibrated risk levels (Section 5)
        if (score >= 70 || pScam >= 0.65 || pPhishing >= 0.65) {
            result.riskLevel = "HIGH";
            if (result.predictedClass.equals("BENIGN")) {
                result.predictedClass = hasBankingLure || hasSuspiciousUrl ? "PHISHING" : "SCAM";
            }
            if (result.predictedClass.equals("PHISHING")) {
                result.explanation = "This message may be trying to steal your account passwords or banking details.";
            } else {
                result.explanation = "This message may be a scam attempting to trick you into payments or sharing personal information.";
            }
            result.recommendedAction = "Do not share your bank details, passwords or OTP. Do not open suspicious links.";
        } else if (score >= 40 || combinedThreatProb >= 0.35) {
            result.riskLevel = "MEDIUM";
            result.explanation = "This message looks unusual. Please check it carefully before responding.";
            result.recommendedAction = "Verify with the sender through official channels before sharing any information.";
        } else {
            result.riskLevel = "LOW";
            result.predictedClass = "BENIGN";
            result.explanation = "No obvious warning signs found in this content.";
            result.recommendedAction = "Content passed baseline checks. Keep security vigilance active.";
        }

        return result;
    }

    private double[] predictText3Class(String text) {
        if (!isModelLoaded || vocabulary.isEmpty() || classWeights.size() < 3) {
            return new double[]{0.8, 0.1, 0.1}; // Safe fallback
        }

        List<String> tokens = cleanTokens(text);
        Map<Integer, Double> x = new HashMap<>();
        Map<String, Integer> tf = new HashMap<>();

        for (String t : tokens) {
            tf.put(t, tf.getOrDefault(t, 0) + 1);
        }

        double normSq = 0.0;
        for (Map.Entry<String, Integer> entry : tf.entrySet()) {
            String tok = entry.getKey();
            if (vocabulary.containsKey(tok)) {
                int idx = vocabulary.get(tok);
                double idf = (idx < idfWeights.size()) ? idfWeights.get(idx) : 1.0;
                double val = (1.0 + Math.log(entry.getValue())) * idf;
                x.put(idx, val);
                normSq += val * val;
            }
        }

        if (normSq > 0) {
            double norm = Math.sqrt(normSq);
            for (Map.Entry<Integer, Double> e : x.entrySet()) {
                x.put(e.getKey(), e.getValue() / norm);
            }
        }

        // Compute 3 class logits
        double[] logits = new double[3];
        for (int c = 0; c < 3; c++) {
            logits[c] = (c < classBiases.size()) ? classBiases.get(c) : 0.0;
            List<Double> wRow = classWeights.get(c);
            for (Map.Entry<Integer, Double> e : x.entrySet()) {
                int idx = e.getKey();
                if (idx < wRow.size()) {
                    logits[c] += wRow.get(idx) * e.getValue();
                }
            }
        }

        // Softmax
        double maxL = Math.max(logits[0], Math.max(logits[1], logits[2]));
        double sumExp = 0.0;
        double[] probs = new double[3];
        for (int c = 0; c < 3; c++) {
            probs[c] = Math.exp(Math.min(Math.max(logits[c] - maxL, -40.0), 40.0));
            sumExp += probs[c];
        }
        if (sumExp > 0) {
            for (int c = 0; c < 3; c++) probs[c] /= sumExp;
        } else {
            probs[0] = 1.0;
        }

        return probs;
    }

    private double predictUrl(String url) {
        if (!isModelLoaded || urlWeights.isEmpty()) {
            return 0.1;
        }
        double[] rawFeats = new double[11];
        String lowerUrl = url.toLowerCase(Locale.ROOT);

        rawFeats[0] = countChar(lowerUrl, '.');              // qty_dot_url
        rawFeats[1] = countChar(lowerUrl, '-');              // qty_hyphen_url
        rawFeats[2] = countChar(lowerUrl, '_');              // qty_underline_url
        rawFeats[3] = countChar(lowerUrl, '/');              // qty_slash_url
        rawFeats[4] = countChar(lowerUrl, '@');              // qty_at_url
        rawFeats[5] = lowerUrl.length();                     // length_url

        String host = extractHost(lowerUrl);
        rawFeats[6] = countChar(host, '.');                  // qty_dot_domain
        rawFeats[7] = countChar(host, '-');                  // qty_hyphen_domain
        rawFeats[8] = host.length();                         // domain_length
        rawFeats[9] = isIpAddress(host) ? 1.0 : 0.0;         // domain_in_ip
        rawFeats[10] = (lowerUrl.contains("bit.ly") || lowerUrl.contains("tinyurl")) ? 1.0 : 0.0;

        double dot = urlBias;
        for (int i = 0; i < 11; i++) {
            double m = (i < urlMeans.size()) ? urlMeans.get(i) : 0.0;
            double s = (i < urlStds.size() && urlStds.get(i) > 1e-5) ? urlStds.get(i) : 1.0;
            double normVal = (rawFeats[i] - m) / s;
            double w = (i < urlWeights.size()) ? urlWeights.get(i) : 0.0;
            dot += w * normVal;
        }

        return 1.0 / (1.0 + Math.exp(-Math.max(Math.min(dot, 20.0), -20.0)));
    }

    private List<String> cleanTokens(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        lower = lower.replaceAll("https?://\\S+|www\\.\\S+", " url_token ");
        lower = lower.replaceAll("\\b\\d{6}\\b", " otp_token ");
        lower = lower.replaceAll("\\brs\\.?\\s*\\d+\\b|\\binr\\s*\\d+\\b", " rs_token ");
        lower = lower.replaceAll("\\b\\d+\\b", " num_token ");

        List<String> words = new ArrayList<>();
        Matcher m = Pattern.compile("\\b[a-z_]{2,}\\b").matcher(lower);
        while (m.find()) {
            words.add(m.group());
        }

        List<String> list = new ArrayList<>(words);
        for (int i = 0; i < words.size() - 1; i++) {
            list.add(words.get(i) + "_" + words.get(i + 1));
        }
        return list;
    }

    private int countChar(String str, char c) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == c) count++;
        }
        return count;
    }

    private String extractHost(String url) {
        String s = url;
        if (s.contains("://")) {
            s = s.substring(s.indexOf("://") + 3);
        }
        int slash = s.indexOf('/');
        if (slash != -1) {
            s = s.substring(0, slash);
        }
        int colon = s.indexOf(':');
        if (colon != -1) {
            s = s.substring(0, colon);
        }
        return s;
    }

    private boolean isIpAddress(String host) {
        return host.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    }

    private boolean isOfficialDomain(String url, String brand) {
        String host = extractHost(url);
        if (brand.equals("sbi") && (host.endsWith("onlinesbi.sbi") || host.endsWith("sbi.co.in"))) return true;
        if (brand.equals("hdfc") && (host.endsWith("hdfcbank.com") || host.endsWith("hdfc.com"))) return true;
        if (brand.equals("icici") && (host.endsWith("icicibank.com"))) return true;
        if (brand.equals("amazon") && (host.endsWith("amazon.in") || host.endsWith("amazon.com"))) return true;
        if (brand.equals("google") && (host.endsWith("google.com") || host.endsWith("google.co.in"))) return true;
        if (brand.equals("indiapost") && (host.endsWith("indiapost.gov.in"))) return true;
        return false;
    }
}

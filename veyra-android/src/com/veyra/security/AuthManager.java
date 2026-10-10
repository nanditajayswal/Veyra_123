package com.veyra.security;

import android.content.Context;
import org.json.JSONObject;

public class AuthManager {
    // Secret provisioning token for administrative setup (not selectable in public registration)
    private static final String ADMIN_PROVISIONING_TOKEN = "VEYRA-ADMIN-SETUP-2026";

    private final DatabaseHelper dbHelper;
    private JSONObject currentUser = null;

    public AuthManager(Context context) {
        this.dbHelper = DatabaseHelper.getInstance(context);
        // Provision initial admin if none exists
        ensureDefaultAdmin();
    }

    private void ensureDefaultAdmin() {
        if (dbHelper.getUserCount() == 0) {
            // Provision initial security officer with default salt/hash
            dbHelper.registerUser("admin", "AdminVeyra@2026!", "admin");
        }
    }

    public JSONObject login(String username, String password) {
        if (username == null || password == null || username.trim().isEmpty() || password.isEmpty()) {
            return createError("Username and password cannot be empty.");
        }
        JSONObject user = dbHelper.authenticateUser(username.trim(), password);
        if (user != null) {
            currentUser = user;
            JSONObject res = new JSONObject();
            try {
                res.put("success", true);
                res.put("user", user);
            } catch (Exception ignored) {}
            return res;
        } else {
            return createError("Invalid username or password.");
        }
    }

    public JSONObject register(String username, String password, String adminToken) {
        if (username == null || password == null || username.trim().length() < 3 || password.length() < 6) {
            return createError("Username must be at least 3 characters and password at least 6 characters.");
        }

        String role = "user";
        if (adminToken != null && !adminToken.trim().isEmpty()) {
            if (ADMIN_PROVISIONING_TOKEN.equals(adminToken.trim())) {
                role = "admin";
            } else {
                return createError("Invalid administrator setup authorization code. Registration denied.");
            }
        }

        boolean success = dbHelper.registerUser(username.trim(), password, role);
        if (success) {
            return login(username, password);
        } else {
            return createError("Username already exists or registration failed.");
        }
    }

    public void logout() {
        currentUser = null;
    }

    public JSONObject getCurrentUser() {
        return currentUser;
    }

    public boolean isAdmin() {
        if (currentUser == null) return false;
        return "admin".equals(currentUser.optString("role", ""));
    }

    private JSONObject createError(String msg) {
        JSONObject res = new JSONObject();
        try {
            res.put("success", false);
            res.put("message", msg);
        } catch (Exception ignored) {}
        return res;
    }
}

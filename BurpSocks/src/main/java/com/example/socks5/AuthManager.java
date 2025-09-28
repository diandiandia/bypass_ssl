package com.example.socks5;

import org.mindrot.jbcrypt.BCrypt;

import java.util.HashMap;
import java.util.Map;

public class AuthManager {
    private final Map<String, String> users = new HashMap<>();
    private final boolean authEnabled;

    public AuthManager(Config.Auth cfg) {
        if (cfg != null && cfg.users != null && cfg.enabled) {
            this.authEnabled = true;
            for (Map<String, String> u : cfg.users) {
                String username = u.get("username");
                String password = u.get("password");
                if (username != null && password != null) {
                    // 允许明文或哈希混用
                    if (password.startsWith("$2a$") || password.startsWith("$2b$")) {
                        users.put(username, password);
                    } else {
                        users.put(username, BCrypt.hashpw(password, BCrypt.gensalt()));
                    }
                }
            }
        } else {
            this.authEnabled = false;
        }
    }

    public boolean isEnabled() {
        return authEnabled;
    }

    public boolean authenticate(String user, String pass) {
        if (!authEnabled) return true;
        String stored = users.get(user);
        return stored != null && BCrypt.checkpw(pass, stored);
    }
}

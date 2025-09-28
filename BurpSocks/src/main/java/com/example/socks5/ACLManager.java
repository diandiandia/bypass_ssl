package com.example.socks5;

import java.util.List;

public class ACLManager {
    private final List<String> allow;
    private final List<String> deny;

    public ACLManager(Config.ACL cfg) {
        this.allow = (cfg != null ? cfg.allow : null);
        this.deny = (cfg != null ? cfg.deny : null);
    }

    public boolean permit(String host) {
        // 处理 IPv6 地址的简化形式
        String normalizedHost = normalizeHost(host);
        
        if (deny != null) {
            for (String d : deny) {
                if (normalizedHost.endsWith(normalizeHost(d))) return false;
            }
        }
        if (allow != null) {
            for (String a : allow) {
                if (normalizedHost.endsWith(normalizeHost(a))) return true;
            }
            return false;
        }
        return true;
    }
    
    private String normalizeHost(String host) {
        // 简化 IPv6 地址处理（实际项目中可能需要更复杂的逻辑）
        if (host.contains(":") && !host.contains(".")) {
            // 可能是 IPv6 地址，转换为小写并移除可能的方括号
            return host.toLowerCase().replace("[", "").replace("]", "");
        }
        return host.toLowerCase();
    }
}

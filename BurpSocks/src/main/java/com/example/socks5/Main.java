package com.example.socks5;

public class Main {
    public static void main(String[] args) throws Exception {
        String configPath = args.length > 0 ? args[0] : "config.yaml";
        Config cfg = Config.load(configPath);

        AuthManager authManager = new AuthManager(cfg.auth);
        ACLManager aclManager = new ACLManager(cfg.acl);

        Socks5Server server = new Socks5Server(cfg, authManager, aclManager);
        server.start();
    }
}

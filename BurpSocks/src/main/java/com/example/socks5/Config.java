package com.example.socks5;

import java.io.File;

// 移除所有 Jackson/YAML 相关的 import

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class Config {
    // 默认值将由 Burp UI 的 SettingPanelSetting 提供
    public int port = 1080;
    public Auth auth;
    public ACL acl;
    public Proxy proxy;

    public static class Auth {
        public boolean enabled = false;
        public List<Map<String, String>> users;
    }

    public static class ACL {
        public List<String> allow;
        public List<String> deny;
    }

    public static class Proxy{
        public boolean enabled = false;
        public String host;
        public int port;
        public int timeout = 10000;
    }

    // 移除 load(String path) 方法，配置将从 Burp UI 传入
    // public static Config load(String path) throws Exception { ... } 
    
    // 添加一个构造函数来方便从 UI 配置中创建新的 Config 实例
    public Config(int port, String proxyHost, int proxyPort, boolean proxyEnabled) {
        this.port = port;
        this.proxy = new Proxy();
        this.proxy.enabled = proxyEnabled;
        this.proxy.host = proxyHost;
        this.proxy.port = proxyPort;
        // ACL 和 Auth 暂时保持 null，需要时再通过其他方式配置
    }
    
    // 默认构造函数，用于保留 ACL 和 Auth 配置的默认值
    public Config() {}

    public static Config load(String path) throws Exception {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        return mapper.readValue(new File(path), Config.class);
    }
}
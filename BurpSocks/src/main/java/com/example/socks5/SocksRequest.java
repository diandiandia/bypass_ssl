package com.example.socks5;

public class SocksRequest {
    public byte cmd;
    public String host;
    public int port;

    public SocksRequest(byte cmd, String host, int port) {
        this.cmd = cmd;
        this.host = host;
        this.port = port;
    }
}

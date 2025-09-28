package com.example.socks5;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

public class Socks5Server {
    private static final Logger logger = LoggerFactory.getLogger(Socks5Server.class);

    private final Config cfg;
    private final AuthManager authManager;
    private final ACLManager aclManager;
    private volatile ServerSocket serverSocket; // 声明为 volatile 且可访问

    public Socks5Server(Config cfg, AuthManager authManager, ACLManager aclManager) {
        this.cfg = cfg;
        this.authManager = authManager;
        this.aclManager = aclManager;
    }

    public void start() throws Exception {
        // 使用成员变量
        serverSocket = new ServerSocket(cfg.port); 
        logger.info("SOCKS5 server listening on port {}", cfg.port);
        while (!serverSocket.isClosed()) {
            try {
                Socket client = serverSocket.accept();
                logger.info("New connection from {}", client.getRemoteSocketAddress());
                new Thread(new Socks5Handler(client, cfg, authManager, aclManager)).start();
            } catch (SocketException e) {
                // 当 stop() 被调用时，serverSocket.accept() 会抛出 SocketException
                if (serverSocket.isClosed()) {
                    logger.info("SOCKS5 Server socket closed. Shutting down.");
                    break;
                }
                throw e; // 其他 SocketException 仍需处理
            }
        }
    }
    
    // 新增：停止方法，用于热更新/卸载扩展
    public void stop() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
                logger.info("SOCKS5 Server stopped successfully.");
            } catch (Exception e) {
                logger.error("Error stopping SOCKS5 Server: {}", e.getMessage());
            }
        }
    }
}
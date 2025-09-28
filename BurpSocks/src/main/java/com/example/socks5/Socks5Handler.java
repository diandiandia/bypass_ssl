package com.example.socks5;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;

public class Socks5Handler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(Socks5Handler.class);

    private final Socket client;
    private final AuthManager authManager;
    private final ACLManager aclManager;
    private final Config cfg;

    public Socks5Handler(Socket client, Config cfg, AuthManager authManager, ACLManager aclManager) {
        this.client = client;
        this.cfg = cfg;
        this.authManager = authManager;
        this.aclManager = aclManager;
    }

    @Override
    public void run() {
        InputStream in = null;
        OutputStream out = null;
        boolean handled = false;
        try {
            in = client.getInputStream();
            out = client.getOutputStream();
            if (!handshake(in, out)) return;
            SocksRequest req = parseRequest(in);
            if (req == null) return;
            logger.info("Request host: {}, port: {} and cmd: {}.", req.host, req.port, req.cmd);
            if (req.cmd == 0x01) {
                handled = handleConnect(req, out);
            } else if (req.cmd == 0x02) {
                logger.info("BIND not supported");
                sendReply(out, (byte) 0x07, "0.0.0.0", 0); // Command not supported
            } else if (req.cmd == 0x03) {
                if (cfg.proxy != null && cfg.proxy.enabled) {
                    logger.info("UDP ASSOCIATE not supported with HTTP proxy");
                    sendReply(out, (byte) 0x07, "0.0.0.0", 0); // Command not supported
                } else {
                    handleUdpAssociate(req, out);
                    handled = true; // UDP waits in its loop
                }
            } else {
                sendReply(out, (byte) 0x07, "0.0.0.0", 0); // Service not supported
            }
        } catch (IOException e) {
            logger.warn("Client {} error: {}", client.getRemoteSocketAddress(), e.getMessage());
        } finally {
            if (!handled) {
                try { client.close(); } catch (IOException ignored) {}
            }
        }
    }

    private boolean handshake(InputStream in, OutputStream out) throws IOException {
        int ver = in.read();
        if (ver != 0x05) return false;
        int nMethods = in.read();
        byte[] methods = in.readNBytes(nMethods);
        
        // 检查是否支持 IPv6 (方法 0x04)
        boolean supportsIPv6 = false;
        for (byte method : methods) {
            if (method == 0x04) {
                supportsIPv6 = true;
                break;
            }
        }
        
        logger.debug("Client supports IPv6: {}", supportsIPv6);

        if (authManager.isEnabled()) {
            out.write(new byte[]{0x05, 0x02}); // username/password
            out.flush();
            if (!doUserPassAuth(in, out)) return false;
        } else {
            out.write(new byte[]{0x05, 0x00});
            out.flush();
        }
        return true;
    }

    private boolean doUserPassAuth(InputStream in, OutputStream out) throws IOException {
        int ver = in.read();
        if (ver != 0x01) return false;
        int ulen = in.read();
        String user = new String(in.readNBytes(ulen));
        int plen = in.read();
        String pass = new String(in.readNBytes(plen));

        boolean ok = authManager.authenticate(user, pass);
        out.write(new byte[]{0x01, (byte) (ok ? 0x00 : 0x01)});
        out.flush();
        return ok;
    }

    private SocksRequest parseRequest(InputStream in) throws IOException {
        int ver = in.read(); if (ver != 0x05) return null;
        int cmd = in.read();
        in.read(); // RSV
        int atyp = in.read();
        String host = null;

        if (atyp == 0x01) {
            byte[] addr = in.readNBytes(4);
            host = (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "." + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
        } else if (atyp == 0x03) {
            int len = in.read();
            host = new String(in.readNBytes(len));
        } else if (atyp == 0x04) {
            byte[] addr = in.readNBytes(16);
            host = InetAddress.getByAddress(addr).getHostAddress();
        }

        int port = (in.read() << 8) | in.read();
        return new SocksRequest((byte) cmd, host, port);
    }

    /**
     * 构建HTTP CONNECT请求，正确处理IPv6地址格式
     */
    private String buildConnectRequest(SocksRequest req) {
        // IPv6 地址需要放在方括号中
        String hostForConnect = req.host;
        if (hostForConnect.contains(":") && !hostForConnect.contains(".")) {
            // 可能是 IPv6 地址（包含冒号但不包含点）
            try {
                InetAddress addr = InetAddress.getByName(hostForConnect);
                if (addr instanceof Inet6Address) {
                    hostForConnect = "[" + hostForConnect + "]";
                    logger.debug("IPv6 address detected and formatted: {}", hostForConnect);
                }
            } catch (UnknownHostException e) {
                logger.debug("Failed to parse host as IPv6: {}, using as-is", hostForConnect);
            }
        }
        
        String connectRequest = "CONNECT " + hostForConnect + ":" + req.port + " HTTP/1.1\r\n" +
            "Host: " + hostForConnect + ":" + req.port + "\r\n" +
            "Connection: keep-alive\r\n\r\n";
        
        logger.debug("Built CONNECT request: {}", connectRequest.replace("\r\n", "\\r\\n"));
        return connectRequest;
    }
    private boolean handleConnect(SocksRequest req, OutputStream out) throws IOException {
        logger.info("Client {} connecting to {}:{}", client.getRemoteSocketAddress(), req.host, req.port);
        if (req.host == null || (aclManager != null && !aclManager.permit(req.host))) {
            sendReply(out, (byte) 0x02, "0.0.0.0", 0); // Connection not allowed by ruleset
            return false;
        }

        if (cfg.proxy != null && cfg.proxy.enabled) {
            // 通过HTTP代理转发
            try {
                Socket proxySocket = new Socket(cfg.proxy.host, cfg.proxy.port);
                proxySocket.setSoTimeout(cfg.proxy.timeout); // 10秒超时

                // 发送HTTP CONNECT请求
                OutputStream proxyOut = proxySocket.getOutputStream();
                InputStream proxyIn = proxySocket.getInputStream();
                // String connectReq = "CONNECT " + req.host + ":" + req.port + " HTTP/1.1\r\n" +
                //         "Host: " + req.host + ":" + req.port + "\r\n" +
                //         "Connection: keep-alive\r\n\r\n";
                String connectReq = buildConnectRequest(req);
                proxyOut.write(connectReq.getBytes("UTF-8"));
                proxyOut.flush();

                // In handleConnect, replace the HTTP response check
                String response = readHttpResponse(proxyIn);
                if (!response.contains("200 Connection established")) {
                    logger.warn("HTTP proxy rejected CONNECT: {}", response);
                    sendReply(out, (byte) 0x05, "0.0.0.0", 0);
                    proxySocket.close();
                    return false;
                }
                logger.info("HTTP proxy CONNECT successful: {}", response);

                // 成功：发送SOCKS5成功回复，并pipe数据
                sendReply(out, (byte) 0x00, req.host, req.port); // 使用目标地址作为bindAddr
                Thread t1 = new Thread(() -> pipe(client, proxySocket), "Pipe-ClientToProxy-" + client.getPort());
                Thread t2 = new Thread(() -> pipe(proxySocket, client), "Pipe-ProxyToClient-" + client.getPort());
                t1.start();
                t2.start();
                return true;  // Handed off successfully
            } catch (UnknownHostException e) {
                logger.warn("Unknown proxy host {}: {}", cfg.proxy.host, e.getMessage());
                sendReply(out, (byte) 0x04, "0.0.0.0", 0); // Host unreachable
                return false;
            } catch (IOException e) {
                logger.warn("Connection via proxy to {}:{} failed: {}", req.host, req.port, e.getMessage());
                sendReply(out, (byte) 0x05, "0.0.0.0", 0); // Connection failed
                return false;
            }
        } else {
            // 原有直接连接逻辑（无变化）
            try {
                Socket remote = new Socket();
                remote.connect(new InetSocketAddress(req.host, req.port), 5000); // 5-second timeout
                sendReply(out, (byte) 0x00, req.host, req.port); // Success
                Thread t1 = new Thread(() -> pipe(client, remote), "Pipe-ClientToRemote-" + client.getPort());
                Thread t2 = new Thread(() -> pipe(remote, client), "Pipe-RemoteToClient-" + client.getPort());
                t1.start();
                t2.start();
                return true;  // Handed off successfully
            } catch (UnknownHostException e) {
                logger.warn("Unknown host {}: {}", req.host, e.getMessage());
                sendReply(out, (byte) 0x04, "0.0.0.0", 0); // Host unreachable
                return false;
            } catch (IOException e) {
                logger.warn("Connection to {}:{} failed: {}", req.host, req.port, e.getMessage());
                sendReply(out, (byte) 0x05, "0.0.0.0", 0); // Connection failed
                return false;
            }
        }
    }

    private String readHttpResponse(InputStream in) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String statusLine = reader.readLine();
        
        if (statusLine == null) {
            throw new IOException("Empty response from HTTP proxy");
        }
        
        logger.info("HTTP proxy status line: {}", statusLine);
        
        // 读取并跳过所有头部信息，直到空行
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            logger.debug("HTTP proxy header: {}", line);
        }
        
        return statusLine;
    }

    private void handleUdpAssociate(SocksRequest req, OutputStream out) throws IOException {
        DatagramSocket ds = new DatagramSocket(0);
        ds.setReuseAddress(true);

        UdpRelay relay = new UdpRelay(ds, aclManager,
                ((InetSocketAddress) client.getRemoteSocketAddress()).getAddress());
        Thread relayThread = new Thread(relay, "UdpRelay-" + client.getPort());
        relayThread.setDaemon(true);
        relayThread.start();

        InetSocketAddress bind = relay.getBindAddress();
        sendReply(out, (byte) 0x00, bind.getAddress().getHostAddress(), bind.getPort());
        logger.info("UDP ASSOCIATE established for {}", client.getRemoteSocketAddress());

        while (!client.isClosed()) {
            try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        }
        relay.stop();
    }

    private void pipe(Socket inSock, Socket outSock) {
        logger.info("Starting pipe: inSock={}, outSock={}", inSock, outSock);
        try (InputStream in = inSock.getInputStream(); OutputStream out = outSock.getOutputStream()) {
            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) != -1) {
                // 记录所有从客户端接收的数据包
                if (inSock.getRemoteSocketAddress().equals(client.getRemoteSocketAddress())) {
                    logger.info("Packet from client ({} bytes): {}", len, bytesToHex(buf, len));
                }
                out.write(buf, 0, len);
                out.flush();
                logger.info("Transferred {} bytes from {} to {}", len, inSock.getRemoteSocketAddress(), outSock.getRemoteSocketAddress());
            }
            logger.info("Pipe closed: inSock={} (EOF received)", inSock.getRemoteSocketAddress());
        } catch (IOException e) {
            logger.warn("Pipe error between {} and {}: {}", inSock.getRemoteSocketAddress(), outSock.getRemoteSocketAddress(), e.getMessage(), e);
        } finally {
            try { inSock.close(); } catch (IOException ignored) {}
            try { outSock.close(); } catch (IOException ignored) {}
        }
    }

    // 辅助方法：将字节数组转为十六进制字符串
    private String bytesToHex(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x ", bytes[i]));
        }
        return sb.toString().trim();
    }

    private void sendReply(OutputStream out, byte rep, String bindAddr, int bindPort) throws IOException {
        ByteArrayOutputStream resp = new ByteArrayOutputStream();
        resp.write(0x05); 
        resp.write(rep); 
        resp.write(0x00);

        InetAddress addr = InetAddress.getByName(bindAddr);
        byte[] raw = addr.getAddress();
        
        // 修复逻辑：优先检查 IPv4
        if (addr instanceof Inet4Address) {
            resp.write(0x01); // IPv4
            resp.write(raw);
        } else if (addr instanceof Inet6Address) {
            resp.write(0x04); // IPv6
            resp.write(raw);
        } else {
            throw new IOException("Unsupported address type: " + bindAddr);
        }
        
        resp.write((bindPort >> 8) & 0xFF);
        resp.write(bindPort & 0xFF);

        out.write(resp.toByteArray());
        out.flush();
    }
}

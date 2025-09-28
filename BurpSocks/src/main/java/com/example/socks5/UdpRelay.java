package com.example.socks5;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/**
 * UDP relay for SOCKS5 UDP ASSOCIATE command.
 * Manages a single DatagramSocket for both client<->target traffic.
 */
public class UdpRelay implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(UdpRelay.class);

    private final DatagramSocket socket;
    private final ACLManager aclManager;
    private final InetAddress clientIp; // TCP client IP for validation
    private final AtomicReference<InetSocketAddress> lastSeenClientUdp = new AtomicReference<>(null);

    private volatile boolean running = true;

    public UdpRelay(DatagramSocket socket, ACLManager aclManager, InetAddress clientIp) {
        this.socket = socket;
        this.aclManager = aclManager;
        this.clientIp = clientIp;
    }

    @Override
    public void run() {
        byte[] buf = new byte[65535];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);

        while (running && !socket.isClosed()) {
            try {
                socket.receive(packet);
                InetAddress srcAddr = packet.getAddress();
                int srcPort = packet.getPort();
                int len = packet.getLength();
                byte[] data = Arrays.copyOfRange(packet.getData(), 0, len);

                // 判定是来自 client 还是来自 target
                if (srcAddr.equals(clientIp)) {
                    handleFromClient(srcAddr, srcPort, data);
                } else {
                    handleFromTarget(srcAddr, srcPort, data);
                }
            } catch (SocketException se) {
                break; // socket closed
            } catch (IOException e) {
                if (running) logger.warn("UDP relay error: {}", e.getMessage());
            }
        }
    }

    private void handleFromClient(InetAddress srcAddr, int srcPort, byte[] data) {
        if (data.length < 4) return;

        int pos = 0;
        int rsv1 = data[pos++] & 0xFF;
        int rsv2 = data[pos++] & 0xFF;
        int frag = data[pos++] & 0xFF;
        if (frag != 0) {
            logger.debug("Drop fragmented UDP packet from client");
            return;
        }
        int atyp = data[pos++] & 0xFF;

        String dstAddr;
        try {
            if (atyp == 0x01) { // IPv4
                if (pos + 4 > data.length) return;
                dstAddr = (data[pos++] & 0xFF) + "." + (data[pos++] & 0xFF) + "." + (data[pos++] & 0xFF) + "." + (data[pos++] & 0xFF);
            } else if (atyp == 0x03) { // DOMAIN
                int dlen = data[pos++] & 0xFF;
                if (pos + dlen > data.length) return;
                dstAddr = new String(Arrays.copyOfRange(data, pos, pos + dlen));
                pos += dlen;
            } else if (atyp == 0x04) { // IPv6
                if (pos + 16 > data.length) return;
                byte[] a6 = Arrays.copyOfRange(data, pos, pos + 16);
                dstAddr = InetAddress.getByAddress(a6).getHostAddress();
                pos += 16;
            } else {
                return;
            }
        } catch (Exception e) {
            return;
        }

        if (pos + 2 > data.length) return;
        int dstPort = ((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF);
        byte[] payload = Arrays.copyOfRange(data, pos, data.length);

        if (aclManager != null && !aclManager.permit(dstAddr)) {
            logger.info("ACL denies UDP access to {}", dstAddr);
            return;
        }

        try {
            InetAddress targetIp = InetAddress.getByName(dstAddr);
            DatagramPacket outp = new DatagramPacket(payload, payload.length, targetIp, dstPort);
            socket.send(outp); // use same socket
            lastSeenClientUdp.set(new InetSocketAddress(srcAddr, srcPort));
        } catch (IOException e) {
            logger.warn("Send UDP to {}:{} failed: {}", dstAddr, dstPort, e.getMessage());
        }
    }

    private void handleFromTarget(InetAddress fromAddr, int fromPort, byte[] data) {
        InetSocketAddress clientUdp = lastSeenClientUdp.get();
        if (clientUdp == null) {
            logger.debug("No client UDP address known, drop target packet");
            return;
        }

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(0x00); baos.write(0x00); // RSV
            baos.write(0x00); // FRAG

            byte[] fbytes = fromAddr.getAddress();
            if (fbytes.length == 4) {
                baos.write(0x01);
                baos.write(fbytes);
            } else if (fbytes.length == 16) {
                baos.write(0x04);
                baos.write(fbytes);
            } else return;

            baos.write((fromPort >> 8) & 0xFF);
            baos.write(fromPort & 0xFF);
            baos.write(data);

            byte[] outPacket = baos.toByteArray();
            DatagramPacket sendBack = new DatagramPacket(outPacket, outPacket.length,
                    clientUdp.getAddress(), clientUdp.getPort());
            socket.send(sendBack);
        } catch (IOException e) {
            logger.warn("Send UDP back to client failed: {}", e.getMessage());
        }
    }

    public void stop() {
        running = false;
        socket.close();
    }

    public InetSocketAddress getBindAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }
}

package com.cyber.dpi.capture;

import com.cyber.dpi.detector.ThreatDetectionEngine;
import com.cyber.dpi.model.PacketLog;

import java.util.Random;

public class PacketSimulator implements Runnable {
    private volatile boolean running = false;
    private Thread thread = null;
    private final Random rand = new Random();
    private int delayMs = 500; // Speed of simulation in milliseconds

    private static final String[] SAFE_IPS = {
            "192.168.1.12", "192.168.1.45", "10.0.0.15", "10.0.0.102", 
            "8.8.8.8", "1.1.1.1", "142.250.190.46", "34.120.54.21", 
            "172.217.16.142", "204.79.197.200"
    };

    private static final String[] BLOCKED_IPS_POOL = {
            "45.33.22.11", "185.220.101.5", "192.168.1.150"
    };

    private static final String[] SAFE_DOMAINS = {
            "google.com", "github.com", "wikipedia.org", "stackoverflow.com", 
            "java.com", "microsoft.com", "youtube.com", "netflix.com"
    };

    private static final String[] BLOCKED_DOMAINS_POOL = {
            "bad-malware-site.com", "phishing-bank-login.net", "gambling-hub.org", 
            "unauthorized-torrent.cc", "tor-exit-node.xyz"
    };

    public synchronized void start() {
        if (!running) {
            running = true;
            thread = new Thread(this, "PacketSimulatorThread");
            thread.start();
            System.out.println("Packet Simulator started.");
        }
    }

    public synchronized void stop() {
        if (running) {
            running = false;
            if (thread != null) {
                thread.interrupt();
            }
            System.out.println("Packet Simulator stopped.");
        }
    }

    public boolean isRunning() {
        return running;
    }

    public void setDelayMs(int delayMs) {
        this.delayMs = delayMs;
    }

    @Override
    public void run() {
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(delayMs + rand.nextInt(delayMs / 2 + 1));
                
                PacketLog simulatedPacket = generateMockPacket();
                ThreatDetectionEngine.processPacket(simulatedPacket);
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                System.err.println("Error generating simulated packet: " + e.getMessage());
            }
        }
    }

    private PacketLog generateMockPacket() {
        int chance = rand.nextInt(100);
        
        String srcIp;
        String destIp;
        int srcPort = rand.nextInt(64511) + 1024;
        int destPort;
        String protocol;
        String payload = "";

        if (chance < 65) {
            // A. Normal clean traffic (65% chance)
            srcIp = getRandomElement(SAFE_IPS);
            destIp = getRandomElement(SAFE_IPS);
            while (srcIp.equals(destIp)) {
                destIp = getRandomElement(SAFE_IPS);
            }
            
            int protoChoice = rand.nextInt(4);
            if (protoChoice == 0) {
                protocol = "TCP";
                destPort = rand.nextInt(64511) + 1024;
                payload = "TCP connection data chunk. Sequence: " + rand.nextInt(100000) + ", Acknowledge: " + rand.nextInt(100000);
            } else if (protoChoice == 1) {
                protocol = "UDP";
                destPort = 53; // DNS
                payload = "DNS Query: IN A " + getRandomElement(SAFE_DOMAINS);
            } else if (protoChoice == 2) {
                protocol = "HTTP";
                destPort = 80;
                String domain = getRandomElement(SAFE_DOMAINS);
                payload = "GET /index.html HTTP/1.1\r\n" +
                          "Host: " + domain + "\r\n" +
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
                          "Accept: text/html,application/xhtml+xml\r\n\r\n";
            } else {
                protocol = "HTTPS";
                destPort = 443;
                payload = "TLSv1.3 Handshake Client Hello. SNI: " + getRandomElement(SAFE_DOMAINS) + 
                          "\r\nCipher Suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256";
            }
            
        } else if (chance < 78) {
            // B. Blacklisted IP attempt (13% chance)
            // Generate a packet involving a blacklisted IP address
            boolean inbound = rand.nextBoolean();
            if (inbound) {
                srcIp = getRandomElement(BLOCKED_IPS_POOL);
                destIp = getRandomElement(SAFE_IPS);
            } else {
                srcIp = getRandomElement(SAFE_IPS);
                destIp = getRandomElement(BLOCKED_IPS_POOL);
            }
            
            protocol = rand.nextBoolean() ? "TCP" : "UDP";
            destPort = rand.nextBoolean() ? 80 : 443;
            payload = "Suspicious network connection handshake from potential malicious node.";

        } else if (chance < 88) {
            // C. Blacklisted Website Filter attempt (10% chance)
            srcIp = getRandomElement(SAFE_IPS);
            destIp = "104.244.42.1"; // Some mock web server IP
            protocol = rand.nextBoolean() ? "HTTP" : "HTTPS";
            destPort = protocol.equals("HTTP") ? 80 : 443;
            
            // Dynamically select a blocked website domain from SQLite database rules
            String blockedDomain = "bad-malware-site.com"; // default fallback
            try {
                java.util.List<String[]> dbBlocked = com.cyber.dpi.db.DatabaseManager.getFilteredWebsites();
                if (dbBlocked != null && !dbBlocked.isEmpty()) {
                    int randIdx = rand.nextInt(dbBlocked.size());
                    blockedDomain = dbBlocked.get(randIdx)[0];
                } else {
                    blockedDomain = getRandomElement(BLOCKED_DOMAINS_POOL);
                }
            } catch (Exception e) {
                blockedDomain = getRandomElement(BLOCKED_DOMAINS_POOL);
            }
            
            if (protocol.equals("HTTP")) {
                payload = "GET /download/updates HTTP/1.1\r\n" +
                          "Host: " + blockedDomain + "\r\n" +
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n";
            } else {
                payload = "TLSv1.2 Client Hello. SNI: " + blockedDomain;
            }

        } else {
            // D. Threat Signature Injection Attack (12% chance)
            // Generate clean IP addresses, but insert a payload that triggers a DB signature
            srcIp = getRandomElement(SAFE_IPS);
            destIp = getRandomElement(SAFE_IPS);
            protocol = "HTTP";
            destPort = 80;
            
            int threatType = rand.nextInt(6);
            switch (threatType) {
                case 0: // SQL Injection Auth Bypass
                    payload = "POST /login HTTP/1.1\r\n" +
                              "Host: vulnerable-bank.com\r\n" +
                              "Content-Type: application/x-www-form-urlencoded\r\n" +
                              "Content-Length: 35\r\n\r\n" +
                              "username=admin&password=1' OR '1'='1";
                    break;
                case 1: // SQL Injection Union
                    payload = "GET /products.php?category=1 UNION SELECT null, username, password FROM users HTTP/1.1\r\n" +
                              "Host: e-commerce-vulnerable.net\r\n\r\n";
                    break;
                case 2: // XSS script tag
                    payload = "POST /submit_comment HTTP/1.1\r\n" +
                              "Host: socialblog.com\r\n\r\n" +
                              "author=User1&comment=<script>alert('xss_attack');</script>";
                    break;
                case 3: // Path traversal
                    payload = "GET /download.jsp?file=../../../../etc/passwd HTTP/1.1\r\n" +
                              "Host: intranet-portal.corp\r\n\r\n";
                    break;
                case 4: // Shell remote execution
                    payload = "POST /cgi-bin/test.cgi HTTP/1.1\r\n" +
                              "Host: gateway.router.local\r\n\r\n" +
                              "command=ping; rm -rf /var/log/*";
                    break;
                default: // Malware download
                    payload = "GET /files/trojan.bin HTTP/1.1\r\n" +
                              "Host: file-sharing-server.biz\r\n\r\n";
                    break;
            }
        }

        return new PacketLog(srcIp, destIp, srcPort, destPort, protocol, payload);
    }

    private <T> T getRandomElement(T[] array) {
        return array[rand.nextInt(array.length)];
    }
}

package com.cyber.dpi.analyzer;

import com.cyber.dpi.db.DatabaseManager;
import com.cyber.dpi.detector.ThreatDetectionEngine;
import com.cyber.dpi.model.PacketLog;
import com.cyber.dpi.model.ThreatSignature;

public class AnalyzerTest {
    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("  STARTING AUTOMATED PIPELINE VERIFICATION TEST  ");
        System.out.println("=================================================");

        // 1. Initialize SQLite connection and schemas
        DatabaseManager.initializeDatabase();

        int testsPassed = 0;
        int totalTests = 7;

        // Test 1: Extract HTTP Host
        try {
            String payload = "GET /index.html HTTP/1.1\r\nHost: my-test-site.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
            String host = ProtocolAnalyzer.extractHttpHost(payload);
            if ("my-test-site.com".equals(host)) {
                System.out.println("[PASS] Test 1: HTTP Host extraction succeeded. Host: " + host);
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 1: Expected 'my-test-site.com', got: " + host);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Test 1 encountered exception: " + e.getMessage());
        }

        // Test 2: Payload Signature Inspection - SQL Injection
        try {
            String sqlPayload = "SELECT * FROM users WHERE username = 'admin' UNION SELECT null, password FROM users";
            ThreatSignature matched = PayloadInspector.inspectPayload(sqlPayload);
            if (matched != null && "SIG-001".equals(matched.getId())) {
                System.out.println("[PASS] Test 2: SQL Injection signature detection succeeded. ID: " + matched.getId());
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 2: SQL Injection signature not matched or wrong ID.");
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Test 2 encountered exception: " + e.getMessage());
        }

        // Test 3: Payload Signature Inspection - Path Traversal
        try {
            String pathPayload = "GET /view.jsp?file=../../../../etc/passwd HTTP/1.1";
            ThreatSignature matched = PayloadInspector.inspectPayload(pathPayload);
            if (matched != null && "SIG-006".equals(matched.getId())) {
                System.out.println("[PASS] Test 3: Path Traversal signature detection succeeded. ID: " + matched.getId());
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 3: Path Traversal signature not matched or wrong ID.");
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Test 3 encountered exception: " + e.getMessage());
        }

        // Test 4: Dynamic Firewall Blacklist Check
        try {
            String maliciousIp = "192.168.1.99";
            // Pre-blacklist
            DatabaseManager.addToBlacklist(maliciousIp, "Test malicious IP");
            
            PacketLog log = new PacketLog(maliciousIp, "192.168.1.1", 1234, 80, "TCP", "Hello");
            PacketLog result = ThreatDetectionEngine.processPacket(log);
            
            if ("Suspicious".equals(result.getThreatStatus()) && "Blocked".equals(result.getActionTaken())) {
                System.out.println("[PASS] Test 4: Blacklisted IP block check succeeded. IP " + maliciousIp + " blocked.");
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 4: Blacklisted IP was not blocked. Status: " + result.getThreatStatus());
            }
            
            // Clean up
            DatabaseManager.removeFromBlacklist(maliciousIp);
        } catch (Exception e) {
            System.err.println("[ERROR] Test 4 encountered exception: " + e.getMessage());
        }

        // Test 5: Clean Traffic Validation
        try {
            PacketLog cleanLog = new PacketLog("192.168.1.5", "8.8.8.8", 54321, 53, "UDP", "DNS query standard request");
            PacketLog result = ThreatDetectionEngine.processPacket(cleanLog);
            if ("Safe".equals(result.getThreatStatus()) && "Allowed".equals(result.getActionTaken())) {
                System.out.println("[PASS] Test 5: Clean traffic allowed check succeeded.");
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 5: Clean traffic was flagged. Status: " + result.getThreatStatus() + " | Details: " + result.getDetails());
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Test 5 encountered exception: " + e.getMessage());
        }

        // Test 6: IP-to-Domain mapping and cache-based website blocking
        try {
            String testIp = "185.123.45.67";
            String testBlockedDomain = "restricted-gambling-site.com";
            
            // 1. Add to website filter
            DatabaseManager.addToWebsiteFilter(testBlockedDomain, "Gambling");
            
            // 2. Map IP to domain
            DatabaseManager.mapIpToDomain(testIp, testBlockedDomain);
            
            // 3. Process packet with no SNI domain but matching destination IP
            PacketLog sniLessLog = new PacketLog("192.168.1.50", testIp, 50123, 443, "HTTPS", "Client Hello / data");
            PacketLog result = ThreatDetectionEngine.processPacket(sniLessLog);
            
            if ("Suspicious".equals(result.getThreatStatus()) && "Blocked".equals(result.getActionTaken()) && testBlockedDomain.equals(result.getDomain())) {
                System.out.println("[PASS] Test 6: Passive DNS IP cache blocking succeeded for domain: " + result.getDomain());
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 6: IP mapping was not resolved/blocked. Domain: " + result.getDomain() + ", Status: " + result.getThreatStatus());
            }
            
            // Cleanup website filter
            DatabaseManager.removeFromWebsiteFilter(testBlockedDomain);
        } catch (Exception e) {
            System.err.println("[ERROR] Test 6 encountered exception: " + e.getMessage());
        }

        // Test 7: DNS response parsing and dynamic IP-to-domain mapping
        try {
            // A mock raw DNS response payload for "test-sniffed-site.com" resolving to "99.88.77.66"
            // Header: ID (2 bytes), Flags (2 bytes, response=0x8180), QDCOUNT (1), ANCOUNT (1), NSCOUNT (0), ARCOUNT (0)
            // Questions: "test-sniffed-site.com" (type A, class IN)
            // Answers: "test-sniffed-site.com" (type A, class IN, TTL 300, length 4, IP 99.88.77.66)
            byte[] dnsPayload = new byte[] {
                // Header (12 bytes)
                0x12, 0x34, // ID
                (byte)0x81, (byte)0x80, // Flags (Response, No Error)
                0x00, 0x01, // QDCOUNT = 1
                0x00, 0x01, // ANCOUNT = 1
                0x00, 0x00, // NSCOUNT = 0
                0x00, 0x00, // ARCOUNT = 0
                
                // Question (Name: test-sniffed-site.com, Type: A, Class: IN)
                12, 't', 'e', 's', 't', '-', 's', 'n', 'i', 'f', 'f', 'e', 'd',
                4, 's', 'i', 't', 'e',
                3, 'c', 'o', 'm',
                0x00, // Zero length (end of name)
                0x00, 0x01, // QTYPE = A (1)
                0x00, 0x01, // QCLASS = IN (1)
                
                // Answer (Name: pointer to question at offset 12, i.e. 0xC00C, Type: A, Class: IN, TTL: 300, DataLen: 4, IP: 99.88.77.66)
                (byte)0xC0, 0x0c, // Pointer
                0x00, 0x01, // TYPE = A (1)
                0x00, 0x01, // CLASS = IN (1)
                0x00, 0x00, 0x01, 0x2C, // TTL = 300 seconds
                0x00, 0x04, // RDLENGTH = 4
                99, 88, 77, 66 // IP Address (99.88.77.66)
            };
            
            // Invoke DNS response parsing
            ProtocolAnalyzer.parseDnsResponseAndMapIps(dnsPayload);
            
            // Check if mapped correctly in DatabaseManager cache
            String mappedDomain = DatabaseManager.getDomainByIp("99.88.77.66");
            if ("test-sniffed.site.com".equals(mappedDomain)) {
                System.out.println("[PASS] Test 7: DNS response parsing and dynamic IP mapping succeeded.");
                testsPassed++;
            } else {
                System.err.println("[FAIL] Test 7: DNS response did not map IP. Got: " + mappedDomain);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Test 7 encountered exception: " + e.getMessage());
        }

        System.out.println("=================================================");
        System.out.println("  TESTS SUMMARY: " + testsPassed + " / " + totalTests + " PASSED  ");
        System.out.println("=================================================");
        
        if (testsPassed == totalTests) {
            System.out.println("STATUS: ALL TESTS COMPLETED SUCCESSFULLY.");
            System.exit(0);
        } else {
            System.err.println("STATUS: TEST FAILURE DETECTED.");
            System.exit(1);
        }
    }
}

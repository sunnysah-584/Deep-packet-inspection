package com.cyber.dpi.db;

import com.cyber.dpi.model.PacketLog;
import com.cyber.dpi.model.ThreatSignature;

import java.io.File;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {
    private static final String DB_URL = "jdbc:sqlite:dpi_system.db";
    private static Connection conn = null;
    
    // In-memory cache for IP-to-Domain mapping
    private static final java.util.Map<String, String> ipToDomainMap = new java.util.concurrent.ConcurrentHashMap<>();

    public static void mapIpToDomain(String ip, String domain) {
        if (ip == null || domain == null) return;
        ipToDomainMap.put(ip.trim(), domain.trim().toLowerCase());
    }

    public static String getDomainByIp(String ip) {
        if (ip == null) return null;
        return ipToDomainMap.get(ip.trim());
    }

    public static void preResolveBlockedDomains() {
        Thread thread = new Thread(() -> {
            System.out.println("Starting pre-resolution of blocked domains...");
            List<String[]> blocked = getFilteredWebsites();
            for (String[] site : blocked) {
                String domain = site[0].trim().toLowerCase();
                if (!domain.isEmpty()) {
                    resolveAndCache(domain);
                    if (!domain.startsWith("www.")) {
                        resolveAndCache("www." + domain);
                    }
                }
            }
            System.out.println("Pre-resolution of blocked domains completed. Cache size: " + ipToDomainMap.size());
        }, "BlockedDomainsResolverThread");
        thread.setDaemon(true);
        thread.start();
    }

    private static void resolveAndCache(String domain) {
        try {
            java.net.InetAddress[] addresses = java.net.InetAddress.getAllByName(domain);
            for (java.net.InetAddress addr : addresses) {
                String ip = addr.getHostAddress();
                mapIpToDomain(ip, domain);
                System.out.println("Pre-resolved: " + domain + " -> " + ip);
            }
        } catch (java.net.UnknownHostException e) {
            System.err.println("Could not pre-resolve domain: " + domain + " (" + e.getMessage() + ")");
        } catch (Exception e) {
            System.err.println("Error resolving domain: " + domain + " (" + e.getMessage() + ")");
        }
    }

    static {
        // Explicitly load SQLite driver class to verify it's on classpath
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC Driver not found on classpath!");
            e.printStackTrace();
        }
    }

    public static synchronized Connection getConnection() throws SQLException {
        if (conn == null || conn.isClosed()) {
            conn = DriverManager.getConnection(DB_URL);
        }
        return conn;
    }

    public static void initializeDatabase() {
        try (Connection c = getConnection();
             Statement stmt = c.createStatement()) {

            // Enable WAL mode for high concurrency
            stmt.execute("PRAGMA journal_mode=WAL;");

            // 1. Packet Logs table
            stmt.execute("CREATE TABLE IF NOT EXISTS packet_logs (" +
                    "id TEXT PRIMARY KEY, " +
                    "source_ip TEXT, " +
                    "destination_ip TEXT, " +
                    "source_port INTEGER, " +
                    "dest_port INTEGER, " +
                    "protocol TEXT, " +
                    "threat_status TEXT, " +
                    "action_taken TEXT, " +
                    "payload TEXT, " +
                    "timestamp TEXT, " +
                    "details TEXT" +
                    ");");

            // 2. IP Blacklist table
            stmt.execute("CREATE TABLE IF NOT EXISTS ip_blacklist (" +
                    "ip TEXT PRIMARY KEY, " +
                    "reason TEXT, " +
                    "timestamp TEXT" +
                    ");");

            // 3. Website Filter table
            stmt.execute("CREATE TABLE IF NOT EXISTS website_filter (" +
                    "domain TEXT PRIMARY KEY, " +
                    "category TEXT, " +
                    "timestamp TEXT" +
                    ");");

            // 4. Threat Signatures table
            stmt.execute("CREATE TABLE IF NOT EXISTS threat_signatures (" +
                    "id TEXT PRIMARY KEY, " +
                    "name TEXT, " +
                    "pattern TEXT, " +
                    "severity TEXT, " +
                    "category TEXT" +
                    ");");

            // Populate defaults
            populateDefaultSignatures(c);
            populateDefaultBlockedWebsites(c);
            populateDefaultBlacklist(c);

            System.out.println("SQLite Database initialized successfully.");
            preResolveBlockedDomains();
        } catch (SQLException e) {
            System.err.println("Failed to initialize database: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void populateDefaultSignatures(Connection c) throws SQLException {
        // Check if signatures already exist
        try (Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM threat_signatures")) {
            if (rs.next() && rs.getInt(1) > 0) {
                return; // Already populated
            }
        }

        List<ThreatSignature> defaults = new ArrayList<>();
        // SQL Injections
        defaults.add(new ThreatSignature("SIG-001", "SQL Injection - Union Query", "(?i)UNION\\s+SELECT", "Critical", "SQL_INJECTION"));
        defaults.add(new ThreatSignature("SIG-002", "SQL Injection - Auth Bypass", "(?i)OR\\s+['\"]\\d+['\"]\\s*=\\s*['\"]\\d+['\"]", "Critical", "SQL_INJECTION"));
        defaults.add(new ThreatSignature("SIG-003", "SQL Injection - Drop Command", "(?i)DROP\\s+TABLE|DELETE\\s+FROM", "Critical", "SQL_INJECTION"));
        
        // XSS (Cross-Site Scripting)
        defaults.add(new ThreatSignature("SIG-004", "XSS - Script Tag", "(?i)<script.*?>.*?</script>|(?i)javascript:", "High", "XSS"));
        defaults.add(new ThreatSignature("SIG-005", "XSS - Inline Event Handler", "(?i)onload\\s*=|(?i)onerror\\s*=", "Medium", "XSS"));
        
        // Path Traversal
        defaults.add(new ThreatSignature("SIG-006", "Path Traversal - etc/passwd", "(?i)\\.\\./\\.\\./|/etc/passwd|\\.\\.\\\\", "High", "PATH_TRAVERSAL"));
        
        // Command Injection / RCE
        defaults.add(new ThreatSignature("SIG-007", "Shell Command Injection", "(?i);\\s*rm\\s+-rf|(?i);\\s*wget|(?i);\\s*curl", "Critical", "REMOTE_CODE_EXECUTION"));
        defaults.add(new ThreatSignature("SIG-008", "PHP Eval Execution", "(?i)eval\\s*\\(\\s*base64_decode", "Critical", "REMOTE_CODE_EXECUTION"));
        
        // Malware and suspicious keywords
        defaults.add(new ThreatSignature("SIG-009", "Malware Payload Download", "(?i)malware\\.exe|(?i)payload\\.sh|(?i)trojan\\.bin", "High", "MALWARE"));
        defaults.add(new ThreatSignature("SIG-010", "Cryptomining Stratus Protocol", "(?i)stratum\\+tcp|(?i)minergate", "Medium", "MALWARE"));

        String insertSQL = "INSERT INTO threat_signatures (id, name, pattern, severity, category) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = c.prepareStatement(insertSQL)) {
            for (ThreatSignature sig : defaults) {
                pstmt.setString(1, sig.getId());
                pstmt.setString(2, sig.getName());
                pstmt.setString(3, sig.getPattern());
                pstmt.setString(4, sig.getSeverity());
                pstmt.setString(5, sig.getCategory());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        }
    }

    private static void populateDefaultBlockedWebsites(Connection c) throws SQLException {
        try (Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM website_filter")) {
            if (rs.next() && rs.getInt(1) > 0) {
                return;
            }
        }

        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String[][] defaults = {
                {"bad-malware-site.com", "Malware", now},
                {"phishing-bank-login.net", "Phishing", now},
                {"gambling-hub.org", "Gambling", now},
                {"unauthorized-torrent.cc", "Piracy", now},
                {"tor-exit-node.xyz", "Anonymizer", now}
        };

        String insertSQL = "INSERT INTO website_filter (domain, category, timestamp) VALUES (?, ?, ?)";
        try (PreparedStatement pstmt = c.prepareStatement(insertSQL)) {
            for (String[] def : defaults) {
                pstmt.setString(1, def[0]);
                pstmt.setString(2, def[1]);
                pstmt.setString(3, def[2]);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        }
    }

    private static void populateDefaultBlacklist(Connection c) throws SQLException {
        try (Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM ip_blacklist")) {
            if (rs.next() && rs.getInt(1) > 0) {
                return;
            }
        }

        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String[][] defaults = {
                {"192.168.1.150", "Known Command & Control Server", now},
                {"45.33.22.11", "Active Botnet Node", now},
                {"185.220.101.5", "TOR Exit Node", now}
        };

        String insertSQL = "INSERT INTO ip_blacklist (ip, reason, timestamp) VALUES (?, ?, ?)";
        try (PreparedStatement pstmt = c.prepareStatement(insertSQL)) {
            for (String[] def : defaults) {
                pstmt.setString(1, def[0]);
                pstmt.setString(2, def[1]);
                pstmt.setString(3, def[2]);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        }
    }

    // Packet Logs Operations
    public static void addPacketLog(PacketLog log) {
        String sql = "INSERT OR REPLACE INTO packet_logs (id, source_ip, destination_ip, source_port, dest_port, protocol, threat_status, action_taken, payload, timestamp, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, log.getId());
            pstmt.setString(2, log.getSourceIP());
            pstmt.setString(3, log.getDestinationIP());
            pstmt.setInt(4, log.getSourcePort());
            pstmt.setInt(5, log.getDestPort());
            pstmt.setString(6, log.getProtocol());
            pstmt.setString(7, log.getThreatStatus());
            pstmt.setString(8, log.getActionTaken());
            pstmt.setString(9, log.getPayload());
            pstmt.setString(10, log.getTimestamp());
            pstmt.setString(11, log.getDetails());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to insert packet log: " + e.getMessage());
        }
    }

    public static List<PacketLog> getPacketLogs(String search, String protocol, String threatStatus, String actionTaken) {
        List<PacketLog> logs = new ArrayList<>();
        StringBuilder sql = new StringBuilder("SELECT * FROM packet_logs WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (search != null && !search.trim().isEmpty()) {
            sql.append(" AND (source_ip LIKE ? OR destination_ip LIKE ? OR payload LIKE ? OR details LIKE ?)");
            String like = "%" + search.trim() + "%";
            params.add(like);
            params.add(like);
            params.add(like);
            params.add(like);
        }
        if (protocol != null && !protocol.equalsIgnoreCase("All")) {
            sql.append(" AND protocol = ?");
            params.add(protocol);
        }
        if (threatStatus != null && !threatStatus.equalsIgnoreCase("All")) {
            sql.append(" AND threat_status = ?");
            params.add(threatStatus);
        }
        if (actionTaken != null && !actionTaken.equalsIgnoreCase("All")) {
            sql.append(" AND action_taken = ?");
            params.add(actionTaken);
        }

        sql.append(" ORDER BY timestamp DESC LIMIT 500");

        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    logs.add(new PacketLog(
                            rs.getString("id"),
                            rs.getString("source_ip"),
                            rs.getString("destination_ip"),
                            rs.getInt("source_port"),
                            rs.getInt("dest_port"),
                            rs.getString("protocol"),
                            rs.getString("threat_status"),
                            rs.getString("action_taken"),
                            rs.getString("payload"),
                            rs.getString("timestamp"),
                            rs.getString("details")
                    ));
                }
            }
        } catch (SQLException e) {
            System.err.println("Failed to query packet logs: " + e.getMessage());
        }
        return logs;
    }

    // IP Blacklist Operations
    public static void addToBlacklist(String ip, String reason) {
        String sql = "INSERT OR REPLACE INTO ip_blacklist (ip, reason, timestamp) VALUES (?, ?, ?)";
        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, ip);
            pstmt.setString(2, reason);
            pstmt.setString(3, now);
            pstmt.executeUpdate();
            System.out.println("Blacklisted IP: " + ip + " (Reason: " + reason + ")");
        } catch (SQLException e) {
            System.err.println("Failed to blacklist IP: " + e.getMessage());
        }
    }

    public static void removeFromBlacklist(String ip) {
        String sql = "DELETE FROM ip_blacklist WHERE ip = ?";
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, ip);
            pstmt.executeUpdate();
            System.out.println("Removed from Blacklist IP: " + ip);
        } catch (SQLException e) {
            System.err.println("Failed to remove IP from blacklist: " + e.getMessage());
        }
    }

    public static List<String[]> getBlacklistedIPs() {
        List<String[]> list = new ArrayList<>();
        String sql = "SELECT * FROM ip_blacklist ORDER BY timestamp DESC";
        try (Connection c = getConnection();
             Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                list.add(new String[]{
                        rs.getString("ip"),
                        rs.getString("reason"),
                        rs.getString("timestamp")
                });
            }
        } catch (SQLException e) {
            System.err.println("Failed to retrieve blacklist: " + e.getMessage());
        }
        return list;
    }

    public static boolean isIPBlacklisted(String ip) {
        String sql = "SELECT COUNT(*) FROM ip_blacklist WHERE ip = ?";
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, ip);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next() && rs.getInt(1) > 0) {
                    return true;
                }
            }
        } catch (SQLException e) {
            System.err.println("Failed to check blacklist: " + e.getMessage());
        }
        return false;
    }

    // Website Filter Operations
    public static void addToWebsiteFilter(String domain, String category) {
        String sql = "INSERT OR REPLACE INTO website_filter (domain, category, timestamp) VALUES (?, ?, ?)";
        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, domain.trim().toLowerCase());
            pstmt.setString(2, category);
            pstmt.setString(3, now);
            pstmt.executeUpdate();
            System.out.println("Blocked website: " + domain);
            
            // Sync OS firewall/hosts file
            HostsFileSynchronizer.syncHostsFile();
            
            // Resolve newly blocked domain immediately in background
            Thread thread = new Thread(() -> {
                String norm = domain.trim().toLowerCase();
                resolveAndCache(norm);
                if (!norm.startsWith("www.")) {
                    resolveAndCache("www." + norm);
                }
            });
            thread.setDaemon(true);
            thread.start();
        } catch (SQLException e) {
            System.err.println("Failed to block domain: " + e.getMessage());
        }
    }

    public static void removeFromWebsiteFilter(String domain) {
        String sql = "DELETE FROM website_filter WHERE domain = ?";
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, domain.trim().toLowerCase());
            pstmt.executeUpdate();
            System.out.println("Unblocked website: " + domain);
            
            // Sync OS firewall/hosts file
            HostsFileSynchronizer.syncHostsFile();
        } catch (SQLException e) {
            System.err.println("Failed to remove domain: " + e.getMessage());
        }
    }

    public static List<String[]> getFilteredWebsites() {
        List<String[]> list = new ArrayList<>();
        String sql = "SELECT * FROM website_filter ORDER BY timestamp DESC";
        try (Connection c = getConnection();
             Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                list.add(new String[]{
                        rs.getString("domain"),
                        rs.getString("category"),
                        rs.getString("timestamp")
                });
            }
        } catch (SQLException e) {
            System.err.println("Failed to retrieve website filters: " + e.getMessage());
        }
        return list;
    }

    public static boolean isDomainBlocked(String domain) {
        if (domain == null) return false;
        String normalized = domain.trim().toLowerCase();
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        
        List<String[]> blockedWebsites = getFilteredWebsites();
        for (String[] site : blockedWebsites) {
            String blocked = site[0].trim().toLowerCase();
            if (blocked.endsWith(".")) {
                blocked = blocked.substring(0, blocked.length() - 1);
            }
            
            if (normalized.equals(blocked)) return true;
            if (normalized.endsWith("." + blocked)) return true;
            if (blocked.endsWith("." + normalized)) return true;
            
            // Compare without 'www.' prefix
            String normNoW = normalized.startsWith("www.") ? normalized.substring(4) : normalized;
            String blockNoW = blocked.startsWith("www.") ? blocked.substring(4) : blocked;
            if (normNoW.equals(blockNoW)) return true;

            // Brand-name substring heuristic block (e.g. intercepts "cdninstagram.com" when "instagram.com" is blocked)
            String blockedBrand = extractBrandName(blocked);
            if (blockedBrand != null && blockedBrand.length() > 3) {
                if (normalized.contains(blockedBrand)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String extractBrandName(String domain) {
        if (domain == null || !domain.contains(".")) return domain;
        String[] parts = domain.split("\\.");
        if (parts.length >= 2) {
            for (int i = parts.length - 2; i >= 0; i--) {
                if (!parts[i].equalsIgnoreCase("www") && parts[i].length() > 2) {
                    return parts[i];
                }
            }
        }
        return parts[0];
    }

    // Threat Signatures Operations
    public static void addThreatSignature(ThreatSignature sig) {
        String sql = "INSERT OR REPLACE INTO threat_signatures (id, name, pattern, severity, category) VALUES (?, ?, ?, ?, ?)";
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, sig.getId());
            pstmt.setString(2, sig.getName());
            pstmt.setString(3, sig.getPattern());
            pstmt.setString(4, sig.getSeverity());
            pstmt.setString(5, sig.getCategory());
            pstmt.executeUpdate();
            System.out.println("Saved signature: " + sig.getName());
        } catch (SQLException e) {
            System.err.println("Failed to save threat signature: " + e.getMessage());
        }
    }

    public static void removeThreatSignature(String id) {
        String sql = "DELETE FROM threat_signatures WHERE id = ?";
        try (Connection c = getConnection();
             PreparedStatement pstmt = c.prepareStatement(sql)) {
            pstmt.setString(1, id);
            pstmt.executeUpdate();
            System.out.println("Deleted signature: " + id);
        } catch (SQLException e) {
            System.err.println("Failed to delete threat signature: " + e.getMessage());
        }
    }

    public static List<ThreatSignature> getThreatSignatures() {
        List<ThreatSignature> sigs = new ArrayList<>();
        String sql = "SELECT * FROM threat_signatures ORDER BY id ASC";
        try (Connection c = getConnection();
             Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                sigs.add(new ThreatSignature(
                        rs.getString("id"),
                        rs.getString("name"),
                        rs.getString("pattern"),
                        rs.getString("severity"),
                        rs.getString("category")
                ));
            }
        } catch (SQLException e) {
            System.err.println("Failed to retrieve threat signatures: " + e.getMessage());
        }
        return sigs;
    }
}

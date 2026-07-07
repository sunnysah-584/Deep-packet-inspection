package com.cyber.dpi.analyzer;

import com.cyber.dpi.model.PacketLog;

public class ProtocolAnalyzer {

    /**
     * Parses the HTTP host from HTTP payload if present.
     */
    public static String extractHttpHost(String payload) {
        if (payload == null || payload.isEmpty()) return null;
        
        // Basic parsing of HTTP header (Host: ...)
        String[] lines = payload.split("\r\n|\n");
        for (String line : lines) {
            if (line.toLowerCase().startsWith("host:")) {
                return line.substring(5).trim();
            }
        }
        
        // Fallback: look for typical Host: header in text
        int index = payload.toLowerCase().indexOf("host:");
        if (index != -1) {
            int end = payload.indexOf("\r\n", index);
            if (end == -1) end = payload.indexOf("\n", index);
            if (end != -1) {
                return payload.substring(index + 5, end).trim();
            }
        }
        return null;
    }

    /**
     * Parses the TLS SNI (Server Name Indication) domain from HTTPS Client Hello payloads.
     */
    public static String extractHttpsSni(String payload) {
        if (payload == null || payload.isEmpty()) return null;
        
        // Scan for domain-like strings in the ASCII representation of TLS packet
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\\b([a-zA-Z0-9-]{2,63}\\.[a-zA-Z]{2,6})\\b");
        java.util.regex.Matcher m = p.matcher(payload);
        while (m.find()) {
            String domain = m.group(1);
            // Filter out common false positives from TLS handshakes
            if (!domain.contains("HTTP") && !domain.contains("TLS") && !domain.equalsIgnoreCase("Client") && !domain.equalsIgnoreCase("Hello")) {
                return domain;
            }
        }
        return null;
    }

    /**
     * Binary parser for standard UDP DNS Query payloads.
     */
    public static String parseDnsQuery(byte[] data) {
        if (data == null || data.length <= 12) return null;
        try {
            int qCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
            if (qCount <= 0) return null;
            
            StringBuilder sb = new StringBuilder();
            int idx = 12;
            while (idx < data.length) {
                int len = data[idx] & 0xFF;
                if (len == 0) {
                    break; 
                }
                if (idx + 1 + len > data.length) {
                    return null; 
                }
                if (sb.length() > 0) {
                    sb.append(".");
                }
                for (int i = 0; i < len; i++) {
                    char c = (char) data[idx + 1 + i];
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
                        sb.append(Character.toLowerCase(c));
                    } else {
                        return null; 
                    }
                }
                idx += 1 + len;
            }
            String domain = sb.toString();
            if (domain.contains(".") && domain.length() > 3) {
                return domain;
            }
        } catch (Exception e) {
            // Safety boundary catch
        }
        return null;
    }

    /**
     * Binary parser searching for TLS SNI (Server Name Indication) in raw Client Hello bytes.
     */
    public static String parseHttpsSni(byte[] data) {
        if (data == null || data.length < 40) return null;
        try {
            if ((data[0] & 0xFF) != 0x16) return null; // Must be TLS Handshake Record
            
            for (int i = 30; i < data.length - 10; i++) {
                if ((data[i] & 0xFF) == 0x00 && (data[i+1] & 0xFF) == 0x00) {
                    int extLen = ((data[i+2] & 0xFF) << 8) | (data[i+3] & 0xFF);
                    int listLen = ((data[i+4] & 0xFF) << 8) | (data[i+5] & 0xFF);
                    if ((data[i+6] & 0xFF) == 0x00) { 
                        int nameLen = ((data[i+7] & 0xFF) << 8) | (data[i+8] & 0xFF);
                        if (nameLen > 0 && nameLen < 256 && i + 9 + nameLen <= data.length) {
                            StringBuilder sb = new StringBuilder();
                            boolean valid = true;
                            for (int j = 0; j < nameLen; j++) {
                                char c = (char) data[i + 9 + j];
                                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
                                    sb.append(Character.toLowerCase(c));
                                } else {
                                    valid = false;
                                    break;
                                }
                            }
                            if (valid) {
                                String name = sb.toString();
                                if (name.contains(".") && name.length() > 3) {
                                    return name;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Safety boundary catch
        }
        return null;
    }

    /**
     * Helper to extract domain name based on protocol from raw bytes.
     */
    public static String extractDomainFromBytes(String protocol, byte[] rawData) {
        if (rawData == null || rawData.length == 0) return null;
        if ("DNS".equalsIgnoreCase(protocol)) {
            return parseDnsQuery(rawData);
        } else if ("HTTPS".equalsIgnoreCase(protocol)) {
            return parseHttpsSni(rawData);
        } else if ("HTTP".equalsIgnoreCase(protocol)) {
            return extractHttpHost(new String(rawData));
        }
        return null;
    }

    /**
     * Helper to extract domain name based on protocol (String payload compatibility).
     */
    public static String extractDomain(String protocol, String payload) {
        if (payload == null || payload.isEmpty()) return null;
        if ("HTTP".equalsIgnoreCase(protocol)) {
            return extractHttpHost(payload);
        } else if ("HTTPS".equalsIgnoreCase(protocol)) {
            return extractHttpsSni(payload);
        } else if ("DNS".equalsIgnoreCase(protocol) || "UDP".equalsIgnoreCase(protocol)) {
            if (payload.contains("DNS Query:")) {
                String[] parts = payload.split(" ");
                return parts[parts.length - 1];
            }
            return extractHttpsSni(payload);
        }
        return null;
    }

    /**
     * Skips a domain name in DNS format, handling compression pointers (0xC0).
     */
    private static int skipDomainName(byte[] data, int startIdx) {
        int idx = startIdx;
        while (idx < data.length) {
            int len = data[idx] & 0xFF;
            if (len == 0) {
                return idx + 1;
            }
            if ((len & 0xC0) == 0xC0) {
                return idx + 2;
            }
            idx += 1 + len;
        }
        return data.length;
    }

    /**
     * Reads a domain name in DNS format, handling compression pointers (0xC0).
     */
    public static String readDomainName(byte[] data, int startIdx) {
        StringBuilder sb = new StringBuilder();
        readDomainNameHelper(data, startIdx, sb, 0);
        return sb.toString();
    }

    private static int readDomainNameHelper(byte[] data, int idx, StringBuilder sb, int depth) {
        if (depth > 5) return idx; // Bounded depth to prevent infinite loops on corrupt packets
        if (idx >= data.length) return idx;

        while (idx < data.length) {
            int len = data[idx] & 0xFF;
            if (len == 0) {
                return idx + 1;
            }
            if ((len & 0xC0) == 0xC0) {
                if (idx + 1 >= data.length) return data.length;
                int offset = ((len & 0x3F) << 8) | (data[idx + 1] & 0xFF);
                readDomainNameHelper(data, offset, sb, depth + 1);
                return idx + 2;
            }

            if (idx + 1 + len > data.length) return data.length;
            if (sb.length() > 0) {
                sb.append(".");
            }
            for (int i = 0; i < len; i++) {
                sb.append((char) data[idx + 1 + i]);
            }
            idx += 1 + len;
        }
        return idx;
    }

    /**
     * Parses a DNS response packet and maps resolved IPs to the requested domain.
     */
    public static void parseDnsResponseAndMapIps(byte[] data) {
        if (data == null || data.length <= 12) return;
        try {
            // Check QR flag (bit 0 of byte 2: 1 means response)
            boolean isResponse = (data[2] & 0x80) != 0;
            if (!isResponse) return;

            int qCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
            int aCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
            if (qCount <= 0 || aCount <= 0) return;

            // Skip questions
            int idx = 12;
            for (int q = 0; q < qCount; q++) {
                idx = skipDomainName(data, idx);
                idx += 4; // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
            }

            // Parse answers
            for (int a = 0; a < aCount; a++) {
                if (idx >= data.length) break;

                int nameStart = idx;
                idx = skipDomainName(data, idx);
                if (idx + 10 > data.length) break;

                int type = ((data[idx] & 0xFF) << 8) | (data[idx + 1] & 0xFF);
                int cls = ((data[idx + 2] & 0xFF) << 8) | (data[idx + 3] & 0xFF);
                int dataLen = ((data[idx + 8] & 0xFF) << 8) | (data[idx + 9] & 0xFF);
                idx += 10;

                if (idx + dataLen > data.length) break;

                // Type 1 is A record (IPv4 address), dataLen must be 4
                if (type == 1 && dataLen == 4) {
                    String domain = readDomainName(data, nameStart);
                    String ip = (data[idx] & 0xFF) + "." +
                                (data[idx + 1] & 0xFF) + "." +
                                (data[idx + 2] & 0xFF) + "." +
                                (data[idx + 3] & 0xFF);
                    if (domain != null && !domain.isEmpty() && ip != null) {
                        com.cyber.dpi.db.DatabaseManager.mapIpToDomain(ip, domain);
                        System.out.println("Sniffed DNS Mapping: " + domain + " -> " + ip);
                    }
                }
                idx += dataLen;
            }
        } catch (Exception e) {
            // Silence boundary/corrupt packet errors
        }
    }

    /**
     * Converts a string payload into a professional hexadecimal and ASCII hex dump.
     * Mimics Wireshark / tcpdump outputs.
     */
    public static String convertToHexDump(String textPayload) {
        if (textPayload == null || textPayload.isEmpty()) {
            return "[Empty Payload]";
        }

        byte[] bytes = textPayload.getBytes();
        StringBuilder dump = new StringBuilder();
        int len = bytes.length;
        
        for (int i = 0; i < len; i += 16) {
            // Address offset
            dump.append(String.format("%04X  ", i));
            
            // Hex bytes
            int k;
            for (k = 0; k < 16; k++) {
                if (i + k < len) {
                    dump.append(String.format("%02X ", bytes[i + k]));
                } else {
                    dump.append("   "); // Padding for shorter lines
                }
                if (k == 7) dump.append(" "); // Split at 8 bytes
            }
            dump.append(" ");

            // ASCII printable characters
            for (k = 0; k < 16; k++) {
                if (i + k < len) {
                    byte b = bytes[i + k];
                    if (b >= 32 && b <= 126) {
                        dump.append((char) b);
                    } else {
                        dump.append("."); // Non-printable character replacement
                    }
                } else {
                    break;
                }
            }
            dump.append("\n");
        }
        return dump.toString();
    }
}

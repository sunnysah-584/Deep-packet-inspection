package com.cyber.dpi.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class PacketLog {
    private String id;
    private String sourceIP;
    private String destinationIP;
    private String protocol; // TCP, UDP, HTTP, HTTPS
    private String threatStatus; // Safe, Suspicious
    private String actionTaken; // Allowed, Blocked
    private String payload;
    private String timestamp;
    private int sourcePort;
    private int destPort;
    private String details; // Short summary of contents or threat explanation
    private String domain; // Target hostname extracted from DNS or TLS SNI

    public PacketLog(String sourceIP, String destinationIP, int sourcePort, int destPort, String protocol, String payload) {
        this.id = UUID.randomUUID().toString();
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destPort = destPort;
        this.protocol = protocol;
        this.payload = payload;
        this.threatStatus = "Safe";
        this.actionTaken = "Allowed";
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.details = "Protocol: " + protocol + " | " + sourceIP + ":" + sourcePort + " -> " + destinationIP + ":" + destPort;
    }

    // Constructor with full fields for DB retrieval
    public PacketLog(String id, String sourceIP, String destinationIP, int sourcePort, int destPort, 
                     String protocol, String threatStatus, String actionTaken, String payload, String timestamp, String details) {
        this.id = id;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destPort = destPort;
        this.protocol = protocol;
        this.threatStatus = threatStatus;
        this.actionTaken = actionTaken;
        this.payload = payload;
        this.timestamp = timestamp;
        this.details = details;
    }

    public String getId() { return id; }
    public String getSourceIP() { return sourceIP; }
    public String getDestinationIP() { return destinationIP; }
    public int getSourcePort() { return sourcePort; }
    public int getDestPort() { return destPort; }
    public String getProtocol() { return protocol; }
    
    public String getThreatStatus() { return threatStatus; }
    public void setThreatStatus(String threatStatus) { this.threatStatus = threatStatus; }

    public String getActionTaken() { return actionTaken; }
    public void setActionTaken(String actionTaken) { this.actionTaken = actionTaken; }

    public String getPayload() { return payload; }
    public String getTimestamp() { return timestamp; }
    
    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
}

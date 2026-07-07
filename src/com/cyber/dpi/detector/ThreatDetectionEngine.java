package com.cyber.dpi.detector;

import com.cyber.dpi.db.DatabaseManager;
import com.cyber.dpi.analyzer.ProtocolAnalyzer;
import com.cyber.dpi.analyzer.PayloadInspector;
import com.cyber.dpi.model.PacketLog;
import com.cyber.dpi.model.ThreatSignature;

import java.util.ArrayList;
import java.util.List;

public class ThreatDetectionEngine {

    public interface PacketProcessedListener {
        void onPacketProcessed(PacketLog log);
    }

    private static final List<PacketProcessedListener> listeners = new ArrayList<>();

    public static synchronized void registerListener(PacketProcessedListener l) {
        listeners.add(l);
    }

    public static synchronized void unregisterListener(PacketProcessedListener l) {
        listeners.remove(l);
    }

    private static synchronized void notifyListeners(PacketLog log) {
        // Run in temporary list copy to avoid ConcurrentModificationException if listeners modify themselves
        List<PacketProcessedListener> copy;
        synchronized (listeners) {
            copy = new ArrayList<>(listeners);
        }
        for (PacketProcessedListener l : copy) {
            try {
                l.onPacketProcessed(log);
            } catch (Exception e) {
                System.err.println("Error calling packet process listener: " + e.getMessage());
            }
        }
    }

    /**
     * Processes an incoming packet through the deep packet inspection pipeline.
     */
    public static PacketLog processPacket(PacketLog log) {
        // 1. IP Blacklist Check
        if (DatabaseManager.isIPBlacklisted(log.getSourceIP())) {
            log.setThreatStatus("Suspicious");
            log.setActionTaken("Blocked");
            log.setDetails("BLOCKED: Source IP (" + log.getSourceIP() + ") is on the system blacklist.");
            
            DatabaseManager.addPacketLog(log);
            notifyListeners(log);
            return log;
        }
        
        if (DatabaseManager.isIPBlacklisted(log.getDestinationIP())) {
            log.setThreatStatus("Suspicious");
            log.setActionTaken("Blocked");
            log.setDetails("BLOCKED: Destination IP (" + log.getDestinationIP() + ") is on the system blacklist.");
            
            DatabaseManager.addPacketLog(log);
            notifyListeners(log);
            return log;
        }

        // 2. Website/Domain Filter Check
        String host = log.getDomain();
        if (host == null) {
            host = ProtocolAnalyzer.extractDomain(log.getProtocol(), log.getPayload());
        }
        if (host == null) {
            host = DatabaseManager.getDomainByIp(log.getSourceIP());
            if (host == null) {
                host = DatabaseManager.getDomainByIp(log.getDestinationIP());
            }
            if (host != null) {
                log.setDomain(host);
            }
        }
        
        if (host != null && DatabaseManager.isDomainBlocked(host)) {
            log.setThreatStatus("Suspicious");
            log.setActionTaken("Blocked");
            log.setDetails("BLOCKED: Access to forbidden domain '" + host + "' restricted by firewall rules.");
            
            DatabaseManager.addPacketLog(log);
            notifyListeners(log);
            return log;
        }

        // 3. Deep Payload Signature Matching
        ThreatSignature matchedSignature = PayloadInspector.inspectPayload(log.getPayload());
        if (matchedSignature != null) {
            log.setThreatStatus("Suspicious");
            log.setActionTaken("Blocked");
            log.setDetails("ALERT [" + matchedSignature.getSeverity() + "]: " + 
                           matchedSignature.getName() + " (" + matchedSignature.getCategory() + ") detected in payload content.");
            
            // DYNAMIC DUAL DEFENSE: Dynamically blacklists the attacking IP
            String attackingIp = log.getSourceIP();
            DatabaseManager.addToBlacklist(attackingIp, "Dynamic Firewall Block: Triggered threat signature " + matchedSignature.getName());
            
            DatabaseManager.addPacketLog(log);
            notifyListeners(log);
            return log;
        }

        // 4. Default Safe Case
        log.setThreatStatus("Safe");
        log.setActionTaken("Allowed");
        
        String extractedDomain = log.getDomain();
        if (extractedDomain == null) {
            extractedDomain = ProtocolAnalyzer.extractDomain(log.getProtocol(), log.getPayload());
        }
        if (extractedDomain != null) {
            log.setDetails("Clean Traffic: Connection to domain <b style='color:#10b981;'>" + extractedDomain + "</b> allowed. Inspected payload content (" + log.getPayload().length() + " bytes). No threat matched.");
        } else if (log.getPayload() != null && !log.getPayload().trim().isEmpty()) {
            log.setDetails("Clean Traffic: Inspected payload content (" + log.getPayload().length() + " bytes). No threat matched.");
        } else {
            log.setDetails("Clean Traffic: Connection allowed. Empty / raw header packet.");
        }

        DatabaseManager.addPacketLog(log);
        notifyListeners(log);
        return log;
    }
}

package com.cyber.dpi.analyzer;

import com.cyber.dpi.db.DatabaseManager;
import com.cyber.dpi.model.ThreatSignature;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PayloadInspector {
    
    /**
     * Inspects a packet payload against all active threat signatures in the database.
     * Returns the matched signature if a threat is found, otherwise null.
     */
    public static ThreatSignature inspectPayload(String payload) {
        if (payload == null || payload.trim().isEmpty()) {
            return null;
        }

        List<ThreatSignature> signatures = DatabaseManager.getThreatSignatures();
        for (ThreatSignature sig : signatures) {
            try {
                // Compile and search for pattern in payload (case-insensitive usually set in the regex itself, e.g. (?i))
                Pattern pattern = Pattern.compile(sig.getPattern());
                Matcher matcher = pattern.matcher(payload);
                if (matcher.find()) {
                    return sig; // Found a matching threat signature!
                }
            } catch (Exception e) {
                System.err.println("Invalid regex pattern in signature " + sig.getId() + ": " + sig.getPattern());
            }
        }
        return null;
    }
}

package com.cyber.dpi.model;

public class ThreatSignature {
    private String id;
    private String name;
    private String pattern;
    private String severity; // Low, Medium, High, Critical
    private String category; // SQL_INJECTION, XSS, PATH_TRAVERSAL, MALWARE, RCE, etc.

    public ThreatSignature(String id, String name, String pattern, String severity, String category) {
        this.id = id;
        this.name = name;
        this.pattern = pattern;
        this.severity = severity;
        this.category = category;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    @Override
    public String toString() {
        return name + " (" + category + " - " + severity + ")";
    }
}

package com.cyber.dpi.db;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class HostsFileSynchronizer {
    private static final String HOSTS_PATH = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    private static final String MARKER = "# DPI-SYSTEM-BLOCK";

    /**
     * Synchronizes the active SQLite website filters to the Windows hosts file.
     * Returns true if successful, false if permission is denied (requires Admin rights).
     */
    public static synchronized boolean syncHostsFile() {
        File file = new File(HOSTS_PATH);
        if (!file.exists()) {
            System.err.println("Windows hosts file not found at " + HOSTS_PATH);
            return false;
        }

        try {
            // 1. Fetch all blocked domains from database
            List<String[]> blockedWebsites = DatabaseManager.getFilteredWebsites();
            
            // 2. Read existing lines, skipping previous DPI markers
            List<String> lines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.contains(MARKER) && 
                        !line.contains("START OF DPI ACTIVE FIREWALL BLOCKS") && 
                        !line.contains("END OF DPI ACTIVE FIREWALL BLOCKS")) {
                        lines.add(line);
                    }
                }
            }

            // Trim extra trailing blank lines
            while (!lines.isEmpty() && lines.get(lines.size() - 1).trim().isEmpty()) {
                lines.remove(lines.size() - 1);
            }

            // 3. Append active blocks
            if (!blockedWebsites.isEmpty()) {
                lines.add("");
                lines.add("# >>> START OF DPI ACTIVE FIREWALL BLOCKS >>>");
                for (String[] site : blockedWebsites) {
                    String domain = site[0].trim().toLowerCase();
                    if (!domain.isEmpty()) {
                        lines.add("127.0.0.1 " + domain + " " + MARKER);
                        if (!domain.startsWith("www.")) {
                            lines.add("127.0.0.1 www." + domain + " " + MARKER);
                        }
                    }
                }
                lines.add("# <<< END OF DPI ACTIVE FIREWALL BLOCKS <<<");
            }

            // 4. Write back to system hosts file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                for (String line : lines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            System.out.println("Hosts file synchronized with active DPI firewall rules.");
            return true;
        } catch (IOException e) {
            System.err.println("Permission Denied: Cannot write to hosts file. Run as Administrator: " + e.getMessage());
            return false;
        }
    }
}

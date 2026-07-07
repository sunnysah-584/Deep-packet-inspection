package com.cyber.dpi;

import com.cyber.dpi.db.DatabaseManager;
import com.cyber.dpi.ui.MainFrame;
import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.*;
import java.awt.*;

public class App {
    public static void main(String[] args) {
        // 1. Setup flat dark cybersecurity theme using FlatLaf
        try {
            // Customize FlatLaf properties before setup
            UIManager.put("Button.arc", 8);
            UIManager.put("Component.arc", 8);
            UIManager.put("TextComponent.arc", 8);
            UIManager.put("TableHeader.background", new Color(40, 44, 52));
            UIManager.put("TableHeader.foreground", Color.WHITE);
            UIManager.put("Table.alternateRowColor", new Color(38, 42, 50));
            UIManager.put("ScrollBar.thumbArc", 999);
            UIManager.put("ScrollBar.trackArc", 999);
            
            FlatDarkLaf.setup();
            System.out.println("FlatLaf Dark Theme loaded successfully.");
        } catch (Exception e) {
            System.err.println("Failed to initialize FlatLaf theme, falling back to cross-platform L&F.");
            try {
                UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        // 2. Initialize the SQLite database and create tables
        DatabaseManager.initializeDatabase();
        
        // Sync active domain blocks on startup
        com.cyber.dpi.db.HostsFileSynchronizer.syncHostsFile();

        // 3. Launch UI on the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            try {
                MainFrame frame = new MainFrame();
                frame.setVisible(true);
            } catch (Exception e) {
                System.err.println("Fatal error starting UI: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }
}

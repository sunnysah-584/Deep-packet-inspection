package com.cyber.dpi.ui;

import com.cyber.dpi.db.DatabaseManager;
import com.cyber.dpi.analyzer.ProtocolAnalyzer;
import com.cyber.dpi.capture.PacketCaptureEngine;
import com.cyber.dpi.capture.PacketSimulator;
import com.cyber.dpi.detector.ThreatDetectionEngine;
import com.cyber.dpi.model.PacketLog;
import com.cyber.dpi.model.ThreatSignature;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

public class MainFrame extends JFrame implements ThreatDetectionEngine.PacketProcessedListener, PacketCaptureEngine.CaptureStatusListener {

    // Theme Color Palette
    private static final Color BG_DARK = new Color(20, 22, 28);
    private static final Color BG_CARD = new Color(28, 30, 38);
    private static final Color TEXT_LIGHT = new Color(220, 224, 232);
    private static final Color TEXT_MUTED = new Color(130, 140, 155);
    private static final Color COLOR_PRIMARY = new Color(50, 130, 246); // Cyber Blue
    private static final Color COLOR_DANGER = new Color(239, 68, 68);   // Neon Red
    private static final Color COLOR_WARNING = new Color(245, 158, 11);  // Amber Orange
    private static final Color COLOR_SUCCESS = new Color(16, 185, 129);  // Neon Green

    // State Variables
    private int countTotal = 0;
    private int countThreats = 0;
    private int countBlocked = 0;
    private int countSigs = 0;

    private int tcpCount = 0;
    private int udpCount = 0;
    private int httpCount = 0;
    private int httpsCount = 0;

    // Background capture engines
    private PacketCaptureEngine liveCapture;
    private boolean isSimulatedMode = false;

    // Charts data queue (packets per second)
    private final Queue<Integer> throughputHistory = new LinkedList<>();
    private final Queue<Integer> threatHistory = new LinkedList<>();
    private int packetsInLastSec = 0;
    private int threatsInLastSec = 0;

    // UI Components
    private CardLayout cardLayout;
    private JPanel contentPanel;
    private Timer throughputTimer;

    // Stats Labels
    private JLabel lblTotalCount;
    private JLabel lblThreatCount;
    private JLabel lblBlockedCount;
    private JLabel lblSigCount;

    // Live Table UI
    private DefaultTableModel liveTableModel;
    private JTable liveTable;
    private List<PacketLog> livePacketsList = new ArrayList<>();
    private JTextArea txtHexDump;
    private JTextPane txtPacketDetails;

    // Dashboard UI
    private JPanel alertDrawer;
    private DynamicChartPanel dashboardChart;
    private JProgressBar barTCP, barUDP, barHTTP, barHTTPS;
    private JLabel lblTCPPercent, lblUDPPercent, lblHTTPPercent, lblHTTPSPercent;

    // Database Tables UI
    private DefaultTableModel blacklistModel;
    private DefaultTableModel domainsModel;
    private DefaultTableModel signaturesModel;
    private DefaultTableModel historyModel;

    // Controls
    private JComboBox<String> cmbNetworkDevs;
    private JButton btnToggleCapture;
    private JRadioButton rdoSimulated, rdoLive;
    private JSlider sldSpeed;
    private JLabel lblSpeedVal;

    public MainFrame() {
        setTitle("Deep Packet Inspection (DPI) System - Security Dashboard");
        setSize(1280, 800);
        setMinimumSize(new Dimension(1024, 700));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_DARK);

        // Initialize Engines
        liveCapture = new PacketCaptureEngine();
        liveCapture.setStatusListener(this);

        // Prefill chart history with zeroes
        for (int i = 0; i < 30; i++) {
            throughputHistory.add(0);
            threatHistory.add(0);
        }

        // Initialize counts from database
        loadInitialCounts();

        // Main Layout: Left Side Nav, Right Dashboard Panel
        setLayout(new BorderLayout());

        add(createLeftSidebar(), BorderLayout.WEST);
        add(createContentArea(), BorderLayout.CENTER);

        // Register engine processing listener
        ThreatDetectionEngine.registerListener(this);

        // Start throughput timer (runs every second to update charts)
        startThroughputTimer();

        // We do NOT auto-start in Live Mode to allow the user to choose their NIC card first.
        System.out.println("System initialized in Live Capturing Mode.");
    }

    private void loadInitialCounts() {
        try {
            countSigs = DatabaseManager.getThreatSignatures().size();
            List<PacketLog> allLogs = DatabaseManager.getPacketLogs("", "All", "All", "All");
            countTotal = allLogs.size();
            for (PacketLog log : allLogs) {
                if ("Suspicious".equalsIgnoreCase(log.getThreatStatus())) {
                    countThreats++;
                }
                if ("Blocked".equalsIgnoreCase(log.getActionTaken())) {
                    countBlocked++;
                }
                
                // Track protocol splits
                incrementProtocolCounters(log.getProtocol());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void incrementProtocolCounters(String protocol) {
        if ("TCP".equalsIgnoreCase(protocol)) tcpCount++;
        else if ("UDP".equalsIgnoreCase(protocol)) udpCount++;
        else if ("HTTP".equalsIgnoreCase(protocol)) httpCount++;
        else if ("HTTPS".equalsIgnoreCase(protocol)) httpsCount++;
    }

    private void startThroughputTimer() {
        throughputTimer = new Timer(1000, e -> {
            synchronized (throughputHistory) {
                throughputHistory.poll();
                throughputHistory.add(packetsInLastSec);
                
                threatHistory.poll();
                threatHistory.add(threatsInLastSec);
                
                packetsInLastSec = 0;
                threatsInLastSec = 0;
            }
            if (dashboardChart != null) {
                dashboardChart.repaint();
            }
        });
        throughputTimer.start();
    }

    private JPanel createLeftSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setPreferredSize(new Dimension(260, 0));
        sidebar.setBackground(new Color(24, 26, 32));
        sidebar.setLayout(new BorderLayout());
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, new Color(40, 44, 52)));

        // Header Title Area
        JPanel pnlTitle = new JPanel(new BorderLayout());
        pnlTitle.setOpaque(false);
        pnlTitle.setBorder(new EmptyBorder(25, 20, 20, 20));

        JLabel title = new JLabel("CYBER SHIELD");
        title.setFont(new Font("Segoe UI", Font.BOLD, 14));
        title.setForeground(COLOR_PRIMARY);
        pnlTitle.add(title, BorderLayout.NORTH);

        JLabel subTitle = new JLabel("DEEP PACKET INSPECTION");
        subTitle.setFont(new Font("Segoe UI", Font.BOLD, 18));
        subTitle.setForeground(Color.WHITE);
        pnlTitle.add(subTitle, BorderLayout.SOUTH);

        sidebar.add(pnlTitle, BorderLayout.NORTH);

        // Sidebar Navigation Links
        JPanel navLinks = new JPanel();
        navLinks.setOpaque(false);
        navLinks.setLayout(new BoxLayout(navLinks, BoxLayout.Y_AXIS));
        navLinks.setBorder(new EmptyBorder(20, 10, 20, 10));

        String[] menuItems = {"Dashboard", "Live Capture", "Firewall Rules", "Threat Database", "Logs History"};
        String[] cardNames = {"DASHBOARD", "CAPTURE", "FIREWALL", "SIGNATURES", "HISTORY"};
        
        JButton[] buttons = new JButton[menuItems.length];

        for (int i = 0; i < menuItems.length; i++) {
            final String cardName = cardNames[i];
            JButton btn = new JButton("  " + menuItems[i]);
            btn.setFont(new Font("Segoe UI", Font.PLAIN, 15));
            btn.setForeground(TEXT_LIGHT);
            btn.setOpaque(false);
            btn.setContentAreaFilled(false);
            btn.setBorderPainted(false);
            btn.setHorizontalAlignment(SwingConstants.LEFT);
            btn.setMaximumSize(new Dimension(240, 45));
            btn.setPreferredSize(new Dimension(240, 45));
            btn.setCursor(new Cursor(Cursor.HAND_CURSOR));

            int index = i;
            btn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    if (!cardName.equals(contentPanel.getName())) {
                        btn.setForeground(Color.WHITE);
                        btn.setOpaque(true);
                        btn.setBackground(new Color(36, 40, 50));
                    }
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    if (!cardName.equals(contentPanel.getName())) {
                        btn.setForeground(TEXT_LIGHT);
                        btn.setOpaque(false);
                    }
                }
            });

            btn.addActionListener(e -> {
                cardLayout.show(contentPanel, cardName);
                contentPanel.setName(cardName);
                
                // Style clicked button and reset others
                for (JButton b : buttons) {
                    b.setOpaque(false);
                    b.setForeground(TEXT_LIGHT);
                }
                btn.setOpaque(true);
                btn.setBackground(new Color(50, 130, 246, 30));
                btn.setForeground(Color.WHITE);
                btn.setBorder(BorderFactory.createMatteBorder(0, 4, 0, 0, COLOR_PRIMARY));
            });

            navLinks.add(btn);
            navLinks.add(Box.createVerticalStrut(8));
            buttons[i] = btn;
        }

        // Auto-select Dashboard
        buttons[0].setOpaque(true);
        buttons[0].setBackground(new Color(50, 130, 246, 30));
        buttons[0].setForeground(Color.WHITE);
        buttons[0].setBorder(BorderFactory.createMatteBorder(0, 4, 0, 0, COLOR_PRIMARY));

        sidebar.add(navLinks, BorderLayout.CENTER);

        // Sidebar Footer Status indicator
        JPanel pnlFooter = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 15));
        pnlFooter.setOpaque(false);
        pnlFooter.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(40, 44, 52)));
        
        JPanel greenDot = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(liveCapture.isRunning() ? COLOR_SUCCESS : COLOR_DANGER);
                g2.fillOval(0, 0, 12, 12);
                g2.dispose();
            }
        };
        greenDot.setPreferredSize(new Dimension(12, 12));
        greenDot.setOpaque(false);

        JLabel lblStatus = new JLabel("Engine Running");
        lblStatus.setFont(new Font("Segoe UI", Font.BOLD, 12));
        lblStatus.setForeground(TEXT_LIGHT);

        pnlFooter.add(greenDot);
        pnlFooter.add(lblStatus);
        
        sidebar.add(pnlFooter, BorderLayout.SOUTH);

        return sidebar;
    }

    private JPanel createContentArea() {
        cardLayout = new CardLayout();
        contentPanel = new JPanel(cardLayout);
        contentPanel.setName("DASHBOARD");
        contentPanel.setOpaque(false);

        // Add sub-panels mapping to tabs
        contentPanel.add(createDashboardPanel(), "DASHBOARD");
        contentPanel.add(createCapturePanel(), "CAPTURE");
        contentPanel.add(createFirewallPanel(), "FIREWALL");
        contentPanel.add(createSignaturesPanel(), "SIGNATURES");
        contentPanel.add(createHistoryPanel(), "HISTORY");

        return contentPanel;
    }

    private JPanel createDashboardPanel() {
        JPanel panel = new JPanel(new BorderLayout(20, 20));
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(25, 25, 25, 25));

        // 1. Stats Bar (Grid layout for cards)
        JPanel statsBar = new JPanel(new GridLayout(1, 4, 15, 0));
        statsBar.setOpaque(false);
        statsBar.setPreferredSize(new Dimension(0, 100));

        statsBar.add(createStatCard("TOTAL INSPECTED", "0", COLOR_PRIMARY));
        statsBar.add(createStatCard("THREATS DETECTED", "0", COLOR_DANGER));
        statsBar.add(createStatCard("BLOCKED EVENTS", "0", COLOR_WARNING));
        statsBar.add(createStatCard("ACTIVE SIGNATURES", "0", COLOR_SUCCESS));

        // Capture labels for updating later
        lblTotalCount = (JLabel) ((JPanel) statsBar.getComponent(0)).getComponent(1);
        lblThreatCount = (JLabel) ((JPanel) statsBar.getComponent(1)).getComponent(1);
        lblBlockedCount = (JLabel) ((JPanel) statsBar.getComponent(2)).getComponent(1);
        lblSigCount = (JLabel) ((JPanel) statsBar.getComponent(3)).getComponent(1);

        updateStatsLabels();

        panel.add(statsBar, BorderLayout.NORTH);

        // 2. Middle Row: Live graph and Alert Drawer
        JPanel middleRow = new JPanel(new BorderLayout(20, 0));
        middleRow.setOpaque(false);

        // A. Sleek Line Graph Panel
        JPanel chartContainer = new JPanel(new BorderLayout());
        chartContainer.setBackground(BG_CARD);
        chartContainer.setBorder(new LineBorder(new Color(45, 48, 58), 1, true));
        chartContainer.setPreferredSize(new Dimension(650, 0));

        JPanel chartHeader = new JPanel(new BorderLayout());
        chartHeader.setOpaque(false);
        chartHeader.setBorder(new EmptyBorder(15, 20, 10, 20));
        JLabel chartTitle = new JLabel("Real-time Throughput (Packets / Sec)");
        chartTitle.setFont(new Font("Segoe UI", Font.BOLD, 16));
        chartTitle.setForeground(Color.WHITE);
        
        JLabel chartDesc = new JLabel("Throughput = Neon Cyan | Threats = Red");
        chartDesc.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        chartDesc.setForeground(TEXT_MUTED);
        chartHeader.add(chartTitle, BorderLayout.WEST);
        chartHeader.add(chartDesc, BorderLayout.EAST);
        chartContainer.add(chartHeader, BorderLayout.NORTH);

        dashboardChart = new DynamicChartPanel();
        chartContainer.add(dashboardChart, BorderLayout.CENTER);

        middleRow.add(chartContainer, BorderLayout.CENTER);

        // B. Threats Drawer (Flashing Cards Panel)
        JPanel rightDrawerContainer = new JPanel(new BorderLayout());
        rightDrawerContainer.setPreferredSize(new Dimension(340, 0));
        rightDrawerContainer.setBackground(BG_CARD);
        rightDrawerContainer.setBorder(new LineBorder(new Color(45, 48, 58), 1, true));

        JPanel drawerHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 15));
        drawerHeader.setOpaque(false);
        JLabel drawerTitle = new JLabel("Live Incident Alerts");
        drawerTitle.setFont(new Font("Segoe UI", Font.BOLD, 16));
        drawerTitle.setForeground(Color.WHITE);
        drawerHeader.add(drawerTitle);
        rightDrawerContainer.add(drawerHeader, BorderLayout.NORTH);

        alertDrawer = new JPanel();
        alertDrawer.setOpaque(false);
        alertDrawer.setLayout(new BoxLayout(alertDrawer, BoxLayout.Y_AXIS));
        alertDrawer.setBorder(new EmptyBorder(5, 10, 10, 10));

        JScrollPane alertScroll = new JScrollPane(alertDrawer);
        alertScroll.setOpaque(false);
        alertScroll.getViewport().setOpaque(false);
        alertScroll.setBorder(null);
        alertScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        rightDrawerContainer.add(alertScroll, BorderLayout.CENTER);

        middleRow.add(rightDrawerContainer, BorderLayout.EAST);

        panel.add(middleRow, BorderLayout.CENTER);

        // 3. Bottom Row: Protocol Distribution progress bars
        JPanel pnlProtocols = new JPanel(new BorderLayout(15, 15));
        pnlProtocols.setBackground(BG_CARD);
        pnlProtocols.setBorder(new EmptyBorder(20, 20, 20, 20));
        pnlProtocols.setPreferredSize(new Dimension(0, 180));

        JLabel lblProtoTitle = new JLabel("Protocol Traffic Analysis");
        lblProtoTitle.setFont(new Font("Segoe UI", Font.BOLD, 16));
        lblProtoTitle.setForeground(Color.WHITE);
        pnlProtocols.add(lblProtoTitle, BorderLayout.NORTH);

        JPanel progressGrid = new JPanel(new GridLayout(2, 2, 30, 15));
        progressGrid.setOpaque(false);

        progressGrid.add(createProtocolProgress("TCP", barTCP = new JProgressBar(), lblTCPPercent = new JLabel("0%"), COLOR_PRIMARY));
        progressGrid.add(createProtocolProgress("UDP", barUDP = new JProgressBar(), lblUDPPercent = new JLabel("0%"), COLOR_SUCCESS));
        progressGrid.add(createProtocolProgress("HTTP", barHTTP = new JProgressBar(), lblHTTPPercent = new JLabel("0%"), COLOR_WARNING));
        progressGrid.add(createProtocolProgress("HTTPS", barHTTPS = new JProgressBar(), lblHTTPSPercent = new JLabel("0%"), COLOR_DANGER));

        pnlProtocols.add(progressGrid, BorderLayout.CENTER);

        panel.add(pnlProtocols, BorderLayout.SOUTH);

        updateProtocolProgressUI();

        return panel;
    }

    private JPanel createProtocolProgress(String name, JProgressBar bar, JLabel percentLabel, Color color) {
        JPanel container = new JPanel(new BorderLayout(5, 5));
        container.setOpaque(false);

        JPanel labels = new JPanel(new BorderLayout());
        labels.setOpaque(false);
        JLabel nameLabel = new JLabel(name);
        nameLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        nameLabel.setForeground(TEXT_LIGHT);
        labels.add(nameLabel, BorderLayout.WEST);

        percentLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        percentLabel.setForeground(color);
        labels.add(percentLabel, BorderLayout.EAST);

        container.add(labels, BorderLayout.NORTH);

        bar.setStringPainted(false);
        bar.setForeground(color);
        bar.setBackground(new Color(40, 44, 52));
        bar.setBorder(null);
        bar.setPreferredSize(new Dimension(0, 12));

        container.add(bar, BorderLayout.CENTER);

        return container;
    }

    private void updateProtocolProgressUI() {
        int total = tcpCount + udpCount + httpCount + httpsCount;
        if (total == 0) return;

        int pTCP = (tcpCount * 100) / total;
        int pUDP = (udpCount * 100) / total;
        int pHTTP = (httpCount * 100) / total;
        int pHTTPS = (httpsCount * 100) / total;

        barTCP.setValue(pTCP);
        lblTCPPercent.setText(pTCP + "% (" + tcpCount + ")");

        barUDP.setValue(pUDP);
        lblUDPPercent.setText(pUDP + "% (" + udpCount + ")");

        barHTTP.setValue(pHTTP);
        lblHTTPPercent.setText(pHTTP + "% (" + httpCount + ")");

        barHTTPS.setValue(pHTTPS);
        lblHTTPSPercent.setText(pHTTPS + "% (" + httpsCount + ")");
    }

    private JPanel createStatCard(String label, String value, Color color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(45, 48, 58), 1, true),
                new EmptyBorder(15, 20, 15, 20)
        ));

        JLabel lblName = new JLabel(label);
        lblName.setFont(new Font("Segoe UI", Font.BOLD, 12));
        lblName.setForeground(TEXT_MUTED);
        card.add(lblName, BorderLayout.NORTH);

        JLabel lblVal = new JLabel(value);
        lblVal.setFont(new Font("Segoe UI", Font.BOLD, 32));
        lblVal.setForeground(Color.WHITE);
        card.add(lblVal, BorderLayout.CENTER);

        JPanel borderStripe = new JPanel();
        borderStripe.setPreferredSize(new Dimension(0, 4));
        borderStripe.setBackground(color);
        card.add(borderStripe, BorderLayout.SOUTH);

        return card;
    }

    private void updateStatsLabels() {
        if (lblTotalCount != null) {
            lblTotalCount.setText(String.format("%,d", countTotal));
            lblThreatCount.setText(String.format("%,d", countThreats));
            lblBlockedCount.setText(String.format("%,d", countBlocked));
            lblSigCount.setText(String.format("%,d", countSigs));
        }
    }

    private JPanel createCapturePanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(25, 25, 25, 25));

        // 1. Controls Top Bar
        JPanel controls = new JPanel(new GridBagLayout());
        controls.setBackground(BG_CARD);
        controls.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(45, 48, 58), 1, true),
                new EmptyBorder(15, 20, 15, 20)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 15);

        // Selector Title
        gbc.gridx = 0;
        JLabel lblNic = new JLabel("Select Network Adapter:");
        lblNic.setFont(new Font("Segoe UI", Font.BOLD, 13));
        lblNic.setForeground(Color.WHITE);
        controls.add(lblNic, gbc);

        // Network Interface combo box (Enabled by default)
        gbc.gridx = 1;
        cmbNetworkDevs = new JComboBox<>();
        cmbNetworkDevs.setPreferredSize(new Dimension(380, 32));
        cmbNetworkDevs.setEnabled(true);
        controls.add(cmbNetworkDevs, gbc);

        // Load devices in dropdown
        List<String> devs = PacketCaptureEngine.getNetworkInterfaces();
        if (devs.isEmpty()) {
            cmbNetworkDevs.addItem("No Network Adapters Detected (Requires Npcap)");
            cmbNetworkDevs.setEnabled(false);
        } else {
            for (String dev : devs) {
                cmbNetworkDevs.addItem(dev);
            }
        }

        // Toggle Button
        gbc.gridx = 2;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.EAST;
        btnToggleCapture = new JButton("Start Capture");
        btnToggleCapture.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btnToggleCapture.setPreferredSize(new Dimension(140, 34));
        btnToggleCapture.setBackground(COLOR_SUCCESS);
        btnToggleCapture.setForeground(Color.WHITE);
        btnToggleCapture.addActionListener(e -> toggleCapture());
        controls.add(btnToggleCapture, gbc);

        panel.add(controls, BorderLayout.NORTH);

        // 2. Main Live View Split Pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setOpaque(false);
        splitPane.setDividerLocation(340);
        splitPane.setResizeWeight(0.5);

        // Top Part: Scrolling Packet Table
        String[] cols = {"Time", "Source IP", "Dest IP", "Protocol", "Port (S>D)", "Size (Bytes)", "Status", "Action"};
        liveTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        liveTable = new JTable(liveTableModel);
        liveTable.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        liveTable.setRowHeight(26);
        liveTable.setGridColor(new Color(40, 44, 52));
        liveTable.getTableHeader().setReorderingAllowed(false);

        // Customize table columns width
        liveTable.getColumnModel().getColumn(0).setPreferredWidth(100);
        liveTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        liveTable.getColumnModel().getColumn(2).setPreferredWidth(120);
        liveTable.getColumnModel().getColumn(3).setPreferredWidth(70);
        liveTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        liveTable.getColumnModel().getColumn(5).setPreferredWidth(90);
        liveTable.getColumnModel().getColumn(6).setPreferredWidth(90);
        liveTable.getColumnModel().getColumn(7).setPreferredWidth(90);

        // Customize renderers for dynamic colored status/actions
        liveTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean isSel, boolean hasFocus, int r, int c) {
                Component comp = super.getTableCellRendererComponent(tbl, val, isSel, hasFocus, r, c);
                
                String action = (String) tbl.getValueAt(r, 7);
                String status = (String) tbl.getValueAt(r, 6);

                if (isSel) {
                    comp.setBackground(new Color(50, 130, 246, 50));
                    comp.setForeground(Color.WHITE);
                } else {
                    comp.setBackground(r % 2 == 0 ? BG_CARD : new Color(38, 42, 50));
                    comp.setForeground(TEXT_LIGHT);
                }

                if (c == 7) {
                    comp.setFont(new Font("Segoe UI", Font.BOLD, 13));
                    if ("Blocked".equalsIgnoreCase(action)) {
                        comp.setForeground(COLOR_DANGER);
                    } else {
                        comp.setForeground(COLOR_SUCCESS);
                    }
                } else if (c == 6) {
                    comp.setFont(new Font("Segoe UI", Font.BOLD, 12));
                    if ("Suspicious".equalsIgnoreCase(status)) {
                        comp.setForeground(COLOR_DANGER);
                    } else {
                        comp.setForeground(COLOR_SUCCESS);
                    }
                } else if (c == 5) {
                    comp.setFont(new Font("Segoe UI", Font.BOLD, 12));
                    comp.setForeground(COLOR_PRIMARY);
                }
                return comp;
            }
        });

        JScrollPane tableScroll = new JScrollPane(liveTable);
        tableScroll.setBackground(BG_CARD);
        tableScroll.getViewport().setBackground(BG_CARD);
        tableScroll.setBorder(new LineBorder(new Color(45, 48, 58)));
        splitPane.setTopComponent(tableScroll);

        // Bottom Part: Selected Packet Details + Hex Dump
        JPanel bottomDetails = new JPanel(new GridLayout(1, 2, 15, 0));
        bottomDetails.setOpaque(false);

        // Left Detail Panel
        JPanel leftDetailPnl = new JPanel(new BorderLayout());
        leftDetailPnl.setBackground(BG_CARD);
        leftDetailPnl.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(45, 48, 58), 1, true),
                new EmptyBorder(10, 15, 10, 15)
        ));

        JLabel lblDetailTitle = new JLabel("Packet Header Information");
        lblDetailTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
        lblDetailTitle.setForeground(COLOR_PRIMARY);
        leftDetailPnl.add(lblDetailTitle, BorderLayout.NORTH);

        txtPacketDetails = new JTextPane();
        txtPacketDetails.setEditable(false);
        txtPacketDetails.setFont(new Font("Consolas", Font.PLAIN, 13));
        txtPacketDetails.setBackground(BG_CARD);
        txtPacketDetails.setForeground(TEXT_LIGHT);
        txtPacketDetails.setContentType("text/html");
        txtPacketDetails.setText("<div style='color:#828c9b;font-family:Segoe UI;'>Select a packet from the table above to view detailed headers.</div>");

        leftDetailPnl.add(new JScrollPane(txtPacketDetails), BorderLayout.CENTER);
        bottomDetails.add(leftDetailPnl);

        // Right Hex Dump Panel
        JPanel rightHexPnl = new JPanel(new BorderLayout());
        rightHexPnl.setBackground(BG_CARD);
        rightHexPnl.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(45, 48, 58), 1, true),
                new EmptyBorder(10, 15, 10, 15)
        ));

        JLabel lblHexTitle = new JLabel("Raw Hexadecimal & ASCII Payload Dump");
        lblHexTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
        lblHexTitle.setForeground(COLOR_PRIMARY);
        rightHexPnl.add(lblHexTitle, BorderLayout.NORTH);

        txtHexDump = new JTextArea();
        txtHexDump.setEditable(false);
        txtHexDump.setFont(new Font("Consolas", Font.PLAIN, 12));
        txtHexDump.setBackground(new Color(20, 21, 26));
        txtHexDump.setForeground(new Color(110, 220, 110)); // Sleek green console output
        txtHexDump.setBorder(new EmptyBorder(10, 10, 10, 10));
        txtHexDump.setText("0000  No Packet Selected.");

        JScrollPane hexScroll = new JScrollPane(txtHexDump);
        hexScroll.setBorder(new LineBorder(new Color(40, 44, 52)));
        rightHexPnl.add(hexScroll, BorderLayout.CENTER);
        bottomDetails.add(rightHexPnl);

        splitPane.setBottomComponent(bottomDetails);

        panel.add(splitPane, BorderLayout.CENTER);

        // Row Selection Listener
        liveTable.getSelectionModel().addListSelectionListener(e -> {
            int r = liveTable.getSelectedRow();
            if (r >= 0 && r < livePacketsList.size()) {
                PacketLog log = livePacketsList.get(r);
                showPacketDetails(log);
            }
        });

        return panel;
    }

    private void showPacketDetails(PacketLog log) {
        // Look up pre-extracted binary domain or extract dynamically
        String domain = log.getDomain();
        if (domain == null) {
            domain = com.cyber.dpi.analyzer.ProtocolAnalyzer.extractDomain(log.getProtocol(), log.getPayload());
        }
        String domainDisplay = domain != null ? 
            "<span style='color:#f59e0b;font-weight:bold;'>" + domain + "</span>" : 
            "<span style='color:#828c9b;'>[N/A - Encrypted/No Domain]</span>";

        // Formatted Header details
        StringBuilder sb = new StringBuilder();
        sb.append("<div style='font-family:Segoe UI; font-size:11px; color:#cdd2dc;'>");
        sb.append("<b>Packet ID:</b> ").append(log.getId()).append("<br/>");
        sb.append("<b>Timestamp:</b> ").append(log.getTimestamp()).append("<br/>");
        sb.append("<hr style='border:0; border-top:1px solid #2d303a;'/>");
        sb.append("<b>Source Socket:</b> <span style='color:#3282f6;'>").append(log.getSourceIP()).append("</span>:").append(log.getSourcePort()).append("<br/>");
        sb.append("<b>Destination Socket:</b> <span style='color:#3282f6;'>").append(log.getDestinationIP()).append("</span>:").append(log.getDestPort()).append("<br/>");
        sb.append("<b>Protocol Layer:</b> <span style='color:#10b981;font-weight:bold;'>").append(log.getProtocol()).append("</span><br/>");
        sb.append("<b>Target Domain:</b> ").append(domainDisplay).append("<br/>");
        sb.append("<hr style='border:0; border-top:1px solid #2d303a;'/>");
        
        String color = "Safe".equalsIgnoreCase(log.getThreatStatus()) ? "#10b981" : "#ef4444";
        sb.append("<b>Threat Evaluation Status:</b> <span style='color:").append(color).append(";font-weight:bold;'>").append(log.getThreatStatus()).append("</span><br/>");
        
        String actColor = "Allowed".equalsIgnoreCase(log.getActionTaken()) ? "#10b981" : "#ef4444";
        sb.append("<b>Firewall Action:</b> <span style='color:").append(actColor).append(";font-weight:bold;'>").append(log.getActionTaken()).append("</span><br/>");
        sb.append("<br/><b>Details:</b> <span style='color:#828c9b;'>").append(log.getDetails()).append("</span>");
        sb.append("</div>");

        txtPacketDetails.setText(sb.toString());

        // Hex Dump output
        txtHexDump.setText(ProtocolAnalyzer.convertToHexDump(log.getPayload()));
        txtHexDump.setCaretPosition(0);
    }

    private void toggleCapture() {
        boolean active = liveCapture.isRunning();
        if (active) {
            // Stop
            liveCapture.stop();

            btnToggleCapture.setText("Start Capture");
            btnToggleCapture.setBackground(COLOR_SUCCESS);
            
            cmbNetworkDevs.setEnabled(true);
        } else {
            // Start
            cmbNetworkDevs.setEnabled(false);

            String dev = (String) cmbNetworkDevs.getSelectedItem();
            if (dev != null && !dev.startsWith("No Network")) {
                String devName = dev.split(" ")[0];
                liveCapture.start(devName);
            }

            btnToggleCapture.setText("Stop Capture");
            btnToggleCapture.setBackground(COLOR_DANGER);
        }
        repaint();
    }

    private JPanel createFirewallPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 20));
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(25, 25, 25, 25));

        JTabbedPane tabPane = new JTabbedPane();
        tabPane.setFont(new Font("Segoe UI", Font.BOLD, 13));

        // TAB 1: IP Blacklist Manager
        JPanel pnlIpBlacklist = new JPanel(new BorderLayout(15, 15));
        pnlIpBlacklist.setOpaque(false);
        pnlIpBlacklist.setBorder(new EmptyBorder(15, 15, 15, 15));

        // Form to add
        JPanel formIp = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 10));
        formIp.setBackground(BG_CARD);
        formIp.setBorder(new LineBorder(new Color(45, 48, 58), 1, true));
        
        JLabel lblIp = new JLabel("IP Address:");
        lblIp.setForeground(Color.WHITE);
        JTextField txtIp = new JTextField(15);
        txtIp.setPreferredSize(new Dimension(150, 30));

        JLabel lblReason = new JLabel("Reason:");
        lblReason.setForeground(Color.WHITE);
        JTextField txtReason = new JTextField(25);
        txtReason.setPreferredSize(new Dimension(250, 30));

        JButton btnAddIp = new JButton("Block IP Address");
        btnAddIp.setBackground(COLOR_PRIMARY);
        btnAddIp.setForeground(Color.WHITE);
        btnAddIp.setPreferredSize(new Dimension(140, 30));
        
        formIp.add(lblIp);
        formIp.add(txtIp);
        formIp.add(lblReason);
        formIp.add(txtReason);
        formIp.add(btnAddIp);

        pnlIpBlacklist.add(formIp, BorderLayout.NORTH);

        // Table
        String[] colsIp = {"IP Address", "Block Reason", "Timestamp", "Action"};
        blacklistModel = new DefaultTableModel(colsIp, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return c == 3; }
        };
        JTable tblBlacklist = new JTable(blacklistModel);
        tblBlacklist.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        tblBlacklist.setRowHeight(28);

        JScrollPane scrollIp = new JScrollPane(tblBlacklist);
        scrollIp.getViewport().setBackground(BG_CARD);
        scrollIp.setBorder(new LineBorder(new Color(40, 44, 52)));
        pnlIpBlacklist.add(scrollIp, BorderLayout.CENTER);

        tabPane.addTab("IP Address Blacklist", pnlIpBlacklist);

        // TAB 2: Domain Website filter Manager
        JPanel pnlWebsites = new JPanel(new BorderLayout(15, 15));
        pnlWebsites.setOpaque(false);
        pnlWebsites.setBorder(new EmptyBorder(15, 15, 15, 15));

        // Form
        JPanel formWeb = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 10));
        formWeb.setBackground(BG_CARD);
        formWeb.setBorder(new LineBorder(new Color(45, 48, 58), 1, true));

        JLabel lblDomain = new JLabel("Domain / URL:");
        lblDomain.setForeground(Color.WHITE);
        JTextField txtDomain = new JTextField(20);
        txtDomain.setPreferredSize(new Dimension(200, 30));

        JLabel lblCat = new JLabel("Block Category:");
        lblCat.setForeground(Color.WHITE);
        JComboBox<String> cmbCat = new JComboBox<>(new String[]{"Malware", "Phishing", "Gambling", "Social Media", "Anonymizer", "Custom"});
        cmbCat.setPreferredSize(new Dimension(150, 30));

        JButton btnAddDomain = new JButton("Filter Website");
        btnAddDomain.setBackground(COLOR_PRIMARY);
        btnAddDomain.setForeground(Color.WHITE);
        btnAddDomain.setPreferredSize(new Dimension(140, 30));

        formWeb.add(lblDomain);
        formWeb.add(txtDomain);
        formWeb.add(lblCat);
        formWeb.add(cmbCat);
        formWeb.add(btnAddDomain);

        pnlWebsites.add(formWeb, BorderLayout.NORTH);

        // Table
        String[] colsWeb = {"Blocked Domain", "Category", "Blocked Date", "Action"};
        domainsModel = new DefaultTableModel(colsWeb, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return c == 3; }
        };
        JTable tblDomains = new JTable(domainsModel);
        tblDomains.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        tblDomains.setRowHeight(28);

        JScrollPane scrollWeb = new JScrollPane(tblDomains);
        scrollWeb.getViewport().setBackground(BG_CARD);
        scrollWeb.setBorder(new LineBorder(new Color(40, 44, 52)));
        pnlWebsites.add(scrollWeb, BorderLayout.CENTER);

        tabPane.addTab("Domain & Website Filtering", pnlWebsites);

        panel.add(tabPane, BorderLayout.CENTER);

        // Load tables data
        loadBlacklistTableData();
        loadWebsiteFilterTableData();

        // Add action handlers to Blacklist manually
        btnAddIp.addActionListener(e -> {
            String ip = txtIp.getText().trim();
            String reason = txtReason.getText().trim();
            if (ip.isEmpty() || reason.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter both IP address and blocking reason.");
                return;
            }
            DatabaseManager.addToBlacklist(ip, reason);
            txtIp.setText("");
            txtReason.setText("");
            loadBlacklistTableData();
        });

        // Add action handlers to Domains manually
        btnAddDomain.addActionListener(e -> {
            String dom = txtDomain.getText().trim();
            String cat = (String) cmbCat.getSelectedItem();
            if (dom.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter a valid domain (e.g. hack-site.com).");
                return;
            }
            DatabaseManager.addToWebsiteFilter(dom, cat);
            txtDomain.setText("");
            loadWebsiteFilterTableData();
        });

        // Setup delete/remove buttons in cells
        setupTableActionDelete(tblBlacklist, blacklistModel, true);
        setupTableActionDelete(tblDomains, domainsModel, false);

        return panel;
    }

    private void loadBlacklistTableData() {
        blacklistModel.setRowCount(0);
        List<String[]> list = DatabaseManager.getBlacklistedIPs();
        for (String[] row : list) {
            blacklistModel.addRow(new Object[]{row[0], row[1], row[2], "Delete"});
        }
    }

    private void loadWebsiteFilterTableData() {
        domainsModel.setRowCount(0);
        List<String[]> list = DatabaseManager.getFilteredWebsites();
        for (String[] row : list) {
            domainsModel.addRow(new Object[]{row[0], row[1], row[2], "Delete"});
        }
    }

    private void setupTableActionDelete(JTable tbl, DefaultTableModel model, boolean isBlacklist) {
        tbl.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JButton btn = new JButton("Remove");
                btn.setFont(new Font("Segoe UI", Font.BOLD, 11));
                btn.setBackground(COLOR_DANGER);
                btn.setForeground(Color.WHITE);
                btn.setBorderPainted(false);
                return btn;
            }
        });

        tbl.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = tbl.columnAtPoint(e.getPoint());
                int row = tbl.rowAtPoint(e.getPoint());
                if (col == 3 && row >= 0) {
                    String target = (String) tbl.getValueAt(row, 0);
                    int choice = JOptionPane.showConfirmDialog(
                            MainFrame.this, 
                            "Are you sure you want to remove rule for '" + target + "'?", 
                            "Confirm Delete Rule", 
                            JOptionPane.YES_NO_OPTION
                    );
                    if (choice == JOptionPane.YES_OPTION) {
                        if (isBlacklist) {
                            DatabaseManager.removeFromBlacklist(target);
                            loadBlacklistTableData();
                        } else {
                            DatabaseManager.removeFromWebsiteFilter(target);
                            loadWebsiteFilterTableData();
                        }
                    }
                }
            }
        });
    }

    private JPanel createSignaturesPanel() {
        JPanel panel = new JPanel(new BorderLayout(20, 0));
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(25, 25, 25, 25));

        // Left Form
        JPanel formPnl = new JPanel(new GridBagLayout());
        formPnl.setPreferredSize(new Dimension(320, 0));
        formPnl.setBackground(BG_CARD);
        formPnl.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(45, 48, 58), 1, true),
                new EmptyBorder(20, 20, 20, 20)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 0, 15, 0);
        gbc.gridx = 0;

        JLabel lblTitle = new JLabel("Add Threat Signature");
        lblTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        lblTitle.setForeground(COLOR_PRIMARY);
        formPnl.add(lblTitle, gbc);

        JLabel lblId = new JLabel("Signature ID:");
        lblId.setForeground(TEXT_LIGHT);
        formPnl.add(lblId, gbc);

        JTextField txtSigId = new JTextField();
        txtSigId.setPreferredSize(new Dimension(0, 32));
        formPnl.add(txtSigId, gbc);

        JLabel lblName = new JLabel("Signature Name:");
        lblName.setForeground(TEXT_LIGHT);
        formPnl.add(lblName, gbc);

        JTextField txtSigName = new JTextField();
        txtSigName.setPreferredSize(new Dimension(0, 32));
        formPnl.add(txtSigName, gbc);

        JLabel lblPattern = new JLabel("Regex Pattern:");
        lblPattern.setForeground(TEXT_LIGHT);
        formPnl.add(lblPattern, gbc);

        JTextField txtPattern = new JTextField();
        txtPattern.setPreferredSize(new Dimension(0, 32));
        formPnl.add(txtPattern, gbc);

        JLabel lblSeverity = new JLabel("Severity Rating:");
        lblSeverity.setForeground(TEXT_LIGHT);
        formPnl.add(lblSeverity, gbc);

        JComboBox<String> cmbSev = new JComboBox<>(new String[]{"Low", "Medium", "High", "Critical"});
        cmbSev.setPreferredSize(new Dimension(0, 32));
        formPnl.add(cmbSev, gbc);

        JLabel lblCategory = new JLabel("Threat Category:");
        lblCategory.setForeground(TEXT_LIGHT);
        formPnl.add(lblCategory, gbc);

        JComboBox<String> cmbCat = new JComboBox<>(new String[]{
                "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "REMOTE_CODE_EXECUTION", "MALWARE", "INFO_DISCLOSURE"
        });
        cmbCat.setPreferredSize(new Dimension(0, 32));
        formPnl.add(cmbCat, gbc);

        JButton btnAdd = new JButton("Save Threat Signature");
        btnAdd.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btnAdd.setBackground(COLOR_PRIMARY);
        btnAdd.setForeground(Color.WHITE);
        btnAdd.setPreferredSize(new Dimension(0, 36));
        
        gbc.insets = new Insets(10, 0, 0, 0);
        formPnl.add(btnAdd, gbc);

        panel.add(formPnl, BorderLayout.WEST);

        // Right Table
        JPanel tablePnl = new JPanel(new BorderLayout(0, 10));
        tablePnl.setOpaque(false);

        JLabel tblHeading = new JLabel("Active Inspection Signature Database");
        tblHeading.setFont(new Font("Segoe UI", Font.BOLD, 16));
        tblHeading.setForeground(Color.WHITE);
        tablePnl.add(tblHeading, BorderLayout.NORTH);

        String[] cols = {"ID", "Name", "Regex Pattern", "Severity", "Category", "Action"};
        signaturesModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return c == 5; }
        };

        JTable tblSigs = new JTable(signaturesModel);
        tblSigs.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        tblSigs.setRowHeight(28);

        tblSigs.getColumnModel().getColumn(0).setPreferredWidth(70);
        tblSigs.getColumnModel().getColumn(1).setPreferredWidth(150);
        tblSigs.getColumnModel().getColumn(2).setPreferredWidth(180);
        tblSigs.getColumnModel().getColumn(3).setPreferredWidth(70);
        tblSigs.getColumnModel().getColumn(4).setPreferredWidth(120);
        tblSigs.getColumnModel().getColumn(5).setPreferredWidth(80);

        JScrollPane scroll = new JScrollPane(tblSigs);
        scroll.getViewport().setBackground(BG_CARD);
        scroll.setBorder(new LineBorder(new Color(40, 44, 52)));
        tablePnl.add(scroll, BorderLayout.CENTER);

        panel.add(tablePnl, BorderLayout.CENTER);

        // Load data
        loadSignaturesTableData();

        // Action handlers
        btnAdd.addActionListener(e -> {
            String id = txtSigId.getText().trim();
            String name = txtSigName.getText().trim();
            String pattern = txtPattern.getText().trim();
            String sev = (String) cmbSev.getSelectedItem();
            String cat = (String) cmbCat.getSelectedItem();

            if (id.isEmpty() || name.isEmpty() || pattern.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please fill all threat signature form details.");
                return;
            }

            // Simple validation of regex
            try {
                java.util.regex.Pattern.compile(pattern);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Invalid regular expression syntax: " + ex.getMessage());
                return;
            }

            ThreatSignature sig = new ThreatSignature(id, name, pattern, sev, cat);
            DatabaseManager.addThreatSignature(sig);
            
            txtSigId.setText("");
            txtSigName.setText("");
            txtPattern.setText("");

            loadSignaturesTableData();
            countSigs = DatabaseManager.getThreatSignatures().size();
            updateStatsLabels();
        });

        // Setup delete action
        tblSigs.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JButton btn = new JButton("Delete");
                btn.setFont(new Font("Segoe UI", Font.BOLD, 11));
                btn.setBackground(COLOR_DANGER);
                btn.setForeground(Color.WHITE);
                btn.setBorderPainted(false);
                return btn;
            }
        });

        tblSigs.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = tblSigs.columnAtPoint(e.getPoint());
                int row = tblSigs.rowAtPoint(e.getPoint());
                if (col == 5 && row >= 0) {
                    String sigId = (String) tblSigs.getValueAt(row, 0);
                    int choice = JOptionPane.showConfirmDialog(
                            MainFrame.this,
                            "Delete custom threat signature '" + sigId + "'?",
                            "Confirm Delete",
                            JOptionPane.YES_NO_OPTION
                    );
                    if (choice == JOptionPane.YES_OPTION) {
                        DatabaseManager.removeThreatSignature(sigId);
                        loadSignaturesTableData();
                        countSigs = DatabaseManager.getThreatSignatures().size();
                        updateStatsLabels();
                    }
                }
            }
        });

        return panel;
    }

    private void loadSignaturesTableData() {
        signaturesModel.setRowCount(0);
        List<ThreatSignature> list = DatabaseManager.getThreatSignatures();
        for (ThreatSignature sig : list) {
            signaturesModel.addRow(new Object[]{
                    sig.getId(), sig.getName(), sig.getPattern(), sig.getSeverity(), sig.getCategory(), "Delete"
            });
        }
    }

    private JPanel createHistoryPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(25, 25, 25, 25));

        // Search and filter top pane
        JPanel filterPnl = new JPanel(new GridBagLayout());
        filterPnl.setBackground(BG_CARD);
        filterPnl.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(45, 48, 58), 1, true),
                new EmptyBorder(15, 20, 15, 20)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 15);

        // Search text box
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        JTextField txtSearch = new JTextField();
        txtSearch.setPreferredSize(new Dimension(150, 32));
        txtSearch.setText("");
        // Add a prompt placeholder
        filterPnl.add(txtSearch, gbc);

        // Filter Protocol dropdown
        gbc.gridx = 1;
        gbc.weightx = 0;
        JComboBox<String> cmbProto = new JComboBox<>(new String[]{"All Protocols", "TCP", "UDP", "HTTP", "HTTPS"});
        cmbProto.setPreferredSize(new Dimension(120, 32));
        filterPnl.add(cmbProto, gbc);

        // Filter Threat Status dropdown
        gbc.gridx = 2;
        JComboBox<String> cmbStatus = new JComboBox<>(new String[]{"All Statuses", "Safe", "Suspicious"});
        cmbStatus.setPreferredSize(new Dimension(120, 32));
        filterPnl.add(cmbStatus, gbc);

        // Filter Action dropdown
        gbc.gridx = 3;
        JComboBox<String> cmbAction = new JComboBox<>(new String[]{"All Actions", "Allowed", "Blocked"});
        cmbAction.setPreferredSize(new Dimension(120, 32));
        filterPnl.add(cmbAction, gbc);

        // Query Button
        gbc.gridx = 4;
        JButton btnQuery = new JButton("Search Logs");
        btnQuery.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btnQuery.setBackground(COLOR_PRIMARY);
        btnQuery.setForeground(Color.WHITE);
        btnQuery.setPreferredSize(new Dimension(110, 32));
        filterPnl.add(btnQuery, gbc);

        // Export button
        gbc.gridx = 5;
        gbc.insets = new Insets(0, 0, 0, 0);
        JButton btnExport = new JButton("Export CSV");
        btnExport.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btnExport.setBackground(COLOR_SUCCESS);
        btnExport.setForeground(Color.WHITE);
        btnExport.setPreferredSize(new Dimension(110, 32));
        filterPnl.add(btnExport, gbc);

        panel.add(filterPnl, BorderLayout.NORTH);

        // Table
        String[] cols = {"Time", "Protocol", "Source Socket", "Destination Socket", "Status", "Action Taken", "DetailsSummary"};
        historyModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable tblHistory = new JTable(historyModel);
        tblHistory.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        tblHistory.setRowHeight(26);
        tblHistory.getTableHeader().setReorderingAllowed(false);

        tblHistory.getColumnModel().getColumn(0).setPreferredWidth(120);
        tblHistory.getColumnModel().getColumn(1).setPreferredWidth(80);
        tblHistory.getColumnModel().getColumn(2).setPreferredWidth(140);
        tblHistory.getColumnModel().getColumn(3).setPreferredWidth(140);
        tblHistory.getColumnModel().getColumn(4).setPreferredWidth(90);
        tblHistory.getColumnModel().getColumn(5).setPreferredWidth(90);
        tblHistory.getColumnModel().getColumn(6).setPreferredWidth(450);

        tblHistory.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean isSel, boolean hasFocus, int r, int c) {
                Component comp = super.getTableCellRendererComponent(tbl, val, isSel, hasFocus, r, c);
                
                String action = (String) tbl.getValueAt(r, 5);
                String status = (String) tbl.getValueAt(r, 4);

                if (isSel) {
                    comp.setBackground(new Color(50, 130, 246, 50));
                    comp.setForeground(Color.WHITE);
                } else {
                    comp.setBackground(r % 2 == 0 ? BG_CARD : new Color(38, 42, 50));
                    comp.setForeground(TEXT_LIGHT);
                }

                if (c == 5) {
                    comp.setFont(new Font("Segoe UI", Font.BOLD, 13));
                    comp.setForeground("Blocked".equalsIgnoreCase(action) ? COLOR_DANGER : COLOR_SUCCESS);
                } else if (c == 4) {
                    comp.setFont(new Font("Segoe UI", Font.BOLD, 12));
                    comp.setForeground("Suspicious".equalsIgnoreCase(status) ? COLOR_DANGER : COLOR_SUCCESS);
                }
                return comp;
            }
        });

        JScrollPane scroll = new JScrollPane(tblHistory);
        scroll.getViewport().setBackground(BG_CARD);
        scroll.setBorder(new LineBorder(new Color(40, 44, 52)));
        panel.add(scroll, BorderLayout.CENTER);

        // Load Initial logs
        loadHistoryLogs("", "All", "All", "All");

        // Action Handlers
        btnQuery.addActionListener(e -> {
            String search = txtSearch.getText();
            String proto = ((String) cmbProto.getSelectedItem()).split(" ")[0];
            String stat = ((String) cmbStatus.getSelectedItem()).split(" ")[0];
            String act = ((String) cmbAction.getSelectedItem()).split(" ")[0];
            loadHistoryLogs(search, proto, stat, act);
        });

        btnExport.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Save Logs CSV");
            chooser.setFileFilter(new FileNameExtensionFilter("CSV (*.csv)", "csv"));
            int save = chooser.showSaveDialog(this);
            if (save == JFileChooser.APPROVE_OPTION) {
                File csvFile = chooser.getSelectedFile();
                if (!csvFile.getName().toLowerCase().endsWith(".csv")) {
                    csvFile = new File(csvFile.getAbsolutePath() + ".csv");
                }
                exportLogsToCSV(csvFile);
            }
        });

        return panel;
    }

    private void loadHistoryLogs(String search, String proto, String stat, String act) {
        historyModel.setRowCount(0);
        List<PacketLog> list = DatabaseManager.getPacketLogs(search, proto, stat, act);
        for (PacketLog log : list) {
            historyModel.addRow(new Object[]{
                    log.getTimestamp(),
                    log.getProtocol(),
                    log.getSourceIP() + ":" + log.getSourcePort(),
                    log.getDestinationIP() + ":" + log.getDestPort(),
                    log.getThreatStatus(),
                    log.getActionTaken(),
                    log.getDetails()
            });
        }
    }

    private void exportLogsToCSV(File file) {
        List<PacketLog> list = DatabaseManager.getPacketLogs("", "All", "All", "All");
        try (FileWriter writer = new FileWriter(file)) {
            writer.write("PacketID,Timestamp,Protocol,SourceIP,SourcePort,DestIP,DestPort,ThreatStatus,ActionTaken,PayloadSummary,Details\n");
            for (PacketLog log : list) {
                String payloadEscaped = log.getPayload() != null ? log.getPayload().replace("\"", "\"\"").replace("\n", " ") : "";
                if (payloadEscaped.length() > 60) payloadEscaped = payloadEscaped.substring(0, 57) + "...";
                
                String detailsEscaped = log.getDetails() != null ? log.getDetails().replace("\"", "\"\"") : "";

                writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\"\n",
                        log.getId(), log.getTimestamp(), log.getProtocol(),
                        log.getSourceIP(), log.getSourcePort(), log.getDestinationIP(), log.getDestPort(),
                        log.getThreatStatus(), log.getActionTaken(), payloadEscaped, detailsEscaped
                ));
            }
            JOptionPane.showMessageDialog(this, "Logs exported successfully to: " + file.getName());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Failed to export logs: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // Capture Status Listener callback
    @Override
    public void onLiveCaptureError(String errorMsg) {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(
                    this, 
                    errorMsg + "\nAutomatically switching to Offline Simulation Mode.", 
                    "Native Driver Error", 
                    JOptionPane.WARNING_MESSAGE
            );
            
            // Switch back to simulation
            rdoSimulated.setSelected(true);
            cmbNetworkDevs.setEnabled(false);
            isSimulatedMode = true;
            
            // Stop and restart
            toggleCapture();
        });
    }

    // Threat detection listener callback (Invoked by background thread on packet capture)
    @Override
    public void onPacketProcessed(PacketLog log) {
        SwingUtilities.invokeLater(() -> {
            // 1. Update overall statistics
            countTotal++;
            packetsInLastSec++;
            
            boolean isSuspicious = "Suspicious".equalsIgnoreCase(log.getThreatStatus());
            boolean isBlocked = "Blocked".equalsIgnoreCase(log.getActionTaken());

            if (isSuspicious) {
                countThreats++;
                threatsInLastSec++;
            }
            if (isBlocked) {
                countBlocked++;
            }

            incrementProtocolCounters(log.getProtocol());
            updateStatsLabels();
            updateProtocolProgressUI();

            // 2. Add packet to table (Keep only last 300 in live visual list)
            livePacketsList.add(0, log);
            liveTableModel.insertRow(0, new Object[]{
                    log.getTimestamp().split(" ")[1], // Show only HH:mm:ss for space
                    log.getSourceIP(),
                    log.getDestinationIP(),
                    log.getProtocol(),
                    log.getSourcePort() + " > " + log.getDestPort(),
                    log.getPayload() != null ? log.getPayload().length() : 0,
                    log.getThreatStatus(),
                    log.getActionTaken()
            });

            if (liveTableModel.getRowCount() > 300) {
                liveTableModel.removeRow(liveTableModel.getRowCount() - 1);
                livePacketsList.remove(livePacketsList.size() - 1);
            }

            // Refresh selections if first item selected
            if (liveTable.getSelectedRow() == 0) {
                showPacketDetails(log);
            }

            // 3. Add to live alert drawer if blocked
            if (isBlocked) {
                addAlertDrawerCard(log);
                
                // If the dynamic blocking added something, reload Firewall blacklist table if visible
                if (isSuspicious) {
                    loadBlacklistTableData();
                }
            }
        });
    }

    private void addAlertDrawerCard(PacketLog log) {
        JPanel card = new JPanel(new BorderLayout(5, 5));
        card.setBackground(new Color(239, 68, 68, 25)); // Light neon red transparency
        card.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(COLOR_DANGER, 1, true),
                new EmptyBorder(8, 12, 8, 12)
        ));
        card.setMaximumSize(new Dimension(320, 75));
        card.setPreferredSize(new Dimension(320, 75));

        JLabel title = new JLabel("🚫 BLOCKED ACCESS EVENT");
        title.setFont(new Font("Segoe UI", Font.BOLD, 12));
        title.setForeground(COLOR_DANGER);
        card.add(title, BorderLayout.NORTH);

        JLabel desc = new JLabel("<html><b>" + log.getSourceIP() + "</b> attempted protocol <b>" + log.getProtocol() + "</b></html>");
        desc.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        desc.setForeground(TEXT_LIGHT);
        card.add(desc, BorderLayout.CENTER);

        JLabel stamp = new JLabel(log.getTimestamp().split(" ")[1] + " | Details: " + log.getProtocol() + " payload inspection");
        stamp.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        stamp.setForeground(TEXT_MUTED);
        card.add(stamp, BorderLayout.SOUTH);

        alertDrawer.add(card, 0);
        alertDrawer.add(Box.createVerticalStrut(10), 1);

        // Restrict to max 10 elements in drawer
        if (alertDrawer.getComponentCount() > 20) {
            alertDrawer.remove(alertDrawer.getComponentCount() - 1);
            alertDrawer.remove(alertDrawer.getComponentCount() - 1);
        }

        alertDrawer.revalidate();
        alertDrawer.repaint();
    }

    // Custom JPanel drawing a gorgeous neon cybersecurity throughput graph
    private class DynamicChartPanel extends JPanel {

        public DynamicChartPanel() {
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getWidth();
            int h = getHeight();
            int padding = 35;

            // Draw grid lines
            g2.setColor(new Color(40, 44, 52));
            for (int i = 0; i < 5; i++) {
                int y = padding + i * (h - 2 * padding) / 4;
                g2.drawLine(padding, y, w - padding, y);
            }

            List<Integer> stats;
            List<Integer> threats;
            synchronized (throughputHistory) {
                stats = new ArrayList<>(throughputHistory);
                threats = new ArrayList<>(threatHistory);
            }

            int n = stats.size();
            if (n < 2) {
                g2.dispose();
                return;
            }

            // Find max for scaling
            int maxVal = 5; // Minimum scale height
            for (int val : stats) {
                if (val > maxVal) maxVal = val;
            }
            // Add margin to scale
            maxVal = (int) (maxVal * 1.2);

            // X and Y coords
            int[] xPoints = new int[n];
            int[] yPoints = new int[n];
            
            int[] xThreats = new int[n];
            int[] yThreats = new int[n];

            for (int i = 0; i < n; i++) {
                xPoints[i] = padding + i * (w - 2 * padding) / (n - 1);
                yPoints[i] = h - padding - (stats.get(i) * (h - 2 * padding)) / maxVal;
                
                xThreats[i] = padding + i * (w - 2 * padding) / (n - 1);
                yThreats[i] = h - padding - (threats.get(i) * (h - 2 * padding)) / maxVal;
            }

            // Draw area under throughput line (gradient)
            Polygon area = new Polygon();
            area.addPoint(xPoints[0], h - padding);
            for (int i = 0; i < n; i++) {
                area.addPoint(xPoints[i], yPoints[i]);
            }
            area.addPoint(xPoints[n - 1], h - padding);

            GradientPaint gradient = new GradientPaint(
                    0, 0, new Color(50, 130, 246, 60), 
                    0, h, new Color(50, 130, 246, 0)
            );
            g2.setPaint(gradient);
            g2.fill(area);

            // Draw Throughput Line
            g2.setStroke(new BasicStroke(3f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(COLOR_PRIMARY);
            for (int i = 0; i < n - 1; i++) {
                g2.drawLine(xPoints[i], yPoints[i], xPoints[i+1], yPoints[i+1]);
            }

            // Draw Area under Threat Line
            Polygon threatArea = new Polygon();
            threatArea.addPoint(xThreats[0], h - padding);
            for (int i = 0; i < n; i++) {
                threatArea.addPoint(xThreats[i], yThreats[i]);
            }
            threatArea.addPoint(xThreats[n - 1], h - padding);
            GradientPaint redGradient = new GradientPaint(
                    0, 0, new Color(239, 68, 68, 50),
                    0, h, new Color(239, 68, 68, 0)
            );
            g2.setPaint(redGradient);
            g2.fill(threatArea);

            // Draw Threat Line
            g2.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(COLOR_DANGER);
            for (int i = 0; i < n - 1; i++) {
                g2.drawLine(xThreats[i], yThreats[i], xThreats[i+1], yThreats[i+1]);
            }

            // Draw axes
            g2.setStroke(new BasicStroke(1.5f));
            g2.setColor(TEXT_MUTED);
            g2.drawLine(padding, h - padding, w - padding, h - padding); // X Axis
            g2.drawLine(padding, padding, padding, h - padding);         // Y Axis

            // Draw text labels
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 10));
            g2.drawString("Max: " + maxVal + " pps", 5, padding + 5);
            g2.drawString("0 pps", 5, h - padding + 5);
            g2.drawString("Now", w - padding - 15, h - padding + 15);
            g2.drawString("-30s", padding, h - padding + 15);

            g2.dispose();
        }
    }
}

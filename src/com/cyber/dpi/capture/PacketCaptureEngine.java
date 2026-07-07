package com.cyber.dpi.capture;

import com.cyber.dpi.detector.ThreatDetectionEngine;
import com.cyber.dpi.model.PacketLog;

import java.util.ArrayList;
import java.util.List;

// Import Pcap4J optionally via reflection or direct references
// We use a robust direct reference. If native DLLs are missing, classloading of Pcaps will throw UnsatisfiedLinkError.
// We catch this at runtime during device lister initialization.
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketCaptureEngine implements Runnable {
    private volatile boolean running = false;
    private Thread thread = null;
    private String selectedDeviceName = null;
    private final String modeChangeCallback = null;
    private CaptureStatusListener statusListener = null;

    public interface CaptureStatusListener {
        void onLiveCaptureError(String errorMsg);
    }

    public void setStatusListener(CaptureStatusListener listener) {
        this.statusListener = listener;
    }

    /**
     * Attempts to retrieve all network interfaces on the host machine.
     * If Npcap/WinPcap is missing, it will throw UnsatisfiedLinkError, which we catch.
     */
    public static List<String> getNetworkInterfaces() {
        List<String> list = new ArrayList<>();
        try {
            // Attempt to load devices
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            for (PcapNetworkInterface dev : devices) {
                String desc = dev.getDescription() != null ? dev.getDescription() : dev.getName();
                list.add(dev.getName() + " (" + desc + ")");
            }
        } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
            System.err.println("Npcap/WinPcap not detected! Live capture is disabled.");
        } catch (Exception e) {
            System.err.println("Failed to search network interfaces: " + e.getMessage());
        }
        return list;
    }

    public synchronized void start(String deviceName) {
        if (!running) {
            this.selectedDeviceName = deviceName;
            this.running = true;
            this.thread = new Thread(this, "LivePacketCaptureThread");
            this.thread.start();
        }
    }

    public synchronized void stop() {
        if (running) {
            this.running = false;
            if (thread != null) {
                thread.interrupt();
            }
            System.out.println("Live Packet Capture stopped.");
        }
    }

    public boolean isRunning() {
        return running;
    }

    @Override
    public void run() {
        PcapHandle handle = null;
        try {
            System.out.println("Starting live capture on device: " + selectedDeviceName);
            PcapNetworkInterface nif = Pcaps.getDevByName(selectedDeviceName);
            if (nif == null) {
                throw new Exception("Device not found: " + selectedDeviceName);
            }

            // Open live capture
            // Snaplen: 65536, Promiscuous Mode: True, Timeout: 10ms
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            
            System.out.println("Live handle opened. Scanning packets...");
            while (running && !Thread.currentThread().isInterrupted()) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    PacketLog log = parsePcapPacket(packet);
                    if (log != null) {
                        ThreatDetectionEngine.processPacket(log);
                    }
                }
            }
        } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
            String errorMsg = "WinPcap/Npcap driver is missing. Cannot start live capture.";
            System.err.println(errorMsg);
            if (statusListener != null) {
                statusListener.onLiveCaptureError(errorMsg);
            }
        } catch (Exception e) {
            String errorMsg = "Capture Error: " + e.getMessage();
            System.err.println(errorMsg);
            if (statusListener != null) {
                statusListener.onLiveCaptureError(errorMsg);
            }
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            running = false;
        }
    }

    /**
     * Parses a Pcap4J Packet object and extracts IP, port, protocol, and payload details.
     */
    private PacketLog parsePcapPacket(Packet packet) {
        try {
            String srcIp = "0.0.0.0";
            String destIp = "0.0.0.0";
            int srcPort = 0;
            int destPort = 0;
            String protocol = "RAW";
            String payloadStr = "";

            // Check if IPv4 Packet
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
                destIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();

                // Check TCP
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                    destPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                    protocol = "TCP";

                    byte[] rawData = tcpPacket.getPayload() != null ? tcpPacket.getPayload().getRawData() : null;
                    if (rawData != null && rawData.length > 0) {
                        payloadStr = new String(rawData);
                    }
                    
                    if (destPort == 80 || srcPort == 80 || payloadStr.contains("HTTP/1.") || payloadStr.contains("GET ") || payloadStr.contains("POST ")) {
                        protocol = "HTTP";
                    } else if (destPort == 443 || srcPort == 443) {
                        protocol = "HTTPS";
                    } else if (destPort == 53 || srcPort == 53) {
                        protocol = "DNS";
                    }
                } 
                // Check UDP
                else if (packet.contains(UdpPacket.class)) {
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                    destPort = udpPacket.getHeader().getDstPort().valueAsInt();
                    protocol = "UDP";

                    byte[] rawData = udpPacket.getPayload() != null ? udpPacket.getPayload().getRawData() : null;
                    if (rawData != null && rawData.length > 0) {
                        payloadStr = new String(rawData);
                    }
                    
                    if (destPort == 53 || srcPort == 53) {
                        protocol = "DNS";
                    } else if (destPort == 443 || srcPort == 443) {
                        protocol = "HTTPS"; 
                    }
                }
            }

            PacketLog log = new PacketLog(srcIp, destIp, srcPort, destPort, protocol, payloadStr);
            
            // Extract and attach domain name directly from raw byte payloads
            byte[] rawBytes = null;
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcp = packet.get(TcpPacket.class);
                rawBytes = tcp.getPayload() != null ? tcp.getPayload().getRawData() : null;
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udp = packet.get(UdpPacket.class);
                rawBytes = udp.getPayload() != null ? udp.getPayload().getRawData() : null;
            }
            if (rawBytes != null && rawBytes.length > 0) {
                if ("DNS".equalsIgnoreCase(protocol)) {
                    com.cyber.dpi.analyzer.ProtocolAnalyzer.parseDnsResponseAndMapIps(rawBytes);
                }
                String domain = com.cyber.dpi.analyzer.ProtocolAnalyzer.extractDomainFromBytes(protocol, rawBytes);
                if (domain != null) {
                    log.setDomain(domain);
                }
            }
            return log;

        } catch (Exception e) {
            System.err.println("Error parsing raw packet: " + e.getMessage());
            return null;
        }
    }
}

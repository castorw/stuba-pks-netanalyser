package net.ctrdn.stuba.pks.netanalyser.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpHardwareType;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpOperation;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpProtocolType;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrameType;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameProtocol;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFlag;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;
import org.krakenapps.pcap.util.Buffer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class DataTypeHelpers {
    
    private static Document icmpParamsDocument;
    private static XPath icmpParamsXpath;
    private static Map<Integer, String> udpServiceMap;
    private static Map<Integer, String> tcpServiceMap;
    
    public final static void initialize() {
        try {
            DataTypeHelpers.icmpParamsDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(DataTypeHelpers.class.getResourceAsStream("/net/ctrdn/stuba/pks/netanalyser/resource/iana-icmp-parameters.xml"));
            DataTypeHelpers.icmpParamsXpath = XPathFactory.newInstance().newXPath();
            InputStream servicesInputStream = DataTypeHelpers.class.getResourceAsStream("/net/ctrdn/stuba/pks/netanalyser/resource/services.dat");
            BufferedReader servicesReader = new BufferedReader(new InputStreamReader(servicesInputStream));
            DataTypeHelpers.udpServiceMap = new HashMap<>();
            DataTypeHelpers.tcpServiceMap = new HashMap<>();
            String serviceLine;
            while ((serviceLine = servicesReader.readLine()) != null) {
                serviceLine = serviceLine.replaceAll("\t", " ").replaceAll("  ", " ");
                if (serviceLine.startsWith("#") || serviceLine.trim().equals("")) {
                    continue;
                }
                String[] serviceDataArray = serviceLine.split(" ");
                String[] portProtoArray = serviceDataArray[1].split("/");
                if (portProtoArray[1].toLowerCase().equals("udp")) {
                    DataTypeHelpers.udpServiceMap.put(Integer.parseInt(portProtoArray[0]), serviceDataArray[0]);
                } else if (portProtoArray[1].toLowerCase().equals("tcp")) {
                    DataTypeHelpers.tcpServiceMap.put(Integer.parseInt(portProtoArray[0]), serviceDataArray[0]);
                }
            }
        } catch (IOException | ParserConfigurationException | SAXException ex) {
            ex.printStackTrace();
        }
    }
    
    public static String getReadableByteSize(long size) {
        if (size <= 0) {
            return "0";
        }
        final String[] units = new String[]{"B", "KB", "MB", "GB", "TB", "PB", "EB"};
        int digitGroups = (int) (Math.log10(size) / Math.log10(1024));
        return new DecimalFormat("#,##0.#").format(size / Math.pow(1024, digitGroups)) + " " + units[digitGroups];
    }
    
    public final static short getUnsignedByteValue(byte b) {
        if (b < 0) {
            return (short) (b & 0xff);
        } else {
            return b;
        }
    }
    
    public final static int getUnsignedShortValue(short s) {
        if (s < 0) {
            return (s & 0xffff);
        } else {
            return s;
        }
    }
    
    public final static int getUnsignedShortFromBytes(byte msb, byte lsb) {
        short targetShort = DataTypeHelpers.getUnsignedByteValue(lsb);
        targetShort |= (msb << 8);
        return DataTypeHelpers.getUnsignedShortValue(targetShort);
    }
    
    public final static String getMacAddressString(byte[] macAddress) throws DataTypeException {
        if (macAddress.length != 6) {
            throw new DataTypeException("Invalid MAC address byte array length (" + macAddress.length + ")");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(":");
            }
            String part = Integer.toString(DataTypeHelpers.getUnsignedByteValue(macAddress[i]), 16);
            sb.append((part.length() < 2) ? "0" + part : part);
        }
        return sb.toString().toUpperCase();
    }
    
    public final static String getIPv4AddressString(byte[] ipv4Address) throws DataTypeException {
        if (ipv4Address.length != 4) {
            throw new DataTypeException("Invalid IPv4 address byte array length (" + ipv4Address.length + ")");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            if (i > 0) {
                sb.append(".");
            }
            String part = Integer.toString(DataTypeHelpers.getUnsignedByteValue(ipv4Address[i]), 10);
            sb.append(part);
        }
        return sb.toString().toUpperCase();
    }
    
    public final static String getFrameTypeString(EthernetFrameType frameType) {
        switch (frameType) {
            case ETHERNET2: {
                return "IEEE 802.3 Ethernet II";
            }
            case ETHERNET_LLC: {
                return "IEEE 802.3 Ethernet LLC";
            }
            case ETHERNET_RAW: {
                return "Novell IEEE 802.3 Ethernet RAW";
            }
            case ETHERNET_SNAP: {
                return "IEEE 802.3 Ethernet SNAP";
            }
            default: {
                return "n/a";
            }
        }
    }
    
    public final static String getArpHardwareTypeString(ArpHardwareType type) {
        switch (type) {
            case ETHERNET: {
                return "Ethernet";
            }
            default: {
                return "n/a";
            }
        }
    }
    
    public final static String getArpProtocolTypeString(ArpProtocolType type) {
        switch (type) {
            case INTERNET_PROTOCOL_V4: {
                return "IPv4";
            }
            default: {
                return "n/a";
            }
        }
    }
    
    public final static String getArpOperationString(ArpOperation operation) {
        switch (operation) {
            case ARP_REQUEST: {
                return "ARP Request";
            }
            case ARP_REPLY: {
                return "ARP Reply";
            }
            default: {
                return "n/a";
            }
        }
    }
    
    public final static String getTcpFlagsString(TcpFrame frame) {
        StringBuilder sb = new StringBuilder();
        boolean added = false;
        for (TcpFlag flag : TcpFlag.values()) {
            if (frame.hasTcpFlag(flag)) {
                if (added) {
                    sb.append(", ");
                }
                sb.append(flag.toString());
                added = true;
            }
        }
        return sb.toString();
    }
    
    public final static String getFrameDataFormatted(Buffer buffer, int bytesPerLine) {
        StringBuilder sb = new StringBuilder();
        int inLine = 0;
        while (!buffer.isEOB()) {
            if (inLine > 0) {
                sb.append(" ");
            }
            String part = Integer.toString(DataTypeHelpers.getUnsignedByteValue(buffer.get()), 16);
            sb.append((part.length() < 2) ? "0" + part : part);
            inLine++;
            if (inLine >= bytesPerLine) {
                sb.append("\n");
                inLine = 0;
            }
        }
        return sb.toString().toUpperCase();
    }
    
    public final static String getIcmpTypeString(short icmpTypeNumber) throws DataTypeException {
        try {
            Element descriptionElement = (Element) DataTypeHelpers.icmpParamsXpath.evaluate("/registry/registry[@id='icmp-parameters-types']/record[value='" + icmpTypeNumber + "']/description", DataTypeHelpers.icmpParamsDocument, XPathConstants.NODE);
            return descriptionElement.getTextContent();
        } catch (XPathExpressionException ex) {
            ex.printStackTrace();
            DataTypeException finalEx = new DataTypeException("Failed to resolve ICMP parameters");
            finalEx.addSuppressed(ex);
            throw finalEx;
        }
    }
    
    public final static String getIcmpCodeString(short icmpTypeNumber, short icmpCodeNumber) throws DataTypeException {
        try {
            Element descriptionElement = (Element) DataTypeHelpers.icmpParamsXpath.evaluate("/registry/registry[@id='icmp-parameters-codes']/registry[@id='icmp-parameters-codes-" + icmpTypeNumber + "']/record[value='" + icmpCodeNumber + "']/description", DataTypeHelpers.icmpParamsDocument, XPathConstants.NODE);
            return descriptionElement.getTextContent();
        } catch (XPathExpressionException ex) {
            ex.printStackTrace();
            DataTypeException finalEx = new DataTypeException("Failed to resolve ICMP parameters");
            finalEx.addSuppressed(ex);
            throw finalEx;
        }
    }
    
    public final static String getPortServiceString(IPv4FrameProtocol protocol, int port) throws DataTypeException {
        switch (protocol) {
            case TCP: {
                if (DataTypeHelpers.tcpServiceMap.containsKey(port)) {
                    return port + " (" + DataTypeHelpers.tcpServiceMap.get(port) + ")";
                } else {
                    return port + " (n/a)";
                }
            }
            case UDP: {
                if (DataTypeHelpers.udpServiceMap.containsKey(port)) {
                    return port + " (" + DataTypeHelpers.udpServiceMap.get(port) + ")";
                } else {
                    return port + " (n/a)";
                }
            }
            default: {
                throw new DataTypeException("Unsupported protocol " + protocol.toString());
            }
        }
    }
}

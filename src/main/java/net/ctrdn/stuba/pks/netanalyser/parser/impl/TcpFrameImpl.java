package net.ctrdn.stuba.pks.netanalyser.parser.impl;

import net.ctrdn.stuba.pks.netanalyser.annotation.FrameParser;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.exception.UnsupportedSourceFrameTypeException;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrameType;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Address;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Frame;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameFlags;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameProtocol;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFlag;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;
import org.krakenapps.pcap.util.Buffer;

@FrameParser(
        name = "TCP Packet Parser",
        version = "1.0.0",
        layer = 4,
        orderKey = 5
)
public class TcpFrameImpl implements TcpFrame {

    private final IPv4Frame ethernetFrame;
    private final int tcpSourcePort;
    private final int tcpDestinationPort;
    private final byte[] tcpSequenceNumber;
    private final byte[] tcpAcknowledgmentNumber;
    private final short tcpDataOffset;
    private final short flagShort;
    private final int tcpWindowSize;
    private final int tcpChecksum;
    private final int tcpUrgentPointer;

    public TcpFrameImpl(EthernetFrame ethernetFrame) throws UnsupportedSourceFrameTypeException {
        if (!IPv4Frame.class.isAssignableFrom(ethernetFrame.getClass())) {
            throw new UnsupportedSourceFrameTypeException("Only IPv4 source frames are allowed");
        }
        this.ethernetFrame = (IPv4Frame) ethernetFrame;
        if (this.ethernetFrame.getIpProtocol() != IPv4FrameProtocol.TCP) {
            throw new UnsupportedSourceFrameTypeException("Unsupported IP protocol " + this.ethernetFrame.getIpProtocolNumber());
        }
        Buffer dataBuffer = ethernetFrame.getDataBuffer();
        this.tcpSourcePort = DataTypeHelpers.getUnsignedShortFromBytes(dataBuffer.get(), dataBuffer.get());
        this.tcpDestinationPort = DataTypeHelpers.getUnsignedShortFromBytes(dataBuffer.get(), dataBuffer.get());
        this.tcpSequenceNumber = new byte[4];
        this.tcpAcknowledgmentNumber = new byte[4];
        for (int i = 0; i < 4; i++) {
            this.tcpSequenceNumber[i] = dataBuffer.get();
        }
        for (int i = 0; i < 4; i++) {
            this.tcpAcknowledgmentNumber[i] = dataBuffer.get();
        }
        byte dataOffsetByte = dataBuffer.get();
        byte flagsByte = dataBuffer.get();
        short fs;
        this.tcpDataOffset = DataTypeHelpers.getUnsignedByteValue((byte) (dataOffsetByte >> 4));
        dataOffsetByte = (byte) (dataOffsetByte & 0x01);
        fs = flagsByte;
        fs |= (dataOffsetByte << 8);
        this.flagShort = fs;
        this.tcpWindowSize = DataTypeHelpers.getUnsignedShortFromBytes(dataBuffer.get(), dataBuffer.get());
        this.tcpChecksum = DataTypeHelpers.getUnsignedShortFromBytes(dataBuffer.get(), dataBuffer.get());
        this.tcpUrgentPointer = DataTypeHelpers.getUnsignedShortFromBytes(dataBuffer.get(), dataBuffer.get());
        if (this.tcpDataOffset > 5) {
            dataBuffer.skip((this.tcpDataOffset - 5) * 4);
        }
    }

    @Override
    public int getTcpSourcePort() {
        return tcpSourcePort;
    }

    @Override
    public int getTcpDestinationPort() {
        return tcpDestinationPort;
    }

    @Override
    public byte[] getTcpSequenceNumber() {
        return tcpSequenceNumber;
    }

    @Override
    public byte[] getTcpAcknowledgmentNumber() {
        return tcpAcknowledgmentNumber;
    }

    @Override
    public short getTcpDataOffset() {
        return this.tcpDataOffset;
    }

    @Override
    public boolean hasTcpFlag(TcpFlag flag) {
        switch (flag) {
            case NS: {
                return (this.flagShort & 0x100) > 0;
            }
            case CWR: {
                return (this.flagShort & 0x80) > 0;
            }
            case ECE: {
                return (this.flagShort & 0x40) > 0;
            }
            case URG: {
                return (this.flagShort & 0x20) > 0;
            }
            case ACK: {
                return (this.flagShort & 0x10) > 0;
            }
            case PSH: {
                return (this.flagShort & 0x8) > 0;
            }
            case RST: {
                return (this.flagShort & 0x4) > 0;
            }
            case SYN: {
                return (this.flagShort & 0x2) > 0;
            }
            case FIN: {
                return (this.flagShort & 0x1) > 0;
            }
        }
        return false;
    }

    @Override
    public int getTcpWindowSize() {
        return tcpWindowSize;
    }

    @Override
    public int getTcpChecksum() {
        return tcpChecksum;
    }

    @Override
    public int getTcpUrgentPointer() {
        return tcpUrgentPointer;
    }

    @Override
    public short getIpVersion() {
        return this.ethernetFrame.getIpVersion();
    }

    @Override
    public short getIpInternetHeaderLength() {
        return this.ethernetFrame.getIpInternetHeaderLength();
    }

    @Override
    public int getIpTotalLength() {
        return this.ethernetFrame.getIpTotalLength();
    }

    @Override
    public int getIpIdentification() {
        return this.ethernetFrame.getIpIdentification();
    }

    @Override
    public boolean hasIpFlag(IPv4FrameFlags frameFlag) {
        return this.ethernetFrame.hasIpFlag(frameFlag);
    }

    @Override
    public int getIpFragmentOffset() {
        return this.ethernetFrame.getIpFragmentOffset();
    }

    @Override
    public int getIpTimeToLive() {
        return this.ethernetFrame.getIpTimeToLive();
    }

    @Override
    public int getIpProtocolNumber() {
        return this.ethernetFrame.getIpProtocolNumber();
    }

    @Override
    public IPv4FrameProtocol getIpProtocol() {
        return this.ethernetFrame.getIpProtocol();
    }

    @Override
    public int getIpHeaderChecksum() {
        return this.ethernetFrame.getIpHeaderChecksum();
    }

    @Override
    public IPv4Address getIpSourceAddress() {
        return this.ethernetFrame.getIpSourceAddress();
    }

    @Override
    public IPv4Address getIpDestinationAddress() {
        return this.ethernetFrame.getIpDestinationAddress();
    }

    @Override
    public int getCaptureId() {
        return this.ethernetFrame.getCaptureId();
    }

    @Override
    public int getCaptureTimeOffset() {
        return this.ethernetFrame.getCaptureTimeOffset();
    }

    @Override
    public int getCaptureOriginalLength() {
        return this.ethernetFrame.getCaptureOriginalLength();
    }

    @Override
    public int getCaptureWireLength() {
        return this.ethernetFrame.getCaptureWireLength();
    }

    @Override
    public byte[] getEthernetSourceMacAddress() {
        return this.ethernetFrame.getEthernetSourceMacAddress();
    }

    @Override
    public byte[] getEthernetDestinationMacAddress() {
        return this.ethernetFrame.getEthernetDestinationMacAddress();
    }

    @Override
    public String getEthernetSourceMacAddressString() throws DataTypeException {
        return this.ethernetFrame.getEthernetSourceMacAddressString();
    }

    @Override
    public String getEthernetDestinationMacAddressString() throws DataTypeException {
        return this.ethernetFrame.getEthernetDestinationMacAddressString();
    }

    @Override
    public byte[] getEthernetEthertypeBytes() {
        return this.ethernetFrame.getEthernetEthertypeBytes();
    }

    @Override
    public EthernetFrameType getEthernetFrameType() {
        return this.ethernetFrame.getEthernetFrameType();
    }

    @Override
    public Buffer getDataBuffer() {
        return this.ethernetFrame.getDataBuffer();
    }
}

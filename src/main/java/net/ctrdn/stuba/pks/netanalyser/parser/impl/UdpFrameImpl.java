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
import net.ctrdn.stuba.pks.netanalyser.parser.UdpFrame;
import org.krakenapps.pcap.util.Buffer;

@FrameParser(
        name = "UDP Packet Parser",
        version = "1.0.1",
        layer = 4,
        orderKey = 20
)
public class UdpFrameImpl implements UdpFrame {

    private final IPv4Frame ethernetFrame;
    private final int udpSourcePort;
    private final int udpDestinationPort;
    private final int udpLength;
    private final int udpChecksum;

    public UdpFrameImpl(EthernetFrame ethernetFrame) throws UnsupportedSourceFrameTypeException {
        if (!IPv4Frame.class.isAssignableFrom(ethernetFrame.getClass())) {
            throw new UnsupportedSourceFrameTypeException("Only IPv4 source frames are allowed");
        }
        this.ethernetFrame = (IPv4Frame) ethernetFrame;
        if (this.ethernetFrame.getIpProtocol() != IPv4FrameProtocol.UDP) {
            throw new UnsupportedSourceFrameTypeException("Unsupported IP protocol " + this.ethernetFrame.getIpProtocolNumber());
        }
        this.udpSourcePort = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        this.udpDestinationPort = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        this.udpLength = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        this.udpChecksum = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
    }

    @Override
    public int getUdpSourcePort() {
        return udpSourcePort;
    }

    @Override
    public int getUdpDestinationPort() {
        return udpDestinationPort;
    }

    @Override
    public int getUdpLength() {
        return udpLength;
    }

    @Override
    public int getUdpChecksum() {
        return udpChecksum;
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

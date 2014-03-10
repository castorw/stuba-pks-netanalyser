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
import net.ctrdn.stuba.pks.netanalyser.parser.IcmpFrame;
import org.krakenapps.pcap.util.Buffer;

@FrameParser(
        name = "ICMP Packet Parser",
        version = "1.0.0",
        layer = 4,
        orderKey = 10
)
public class IcmpFrameImpl implements IcmpFrame {

    private final IPv4Frame ethernetFrame;
    private final short icmpTypeNumber;
    private final short icmpCodeNumber;
    private final int icmpChecksum;
    private final byte[] icmpRestHeader;

    public IcmpFrameImpl(EthernetFrame ethernetFrame) throws UnsupportedSourceFrameTypeException {
        if (!IPv4Frame.class.isAssignableFrom(ethernetFrame.getClass())) {
            throw new UnsupportedSourceFrameTypeException("Only IPv4 source frames are allowed");
        }
        this.ethernetFrame = (IPv4Frame) ethernetFrame;
        if (this.ethernetFrame.getIpProtocol() != IPv4FrameProtocol.ICMP) {
            throw new UnsupportedSourceFrameTypeException("Unsupported IP protocol " + this.ethernetFrame.getIpProtocolNumber());
        }
        this.icmpTypeNumber = DataTypeHelpers.getUnsignedByteValue(ethernetFrame.getDataBuffer().get());
        this.icmpCodeNumber = DataTypeHelpers.getUnsignedByteValue(ethernetFrame.getDataBuffer().get());
        this.icmpChecksum = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        this.icmpRestHeader = new byte[4];
        for (int i = 0; i < 4; i++) {
            this.icmpRestHeader[i] = ethernetFrame.getDataBuffer().get();
        }
    }

    @Override
    public short getIcmpTypeNumber() {
        return icmpTypeNumber;
    }

    @Override
    public short getIcmpCodeNumber() {
        return icmpCodeNumber;
    }

    @Override
    public String getIcmpTypeString() throws DataTypeException {
        return DataTypeHelpers.getIcmpTypeString(this.icmpTypeNumber);
    }

    @Override
    public String getIcmpCodeString() throws DataTypeException {
        return DataTypeHelpers.getIcmpCodeString(this.icmpTypeNumber, this.icmpCodeNumber);
    }

    @Override
    public int getIcmpChecksum() {
        return icmpChecksum;
    }

    @Override
    public byte[] getIcmpRestHeader() {
        return icmpRestHeader;
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

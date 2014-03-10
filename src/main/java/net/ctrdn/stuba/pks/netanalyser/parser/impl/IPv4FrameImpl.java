package net.ctrdn.stuba.pks.netanalyser.parser.impl;

import net.ctrdn.stuba.pks.netanalyser.annotation.FrameParser;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrameType;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Address;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Frame;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameFlags;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameProtocol;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.exception.FrameAnalysisException;
import net.ctrdn.stuba.pks.netanalyser.exception.UnsupportedSourceFrameTypeException;
import org.krakenapps.pcap.util.Buffer;

@FrameParser(
        name = "IPv4 Packet Parser",
        version = "1.0.2",
        layer = 3,
        orderKey = 10
)
public class IPv4FrameImpl implements IPv4Frame {

    private final EthernetFrame ethernetFrame;
    private final short ipVersion;
    private final short ipInternetHeaderLength;
    private final int ipTotalLength;
    private final int ipIdentification;
    private final byte ipFlags;
    private final int ipFragmentOffset;
    private final int ipTimeToLive;
    private final int ipProtocolNumber;
    private final IPv4FrameProtocol ipProtocol;
    private final int ipHeaderChecksum;
    private final IPv4Address ipSourceAddress;
    private final IPv4Address ipDestinationAddress;

    public IPv4FrameImpl(EthernetFrame ethernetFrame) throws UnsupportedSourceFrameTypeException, FrameAnalysisException {
        this.ethernetFrame = ethernetFrame;
        if (ethernetFrame.getEthernetFrameType() != EthernetFrameType.ETHERNET2) {
            throw new UnsupportedSourceFrameTypeException("Only Ethernet II packets are supported");
        }
        if (ethernetFrame.getEthernetEthertypeBytes()[0] != 0x08 || ethernetFrame.getEthernetEthertypeBytes()[1] != 0x00) {
            throw new UnsupportedSourceFrameTypeException("Unsupported ethertype " + ethernetFrame.getEthernetEthertypeBytes());
        }
        byte versionIhlByte = ethernetFrame.getDataBuffer().get();
        this.ipVersion = (short) (versionIhlByte >> 4);
        this.ipInternetHeaderLength = (short) (versionIhlByte & 0x0F);
        ethernetFrame.getDataBuffer().get(); // igonre DSCP and ECN
        this.ipTotalLength = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        this.ipIdentification = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        byte fragementationFirstByte = ethernetFrame.getDataBuffer().get();
        this.ipFlags = (byte) (fragementationFirstByte >> 5);
        this.ipFragmentOffset = DataTypeHelpers.getUnsignedShortFromBytes((byte) (fragementationFirstByte & 0x1f), ethernetFrame.getDataBuffer().get());
        this.ipTimeToLive = DataTypeHelpers.getUnsignedByteValue(ethernetFrame.getDataBuffer().get());
        this.ipProtocolNumber = DataTypeHelpers.getUnsignedByteValue(ethernetFrame.getDataBuffer().get());
        this.ipHeaderChecksum = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        this.ipSourceAddress = new IPv4AddressImpl(new byte[]{ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get()});
        this.ipDestinationAddress = new IPv4AddressImpl(new byte[]{ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get()});
        switch (this.ipProtocolNumber) {
            case 17: {
                this.ipProtocol = IPv4FrameProtocol.UDP;
                break;
            }
            case 6: {
                this.ipProtocol = IPv4FrameProtocol.TCP;
                break;
            }
            case 1: {
                this.ipProtocol = IPv4FrameProtocol.ICMP;
                break;
            }
            case 2: {
                this.ipProtocol = IPv4FrameProtocol.IGMP;
                break;
            }
            default: {
                this.ipProtocol = IPv4FrameProtocol.PARSER_UNSUPPORTED;
                break;
            }
        }
        if (this.ipInternetHeaderLength > 5) {
            this.ethernetFrame.getDataBuffer().skip((this.getIpInternetHeaderLength() - 5) * 4);
        }
    }

    @Override
    public short getIpVersion() {
        return this.ipVersion;
    }

    @Override
    public short getIpInternetHeaderLength() {
        return this.ipInternetHeaderLength;
    }

    @Override
    public int getIpTotalLength() {
        return this.ipTotalLength;
    }

    @Override
    public int getIpIdentification() {
        return this.ipIdentification;
    }

    @Override
    public boolean hasIpFlag(IPv4FrameFlags frameFlag) {
        if (frameFlag == IPv4FrameFlags.DONT_FRAGMENT && (this.ipFlags & 2) > 0) {
            return true;
        } else if (frameFlag == IPv4FrameFlags.MORE_FRAGMENTS && (this.ipFlags & 4) > 0) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int getIpFragmentOffset() {
        return this.ipFragmentOffset;
    }

    @Override
    public int getIpTimeToLive() {
        return this.ipTimeToLive;
    }

    @Override
    public int getIpProtocolNumber() {
        return this.ipProtocolNumber;
    }

    @Override
    public IPv4FrameProtocol getIpProtocol() {
        return this.ipProtocol;
    }

    @Override
    public int getIpHeaderChecksum() {
        return this.ipHeaderChecksum;
    }

    @Override
    public IPv4Address getIpSourceAddress() {
        return this.ipSourceAddress;
    }

    @Override
    public IPv4Address getIpDestinationAddress() {
        return this.ipDestinationAddress;
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

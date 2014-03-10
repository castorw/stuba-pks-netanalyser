package net.ctrdn.stuba.pks.netanalyser.parser.impl;

import net.ctrdn.stuba.pks.netanalyser.annotation.FrameParser;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrameType;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.exception.FrameAnalysisException;
import org.krakenapps.pcap.packet.PcapPacket;
import org.krakenapps.pcap.util.Buffer;

@FrameParser(
        name = "Ethernet Frame Parser",
        version = "1.0.0",
        layer = 2,
        orderKey = 10
)
public class EthernetFrameImpl implements EthernetFrame {

    private final int frameId;
    private final byte[] sourceMacAddress;
    private final byte[] destinationMacAddress;
    private final byte[] etherTypeBytes;
    private final EthernetFrameType frameType;
    private final int originalLength;
    private final int wireLength;
    private final int captureTimeOffset;
    private final Buffer dataBuffer;

    public EthernetFrameImpl(Integer frameId, PcapPacket packet) throws FrameAnalysisException {
        this.frameId = frameId;
        this.captureTimeOffset = packet.getPacketHeader().getTsUsec();
        this.originalLength = packet.getPacketHeader().getOrigLen();
        this.wireLength = packet.getPacketHeader().getInclLen();
        this.dataBuffer = packet.getPacketData();
        this.sourceMacAddress = new byte[6];
        this.destinationMacAddress = new byte[6];
        for (int i = 0; i < 6; i++) {
            this.destinationMacAddress[i] = this.dataBuffer.get();
        }
        for (int i = 0; i < 6; i++) {
            this.sourceMacAddress[i] = this.dataBuffer.get();
        }
        this.etherTypeBytes = new byte[2];
        this.etherTypeBytes[0] = this.dataBuffer.get();
        this.etherTypeBytes[1] = this.dataBuffer.get();
        short dataBufferShort = this.etherTypeBytes[1];
        dataBufferShort |= this.etherTypeBytes[0] << 8;
        int dataBufferInt = (dataBufferShort < 0) ? dataBufferShort & 0xffff : dataBufferShort;
        EthernetFrameType newFrameType = null;
        if (dataBufferInt >= 1536) {
            newFrameType = EthernetFrameType.ETHERNET2;
        } else if (dataBufferInt <= 1500) {
            byte[] firstTwoBytes = new byte[2];
            firstTwoBytes[0] = this.dataBuffer.get();
            firstTwoBytes[1] = this.dataBuffer.get();
            this.dataBuffer.skip(-2);
            if (firstTwoBytes[0] == 0xff && firstTwoBytes[1] == 0xff) {
                newFrameType = EthernetFrameType.ETHERNET_RAW;
            } else if (firstTwoBytes[0] == 0xaa && firstTwoBytes[1] == 0xaa) {
                newFrameType = EthernetFrameType.ETHERNET_SNAP;
            } else {
                newFrameType = EthernetFrameType.ETHERNET_LLC;
            }
        }
        this.frameType = newFrameType;
        if (this.frameType == null) {
            throw new FrameAnalysisException("Failed to determine frame type (0x" + Integer.toString(DataTypeHelpers.getUnsignedByteValue(this.etherTypeBytes[0]), 16) + Integer.toString(DataTypeHelpers.getUnsignedByteValue(this.etherTypeBytes[1]), 16) + ")");
        }
    }

    @Override
    public int getCaptureId() {
        return frameId;
    }

    @Override
    public byte[] getEthernetSourceMacAddress() {
        return sourceMacAddress;
    }

    @Override
    public byte[] getEthernetDestinationMacAddress() {
        return destinationMacAddress;
    }

    @Override
    public byte[] getEthernetEthertypeBytes() {
        return this.etherTypeBytes;
    }

    @Override
    public EthernetFrameType getEthernetFrameType() {
        return frameType;
    }

    @Override
    public int getCaptureOriginalLength() {
        return originalLength;
    }

    @Override
    public int getCaptureWireLength() {
        return wireLength;
    }

    @Override
    public int getCaptureTimeOffset() {
        return captureTimeOffset;
    }

    @Override
    public Buffer getDataBuffer() {
        return dataBuffer;
    }

    @Override
    public String getEthernetSourceMacAddressString() throws DataTypeException {
        return DataTypeHelpers.getMacAddressString(this.sourceMacAddress);
    }

    @Override
    public String getEthernetDestinationMacAddressString() throws DataTypeException {
        return DataTypeHelpers.getMacAddressString(this.destinationMacAddress);
    }

}

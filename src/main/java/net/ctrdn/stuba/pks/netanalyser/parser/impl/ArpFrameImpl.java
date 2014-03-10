package net.ctrdn.stuba.pks.netanalyser.parser.impl;

import net.ctrdn.stuba.pks.netanalyser.annotation.FrameParser;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.exception.UnsupportedSourceFrameTypeException;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpHardwareType;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpOperation;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpProtocolType;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrameType;
import org.krakenapps.pcap.util.Buffer;

@FrameParser(
        name = "ARP Packet Parser",
        version = "1.0.0",
        layer = 3,
        orderKey = 20
)
public class ArpFrameImpl implements ArpFrame {

    private final EthernetFrame ethernetFrame;
    private final int arpHardwareTypeNumber;
    private final ArpHardwareType arpHardwareType;
    private final int arpProtocolTypeNumber;
    private final ArpProtocolType arpProtocolType;
    private final short arpHardwareAddressLength;
    private final short arpProtocolAddressLength;
    private final int arpOperationNumber;
    private final ArpOperation arpOperation;
    private final byte[] arpSenderHardwareAddress;
    private final byte[] arpSenderProtocolAddress;
    private final byte[] arpTargetHardwareAddress;
    private final byte[] arpTargetProtocolAddress;

    public ArpFrameImpl(EthernetFrame ethernetFrame) throws UnsupportedSourceFrameTypeException {
        this.ethernetFrame = ethernetFrame;
        if (ethernetFrame.getEthernetFrameType() != EthernetFrameType.ETHERNET2) {
            throw new UnsupportedSourceFrameTypeException("Only Ethernet II packets are supported");
        }
        if (ethernetFrame.getEthernetEthertypeBytes()[0] != 0x08 || ethernetFrame.getEthernetEthertypeBytes()[1] != 0x06) {
            throw new UnsupportedSourceFrameTypeException("Unsupported ethertype " + ethernetFrame.getEthernetEthertypeBytes());
        }
        this.arpHardwareTypeNumber = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        byte[] arpProtocolTypeBytes = new byte[2];
        arpProtocolTypeBytes[0] = ethernetFrame.getDataBuffer().get();
        arpProtocolTypeBytes[1] = ethernetFrame.getDataBuffer().get();
        this.arpProtocolTypeNumber = DataTypeHelpers.getUnsignedShortFromBytes(arpProtocolTypeBytes[0], arpProtocolTypeBytes[1]);
        switch (this.arpHardwareTypeNumber) {
            case 1: {
                this.arpHardwareType = ArpHardwareType.ETHERNET;
                break;
            }
            default: {
                throw new UnsupportedSourceFrameTypeException("Unknown hardware type number " + this.getArpHardwareTypeNumber());
            }
        }
        if (arpProtocolTypeBytes[0] == 0x08 && arpProtocolTypeBytes[1] == 0x00) {
            this.arpProtocolType = ArpProtocolType.INTERNET_PROTOCOL_V4;
        } else {
            throw new UnsupportedSourceFrameTypeException("Unknown protocol type number" + this.getArpProtocolTypeNumber());
        }
        this.arpHardwareAddressLength = DataTypeHelpers.getUnsignedByteValue(ethernetFrame.getDataBuffer().get());
        this.arpProtocolAddressLength = DataTypeHelpers.getUnsignedByteValue(ethernetFrame.getDataBuffer().get());
        this.arpOperationNumber = DataTypeHelpers.getUnsignedShortFromBytes(ethernetFrame.getDataBuffer().get(), ethernetFrame.getDataBuffer().get());
        switch (this.arpOperationNumber) {
            case 1: {
                this.arpOperation = ArpOperation.ARP_REQUEST;
                break;
            }
            case 2: {
                this.arpOperation = ArpOperation.ARP_REPLY;
                break;
            }
            default: {
                throw new UnsupportedSourceFrameTypeException("Unsupported ARP operation number" + this.getArpOperationNumber());
            }
        }
        this.arpSenderHardwareAddress = new byte[this.arpHardwareAddressLength];
        this.arpSenderProtocolAddress = new byte[this.arpProtocolAddressLength];
        this.arpTargetHardwareAddress = new byte[this.arpHardwareAddressLength];
        this.arpTargetProtocolAddress = new byte[this.arpProtocolAddressLength];
        for (int i = 0; i < this.arpHardwareAddressLength; i++) {
            this.arpSenderHardwareAddress[i] = ethernetFrame.getDataBuffer().get();
        }
        for (int i = 0; i < this.arpProtocolAddressLength; i++) {
            this.arpSenderProtocolAddress[i] = ethernetFrame.getDataBuffer().get();
        }
        for (int i = 0; i < this.arpHardwareAddressLength; i++) {
            this.arpTargetHardwareAddress[i] = ethernetFrame.getDataBuffer().get();
        }
        for (int i = 0; i < this.arpProtocolAddressLength; i++) {
            this.arpTargetProtocolAddress[i] = ethernetFrame.getDataBuffer().get();
        }
    }

    @Override
    public int getArpHardwareTypeNumber() {
        return arpHardwareTypeNumber;
    }

    @Override
    public ArpHardwareType getArpHardwareType() {
        return arpHardwareType;
    }

    @Override
    public int getArpProtocolTypeNumber() {
        return arpProtocolTypeNumber;
    }

    @Override
    public ArpProtocolType getArpProtocolType() {
        return arpProtocolType;
    }

    @Override
    public short getArpHardwareAddressLength() {
        return arpHardwareAddressLength;
    }

    @Override
    public short getArpProtocolAddressLength() {
        return arpProtocolAddressLength;
    }

    @Override
    public int getArpOperationNumber() {
        return arpOperationNumber;
    }

    @Override
    public ArpOperation getArpOperation() {
        return arpOperation;
    }

    @Override
    public byte[] getArpSenderHardwareAddress() {
        return arpSenderHardwareAddress;
    }

    @Override
    public byte[] getArpSenderProtocolAddress() {
        return arpSenderProtocolAddress;
    }

    @Override
    public byte[] getArpTargetHardwareAddress() {
        return arpTargetHardwareAddress;
    }

    @Override
    public byte[] getArpTargetProtocolAddress() {
        return arpTargetProtocolAddress;
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

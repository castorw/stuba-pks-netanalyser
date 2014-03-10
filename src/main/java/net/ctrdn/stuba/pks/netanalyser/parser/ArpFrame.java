package net.ctrdn.stuba.pks.netanalyser.parser;

public interface ArpFrame extends EthernetFrame {

    public int getArpHardwareTypeNumber();

    public ArpHardwareType getArpHardwareType();

    public int getArpProtocolTypeNumber();

    public ArpProtocolType getArpProtocolType();

    public short getArpHardwareAddressLength();

    public short getArpProtocolAddressLength();

    public int getArpOperationNumber();

    public ArpOperation getArpOperation();

    public byte[] getArpSenderHardwareAddress();

    public byte[] getArpSenderProtocolAddress();

    public byte[] getArpTargetHardwareAddress();

    public byte[] getArpTargetProtocolAddress();
}

package net.ctrdn.stuba.pks.netanalyser.parser;

public interface TcpFrame extends IPv4Frame {

    public int getTcpSourcePort();

    public int getTcpDestinationPort();

    public byte[] getTcpSequenceNumber();

    public byte[] getTcpAcknowledgmentNumber();

    public short getTcpDataOffset();

    public boolean hasTcpFlag(TcpFlag flag);

    public int getTcpWindowSize();

    public int getTcpChecksum();

    public int getTcpUrgentPointer();
}

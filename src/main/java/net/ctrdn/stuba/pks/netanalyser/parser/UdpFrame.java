package net.ctrdn.stuba.pks.netanalyser.parser;

public interface UdpFrame extends IPv4Frame {

    public int getUdpSourcePort();

    public int getUdpDestinationPort();

    public int getUdpLength();

    public int getUdpChecksum();
}
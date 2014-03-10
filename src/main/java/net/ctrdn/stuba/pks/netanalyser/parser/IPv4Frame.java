package net.ctrdn.stuba.pks.netanalyser.parser;

public interface IPv4Frame extends EthernetFrame {

    public short getIpVersion();

    public short getIpInternetHeaderLength();

    public int getIpTotalLength();

    public int getIpIdentification();

    public boolean hasIpFlag(IPv4FrameFlags frameFlag);

    public int getIpFragmentOffset();

    public int getIpTimeToLive();

    public int getIpProtocolNumber();

    public IPv4FrameProtocol getIpProtocol();

    public int getIpHeaderChecksum();

    public IPv4Address getIpSourceAddress();

    public IPv4Address getIpDestinationAddress();
}

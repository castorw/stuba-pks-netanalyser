package net.ctrdn.stuba.pks.netanalyser.connection;

import java.util.List;
import net.ctrdn.stuba.pks.netanalyser.exception.TcpFrameNotMatchingException;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Address;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;

public interface TcpConnection {

    public void addFrame(TcpFrame frame) throws TcpFrameNotMatchingException;

    public TcpConnectionState getTcpConnectionState();

    public boolean isComplete();

    public IPv4Address getSourceIpAddress();

    public IPv4Address getDestinationIpAddress();

    public int getSourcePort();

    public int getDestinationPort();

    public List<TcpFrame> getFrames();
}

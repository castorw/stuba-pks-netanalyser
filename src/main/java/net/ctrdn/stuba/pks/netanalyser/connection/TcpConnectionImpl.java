package net.ctrdn.stuba.pks.netanalyser.connection;

import java.util.ArrayList;
import java.util.List;
import net.ctrdn.stuba.pks.netanalyser.exception.TcpFrameNotMatchingException;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Address;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFlag;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;

public class TcpConnectionImpl implements TcpConnection {

    private final List<TcpFrame> frameList = new ArrayList<>();
    private final IPv4Address firstPeerAddress;
    private final IPv4Address secondPeerAddress;
    private final int firstPeerPort;
    private final int secondPeerPort;
    private TcpConnectionState state = TcpConnectionState.UNKNOWN;

    public TcpConnectionImpl(TcpFrame firstFrame) {
        if (firstFrame.hasTcpFlag(TcpFlag.SYN)) {
            this.state = TcpConnectionState.TWHS_SYN_SENT;
        }
        this.firstPeerAddress = firstFrame.getIpSourceAddress();
        this.secondPeerAddress = firstFrame.getIpDestinationAddress();
        this.firstPeerPort = firstFrame.getTcpSourcePort();
        this.secondPeerPort = firstFrame.getTcpDestinationPort();
        this.frameList.add(firstFrame);
    }

    private enum FrameDirection {

        FIRST_TO_SECOND,
        SECOND_TO_FIRST
    }

    @Override
    public void addFrame(TcpFrame frame) throws TcpFrameNotMatchingException {
        FrameDirection direction = null;
        if (frame.getIpSourceAddress().equals(this.firstPeerAddress) && frame.getIpDestinationAddress().equals(this.secondPeerAddress) && frame.getTcpSourcePort() == this.firstPeerPort && frame.getTcpDestinationPort() == this.secondPeerPort) {
            direction = FrameDirection.FIRST_TO_SECOND;
        } else if (frame.getIpSourceAddress().equals(this.secondPeerAddress) && frame.getIpDestinationAddress().equals(this.firstPeerAddress) && frame.getTcpSourcePort() == this.secondPeerPort && frame.getTcpDestinationPort() == this.firstPeerPort) {
            direction = FrameDirection.SECOND_TO_FIRST;
        }
        if (direction == null) {
            throw new TcpFrameNotMatchingException("Frame does not match this connection");
        } else if (this.state == TcpConnectionState.FIN2 || this.state == TcpConnectionState.RST) {
            throw new TcpFrameNotMatchingException("This connection has already been closed");
        }
        if (this.state == TcpConnectionState.TWHS_SYN_SENT && direction == FrameDirection.SECOND_TO_FIRST && frame.hasTcpFlag(TcpFlag.SYN) && frame.hasTcpFlag(TcpFlag.ACK)) {
            this.state = TcpConnectionState.TWHS_SYN_ACK_RECEIVED;
        } else if (this.state == TcpConnectionState.TWHS_SYN_ACK_RECEIVED && direction == FrameDirection.FIRST_TO_SECOND && frame.hasTcpFlag(TcpFlag.ACK)) {
            this.state = TcpConnectionState.TWHS_ACK_SENT;
        } else if (this.state == TcpConnectionState.TWHS_ACK_SENT && direction == FrameDirection.SECOND_TO_FIRST) {
            this.state = TcpConnectionState.ESTABLISHED;
        } else if ((this.state == TcpConnectionState.ESTABLISHED || this.state == TcpConnectionState.FIN1) && frame.hasTcpFlag(TcpFlag.FIN)) {
            if (this.state == TcpConnectionState.ESTABLISHED) {
                this.state = TcpConnectionState.FIN1;
            } else if (this.state == TcpConnectionState.FIN1) {
                this.state = TcpConnectionState.FIN2;
            }
        } else if (frame.hasTcpFlag(TcpFlag.RST)) {
            this.state = TcpConnectionState.RST;
        }
        this.frameList.add(frame);
    }

    @Override
    public TcpConnectionState getTcpConnectionState() {
        return this.state;
    }

    @Override
    public boolean isComplete() {
        return (this.state == TcpConnectionState.FIN2 || this.state == TcpConnectionState.RST);
    }

    @Override
    public IPv4Address getSourceIpAddress() {
        return this.firstPeerAddress;
    }

    @Override
    public IPv4Address getDestinationIpAddress() {
        return this.secondPeerAddress;
    }

    @Override
    public int getSourcePort() {
        return this.firstPeerPort;
    }

    @Override
    public int getDestinationPort() {
        return this.secondPeerPort;
    }

    @Override
    public List<TcpFrame> getFrames() {
        return this.frameList;
    }

}

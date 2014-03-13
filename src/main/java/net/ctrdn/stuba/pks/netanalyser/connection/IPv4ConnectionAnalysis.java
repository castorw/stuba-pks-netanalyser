package net.ctrdn.stuba.pks.netanalyser.connection;

import java.util.ArrayList;
import java.util.List;
import net.ctrdn.stuba.pks.netanalyser.exception.ConnectionAnalyserException;
import net.ctrdn.stuba.pks.netanalyser.exception.TcpFrameNotMatchingException;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Frame;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameProtocol;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;

public class IPv4ConnectionAnalysis {

    private final List<IPv4Frame> frameList;
    private final List<Filter> filterList;
    private boolean analysed = false;
    private List<IPv4Frame> statelessPacketList;
    private List<TcpConnection> connections;
    private int framesPassedFilter = 0;

    public IPv4ConnectionAnalysis(List<IPv4Frame> frameList) {
        this.frameList = frameList;
        this.filterList = new ArrayList<>();
    }

    public void addFilter(Filter filter) {
        this.filterList.add(filter);
    }

    private boolean match(IPv4Frame frame) {
        for (Filter f : this.filterList) {
            if (f.match(frame)) {
                return true;
            }
        }
        return false;
    }

    public void analyze() {
        this.statelessPacketList = new ArrayList<>();
        this.connections = new ArrayList<>();
        for (IPv4Frame frame : this.frameList) {
            if (this.match(frame)) {
                if (frame.getIpProtocol() == IPv4FrameProtocol.ICMP || frame.getIpProtocol() == IPv4FrameProtocol.UDP) {
                    this.statelessPacketList.add(frame);
                } else if (frame.getIpProtocol() == IPv4FrameProtocol.TCP) {
                    boolean parsed = false;
                    for (TcpConnection conn : this.connections) {
                        try {
                            conn.addFrame((TcpFrame) frame);
                            parsed = true;
                            break;
                        } catch (TcpFrameNotMatchingException ex) {
                        }
                    }
                    if (!parsed) {
                        this.connections.add(new TcpConnectionImpl((TcpFrame) frame));
                    }
                } else {
                    // unknown (for us) ip protocol - nothing to do
                }
                this.framesPassedFilter++;
            }
        }
        this.analysed = true;
    }

    public List<IPv4Frame> getStatelessPacketList() throws ConnectionAnalyserException {
        if (!this.analysed) {
            throw new ConnectionAnalyserException("Analysis hasn't been run yet");
        }
        return statelessPacketList;
    }

    public List<TcpConnection> getConnections() throws ConnectionAnalyserException {
        if (!this.analysed) {
            throw new ConnectionAnalyserException("Analysis hasn't been run yet");
        }
        return connections;
    }

    public int getTotalPackets() {
        return this.frameList.size();
    }

    public int getFilteredPackets() {
        return this.framesPassedFilter;
    }
}

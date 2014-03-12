package net.ctrdn.stuba.pks.netanalyser.connection;

import java.util.List;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;

public class ConnectionAnalyser {

    private final List<EthernetFrame> frameList;
    private final Filter filter;
    private boolean analysed = false;

    public ConnectionAnalyser(List<EthernetFrame> frameList, Filter filter) {
        this.frameList = frameList;
        this.filter = filter;
    }

    public void analyze() {

    }
}

package net.ctrdn.stuba.pks.netanalyser.am.http;

import java.util.List;
import javax.swing.JPanel;
import net.ctrdn.stuba.pks.netanalyser.am.AnalyserModule;
import net.ctrdn.stuba.pks.netanalyser.annotation.Analyser;
import net.ctrdn.stuba.pks.netanalyser.connection.DefaultIPv4ConnectionAnalysisPanel;
import net.ctrdn.stuba.pks.netanalyser.connection.FilterFactory;
import net.ctrdn.stuba.pks.netanalyser.connection.FilterPortDirection;
import net.ctrdn.stuba.pks.netanalyser.connection.IPv4ConnectionAnalysis;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Frame;

@Analyser(
        name = "HTTP Packet Analyser",
        version = "1.0.0"
)
public class HttpAnalyserModule implements AnalyserModule<IPv4Frame> {

    public DefaultIPv4ConnectionAnalysisPanel panel = new DefaultIPv4ConnectionAnalysisPanel("HTTP");

    @Override
    public int getPanelOrderKey() {
        return 100;
    }

    @Override
    public JPanel getPanel() {
        return this.panel;
    }

    @Override
    public void parse(List<IPv4Frame> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException {
        IPv4ConnectionAnalysis analysis = new IPv4ConnectionAnalysis(frameList);
        analysis.addFilter(FilterFactory.tcpPortFilter(FilterPortDirection.SRC_OR_DST_PORT, 80));
        analysis.addFilter(FilterFactory.udpPortFilter(FilterPortDirection.SRC_OR_DST_PORT, 80));
        analysis.analyze();
        this.panel.update(analysis, filteredFrameCount, totalFrameCount);
    }

    @Override
    public Class<IPv4Frame> getFilterClass() {
        return IPv4Frame.class;
    }
}
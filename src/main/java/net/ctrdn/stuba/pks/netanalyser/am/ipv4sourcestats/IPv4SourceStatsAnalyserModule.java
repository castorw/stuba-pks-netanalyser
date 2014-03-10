package net.ctrdn.stuba.pks.netanalyser.am.ipv4sourcestats;

import java.util.List;
import javax.swing.JPanel;
import net.ctrdn.stuba.pks.netanalyser.am.AnalyserModule;
import net.ctrdn.stuba.pks.netanalyser.annotation.Analyser;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Frame;

@Analyser(
        name = "IPv4 Source Stats",
        version = "1.0.0"
)
public class IPv4SourceStatsAnalyserModule implements AnalyserModule<IPv4Frame> {

    private final IPv4SourceStatsPanel panel = new IPv4SourceStatsPanel(this);

    @Override
    public int getPanelOrderKey() {
        return 20;
    }

    @Override
    public JPanel getPanel() {
        return this.panel;
    }

    @Override
    public void parse(List<IPv4Frame> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException {
        this.panel.update(frameList, filteredFrameCount, totalFrameCount);
    }

    @Override
    public Class<IPv4Frame> getFilterClass() {
        return IPv4Frame.class;
    }
}

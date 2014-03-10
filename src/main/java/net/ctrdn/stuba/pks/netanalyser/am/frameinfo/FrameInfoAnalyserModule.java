package net.ctrdn.stuba.pks.netanalyser.am.frameinfo;

import java.util.List;
import javax.swing.JPanel;
import net.ctrdn.stuba.pks.netanalyser.am.AnalyserModule;
import net.ctrdn.stuba.pks.netanalyser.annotation.Analyser;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;

@Analyser(
        name = "Ethernet Frame Info Analyser",
        version = "1.0.0"
)
public class FrameInfoAnalyserModule implements AnalyserModule<EthernetFrame> {

    private final FrameInfoPanel panel = new FrameInfoPanel(this);

    @Override
    public int getPanelOrderKey() {
        return 10;
    }

    @Override
    public JPanel getPanel() {
        return this.panel;
    }

    @Override
    public void parse(List<EthernetFrame> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException {
        this.panel.update(frameList, filteredFrameCount, totalFrameCount);
    }

    @Override
    public Class<EthernetFrame> getFilterClass() {
        return EthernetFrame.class;
    }
}

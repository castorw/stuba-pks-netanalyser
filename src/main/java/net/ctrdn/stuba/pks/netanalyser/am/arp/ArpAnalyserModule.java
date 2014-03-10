package net.ctrdn.stuba.pks.netanalyser.am.arp;

import java.util.List;
import javax.swing.JPanel;
import net.ctrdn.stuba.pks.netanalyser.am.AnalyserModule;
import net.ctrdn.stuba.pks.netanalyser.annotation.Analyser;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpFrame;

@Analyser(
        name = "ARP Analyser",
        version = "1.0.0"
)
public class ArpAnalyserModule implements AnalyserModule<ArpFrame> {
    
    private final ArpPanel panel = new ArpPanel();
    
    @Override
    public int getPanelOrderKey() {
        return 30;
    }
    
    @Override
    public JPanel getPanel() {
        return this.panel;
    }
    
    @Override
    public void parse(List<ArpFrame> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException {
        this.panel.update(frameList, filteredFrameCount, totalFrameCount);
    }
    
    @Override
    public Class<ArpFrame> getFilterClass() {
        return ArpFrame.class;
    }
    
}

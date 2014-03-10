package net.ctrdn.stuba.pks.netanalyser.am.icmp;

import java.util.List;
import javax.swing.JPanel;
import net.ctrdn.stuba.pks.netanalyser.am.AnalyserModule;
import net.ctrdn.stuba.pks.netanalyser.annotation.Analyser;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.parser.IcmpFrame;

@Analyser(
        name = "ICMP Analyser",
        version = "1.0.0"
)
public class IcmpAnalyserModule implements AnalyserModule<IcmpFrame> {
    
    private final IcmpPanel panel = new IcmpPanel();
    
    @Override
    public int getPanelOrderKey() {
        return 40;
    }
    
    @Override
    public JPanel getPanel() {
        return this.panel;
    }
    
    @Override
    public void parse(List<IcmpFrame> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException {
        this.panel.update(frameList, filteredFrameCount, totalFrameCount);
    }
    
    @Override
    public Class<IcmpFrame> getFilterClass() {
        return IcmpFrame.class;
    }
    
}

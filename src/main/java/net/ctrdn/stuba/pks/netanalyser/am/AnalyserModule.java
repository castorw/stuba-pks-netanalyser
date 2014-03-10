package net.ctrdn.stuba.pks.netanalyser.am;

import java.util.List;
import javax.swing.JPanel;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;

public interface AnalyserModule<FT extends EthernetFrame> {

    public int getPanelOrderKey();

    public JPanel getPanel();

    public void parse(List<FT> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException;

    public Class<FT> getFilterClass();
}

package net.ctrdn.stuba.pks.netanalyser.connection;

import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;

public interface Filter {

    public boolean match(EthernetFrame frame);
}

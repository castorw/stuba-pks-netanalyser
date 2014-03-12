package net.ctrdn.stuba.pks.netanalyser.connection;

import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.IcmpFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.UdpFrame;

public class FilterFactory {

    public static Filter tcpFilter() {
        return new Filter() {

            @Override
            public boolean match(EthernetFrame frame) {
                return TcpFrame.class.isAssignableFrom(frame.getClass());
            }
        };
    }

    public static Filter udpFilter() {
        return new Filter() {

            @Override
            public boolean match(EthernetFrame frame) {
                return UdpFrame.class.isAssignableFrom(frame.getClass());
            }
        };
    }

    public static Filter icmpFilter() {
        return new Filter() {

            @Override
            public boolean match(EthernetFrame frame) {
                return IcmpFrame.class.isAssignableFrom(frame.getClass());
            }
        };
    }

    public static Filter tcpPortFilter(final FilterPortDirection direction, final int port) {
        return new Filter() {

            @Override
            public boolean match(EthernetFrame frame) {
                if (FilterFactory.tcpFilter().match(frame)) {
                    TcpFrame tcpFrame = (TcpFrame) frame;
                    if (direction == FilterPortDirection.SRC_PORT && tcpFrame.getTcpSourcePort() == port) {
                        return true;
                    } else if (direction == FilterPortDirection.DST_PORT && tcpFrame.getTcpDestinationPort() == port) {
                        return true;
                    } else if (direction == FilterPortDirection.SRC_OR_DST_PORT && (tcpFrame.getTcpSourcePort() == port || tcpFrame.getTcpDestinationPort() == port)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public static Filter udpPortFilter(final FilterPortDirection direction, final int port) {
        return new Filter() {

            @Override
            public boolean match(EthernetFrame frame) {
                if (FilterFactory.udpFilter().match(frame)) {
                    UdpFrame tcpFrame = (UdpFrame) frame;
                    if (direction == FilterPortDirection.SRC_PORT && tcpFrame.getUdpSourcePort() == port) {
                        return true;
                    } else if (direction == FilterPortDirection.DST_PORT && tcpFrame.getUdpDestinationPort() == port) {
                        return true;
                    } else if (direction == FilterPortDirection.SRC_OR_DST_PORT && (tcpFrame.getUdpSourcePort() == port || tcpFrame.getUdpDestinationPort() == port)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }
}

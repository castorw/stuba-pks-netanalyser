package net.ctrdn.stuba.pks.netanalyser.connection;

public enum TcpConnectionState {

    UNKNOWN,
    TWHS_SYN_SENT,
    TWHS_SYN_ACK_RECEIVED,
    TWHS_ACK_SENT,
    ESTABLISHED,
    FIN1,
    FIN2_WAIT_ACK,
    FIN2,
    RST,
    LOCKED
}

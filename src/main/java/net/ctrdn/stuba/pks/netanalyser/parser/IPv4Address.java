package net.ctrdn.stuba.pks.netanalyser.parser;

import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;

public interface IPv4Address {

    public byte[] getBytes();

    public String getString() throws DataTypeException;

    public boolean isBroadcast();
}

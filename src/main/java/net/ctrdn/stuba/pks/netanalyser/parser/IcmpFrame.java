package net.ctrdn.stuba.pks.netanalyser.parser;

import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;

public interface IcmpFrame extends IPv4Frame {

    public short getIcmpTypeNumber();

    public String getIcmpTypeString() throws DataTypeException;

    public short getIcmpCodeNumber();

    public String getIcmpCodeString() throws DataTypeException;

    public int getIcmpChecksum();

    public byte[] getIcmpRestHeader();
}

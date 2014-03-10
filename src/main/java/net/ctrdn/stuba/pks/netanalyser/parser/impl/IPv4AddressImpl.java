package net.ctrdn.stuba.pks.netanalyser.parser.impl;

import java.util.Arrays;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Address;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.exception.FrameAnalysisException;

public class IPv4AddressImpl implements IPv4Address {

    private final byte[] address;

    public IPv4AddressImpl(byte[] address) throws FrameAnalysisException {
        if (address.length != 4) {
            throw new FrameAnalysisException("Invalid IPv4 address byte array length (" + address.length + ")");
        }
        this.address = address;
    }

    @Override
    public String getString() throws DataTypeException {
        return DataTypeHelpers.getIPv4AddressString(this.address);
    }

    @Override
    public byte[] getBytes() {
        return this.address;
    }

    @Override
    public boolean isBroadcast() {
        if (address[0] == 0xff && address[1] == 0xff && address[2] == 0xff && address[3] == 0xff) {
            return true;
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (o.getClass() != IPv4AddressImpl.class) {
            return false;
        } else {
            IPv4AddressImpl cast = (IPv4AddressImpl) o;
            if (Arrays.equals(cast.address, this.address)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 71 * hash + Arrays.hashCode(this.address);
        return hash;
    }
}

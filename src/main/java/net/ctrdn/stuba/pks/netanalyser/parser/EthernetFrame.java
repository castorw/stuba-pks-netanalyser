package net.ctrdn.stuba.pks.netanalyser.parser;

import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import org.krakenapps.pcap.util.Buffer;

public interface EthernetFrame {

    public int getCaptureId();

    public int getCaptureTimeOffset();

    public int getCaptureOriginalLength();

    public int getCaptureWireLength();

    public byte[] getEthernetSourceMacAddress();

    public byte[] getEthernetDestinationMacAddress();

    public String getEthernetSourceMacAddressString() throws DataTypeException;

    public String getEthernetDestinationMacAddressString() throws DataTypeException;

    public byte[] getEthernetEthertypeBytes();

    public EthernetFrameType getEthernetFrameType();

    public Buffer getDataBuffer();
}

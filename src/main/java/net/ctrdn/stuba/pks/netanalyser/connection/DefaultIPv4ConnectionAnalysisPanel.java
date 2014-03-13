package net.ctrdn.stuba.pks.netanalyser.connection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.common.NonEditableColorableDefaultTableModel;
import net.ctrdn.stuba.pks.netanalyser.exception.ConnectionAnalyserException;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4Frame;
import net.ctrdn.stuba.pks.netanalyser.parser.IPv4FrameProtocol;
import net.ctrdn.stuba.pks.netanalyser.parser.TcpFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.UdpFrame;
import org.krakenapps.pcap.util.Buffer;

public class DefaultIPv4ConnectionAnalysisPanel extends javax.swing.JPanel {

    private IPv4ConnectionAnalysis analysis;
    private boolean statelessSelected = false;
    private int communicationId = 0;

    public DefaultIPv4ConnectionAnalysisPanel(String title) {
        initComponents();
        this.setName(title);
        this.communicationsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                try {
                    int selectedRowId = communicationsTable.getSelectedRow();
                    if (selectedRowId >= 0) {
                        String indexColumnData = null;
                        if (communicationsTable.getValueAt(selectedRowId, 0).getClass() == Integer.class) {
                            indexColumnData = Integer.toString((Integer) communicationsTable.getValueAt(selectedRowId, 0));
                        } else {
                            indexColumnData = (String) communicationsTable.getValueAt(selectedRowId, 0);
                        }
                        List<Integer> lengthList = new ArrayList<>();
                        if (indexColumnData.equals("-")) {
                            statelessSelected = true;
                            DefaultTableModel framesTableModel = new NonEditableColorableDefaultTableModel(new Object[]{"#", "Capture #", "Source MAC", "Destination MAC", "IP Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "IPv4 Length"}, 0);
                            int index = 0;
                            for (IPv4Frame frame : analysis.getStatelessPacketList()) {
                                lengthList.add(frame.getCaptureOriginalLength());
                                framesTableModel.addRow(new Object[]{index, frame.getCaptureId(), frame.getEthernetSourceMacAddressString(), frame.getEthernetDestinationMacAddressString(), frame.getIpProtocol().toString(), frame.getIpSourceAddress().getString(), (frame.getIpProtocol() == IPv4FrameProtocol.UDP) ? DataTypeHelpers.getPortServiceString(IPv4FrameProtocol.UDP, ((UdpFrame) frame).getUdpSourcePort()) : "-", frame.getIpDestinationAddress().getString(), (frame.getIpProtocol() == IPv4FrameProtocol.UDP) ? DataTypeHelpers.getPortServiceString(IPv4FrameProtocol.UDP, ((UdpFrame) frame).getUdpDestinationPort()) : "-", frame.getIpTotalLength()});
                                index++;
                            }
                            frameTable.setModel(framesTableModel);
                        } else {
                            statelessSelected = false;
                            communicationId = Integer.parseInt(indexColumnData);
                            DefaultTableModel framesTableModel = new NonEditableColorableDefaultTableModel(new Object[]{"#", "Capture #", "Source MAC", "Destination MAC", "Source IP", "Source Port", "Destination IP", "Destination Port", "TCP Flags", "IPv4 Length"}, 0);
                            int index = 0;
                            for (TcpFrame frame : analysis.getConnections().get(communicationId).getFrames()) {
                                lengthList.add(frame.getCaptureOriginalLength());
                                framesTableModel.addRow(new Object[]{index, frame.getCaptureId(), frame.getEthernetSourceMacAddressString(), frame.getEthernetDestinationMacAddressString(), frame.getIpSourceAddress().getString(), DataTypeHelpers.getPortServiceString(IPv4FrameProtocol.TCP, frame.getTcpSourcePort()), frame.getIpDestinationAddress().getString(), DataTypeHelpers.getPortServiceString(IPv4FrameProtocol.TCP, frame.getTcpDestinationPort()), DataTypeHelpers.getTcpFlagsString(frame), frame.getIpTotalLength()});
                                index++;
                            }
                            frameTable.setModel(framesTableModel);
                        }
                        DefaultTableModel lengthTableModel = new NonEditableColorableDefaultTableModel(new Object[]{"Length", "Count"}, 0);
                        List<Integer> baselineList = new ArrayList<>();
                        Map<Integer, Integer> baselineCountMap = new HashMap<>();
                        baselineList.add(0);
                        baselineList.add(20);
                        baselineCountMap.put(0, 0);
                        baselineCountMap.put(20, 0);
                        for (int size : lengthList) {
                            boolean added = false;
                            for (Integer baseline : baselineList) {
                                if (size >= baseline && size <= (2 * baseline) - 1) {
                                    if (baselineCountMap.containsKey(baseline)) {
                                        baselineCountMap.replace(baseline, baselineCountMap.get(baseline) + 1);
                                    } else {
                                        baselineCountMap.put(baseline, 1);
                                    }
                                    added = true;
                                    break;
                                }
                            }
                            if (!added) {
                                int baselineId = 0;
                                while (!(size >= baselineList.get(baselineId) && size <= (2 * baselineList.get(baselineId)) - 1)) {
                                    baselineId++;
                                    if (baselineId == baselineList.size()) {
                                        baselineList.add(baselineList.get(baselineId - 1) * 2);
                                        baselineCountMap.put(baselineList.get(baselineId), 0);
                                    }
                                    if (size >= baselineList.get(baselineId) && size <= (2 * baselineList.get(baselineId)) - 1) {
                                        baselineCountMap.replace(baselineList.get(baselineId), baselineCountMap.get(baselineList.get(baselineId)) + 1);
                                    }
                                }
                            }
                        }
                        for (int baseline : baselineList) {
                            lengthTableModel.addRow(new Object[]{baseline + "-" + ((baseline == 0) ? "19" : ((baseline * 2) - 1)), baselineCountMap.get(baseline)});
                        }
                        lengthTable.setModel(lengthTableModel);
                    }
                } catch (ConnectionAnalyserException | DataTypeException ex) {
                    ex.printStackTrace();
                }
            }
        });

        frameTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                try {
                    int tableRowId = frameTable.getSelectedRow();
                    if (tableRowId >= 0) {
                        int frameId = (Integer) frameTable.getValueAt(tableRowId, 0);
                        if (statelessSelected) {
                            Buffer frameBuffer = analysis.getStatelessPacketList().get(frameId).getDataBuffer();
                            int posBackup = frameBuffer.position();
                            frameBuffer.rewind();
                            jTextPaneFrameData.setText(DataTypeHelpers.getFrameDataFormatted(frameBuffer, 32));
                            jTextPaneFrameData.setCaretPosition(0);
                            frameBuffer.rewind();
                            frameBuffer.skip(posBackup);
                        } else {
                            Buffer frameBuffer = analysis.getConnections().get(communicationId).getFrames().get(frameId).getDataBuffer();
                            int posBackup = frameBuffer.position();
                            frameBuffer.rewind();
                            jTextPaneFrameData.setText(DataTypeHelpers.getFrameDataFormatted(frameBuffer, 32));
                            jTextPaneFrameData.setCaretPosition(0);
                            frameBuffer.rewind();
                            frameBuffer.skip(posBackup);
                        }
                    }
                } catch (ConnectionAnalyserException ex) {
                    ex.printStackTrace();
                }
            }
        }
        );
    }

    ;
    
    public void update(IPv4ConnectionAnalysis analysis, int filteredCount, int totalCount) {
        communicationsTable.setModel(new DefaultTableModel());
        frameTable.setModel(new DefaultTableModel());
        jTextPaneFrameData.setText("");
        lengthTable.setModel(new DefaultTableModel());
        this.analysis = analysis;
        try {
            DefaultTableModel commsTableModel = new NonEditableColorableDefaultTableModel(new Object[]{"Id", "Type", "Source Address", "SRC Port", "Destination Address", "DST Port", "Status", "Frames"}, 0);
            if (this.analysis.getStatelessPacketList().size() > 0) {
                commsTableModel.addRow(new Object[]{"-", "Stateless", "-", "-", "-", "-", "-", analysis.getStatelessPacketList().size()});
            }
            int index = 0;
            for (TcpConnection conn : this.analysis.getConnections()) {
                commsTableModel.addRow(new Object[]{index, "TCP", conn.getSourceIpAddress().getString(), DataTypeHelpers.getPortServiceString(IPv4FrameProtocol.TCP, conn.getSourcePort()), conn.getDestinationIpAddress().getString(), DataTypeHelpers.getPortServiceString(IPv4FrameProtocol.TCP, conn.getDestinationPort()), (conn.isComplete()) ? "Complete" : "Incomplete", conn.getFrames().size()});
                index++;
            }
            this.communicationsTable.setModel(commsTableModel);
        } catch (ConnectionAnalyserException | DataTypeException ex) {
            ex.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSplitPane1 = new javax.swing.JSplitPane();
        jSplitPane2 = new javax.swing.JSplitPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        communicationsTable = new javax.swing.JTable();
        jSplitPane3 = new javax.swing.JSplitPane();
        jScrollPane5 = new javax.swing.JScrollPane();
        lengthTable = new javax.swing.JTable();
        jScrollPane6 = new javax.swing.JScrollPane();
        frameTable = new javax.swing.JTable();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextPaneFrameData = new javax.swing.JTextPane();

        jSplitPane1.setDividerLocation(400);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        jSplitPane2.setDividerLocation(200);
        jSplitPane2.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        communicationsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane2.setViewportView(communicationsTable);

        jSplitPane2.setLeftComponent(jScrollPane2);

        jSplitPane3.setDividerLocation(175);

        lengthTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane5.setViewportView(lengthTable);

        jSplitPane3.setLeftComponent(jScrollPane5);

        frameTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane6.setViewportView(frameTable);

        jSplitPane3.setRightComponent(jScrollPane6);

        jSplitPane2.setRightComponent(jSplitPane3);

        jSplitPane1.setTopComponent(jSplitPane2);

        jTextPaneFrameData.setEditable(false);
        jTextPaneFrameData.setFont(new java.awt.Font("Monospaced", 0, 13)); // NOI18N
        jScrollPane1.setViewportView(jTextPaneFrameData);

        jSplitPane1.setRightComponent(jScrollPane1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 732, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 489, Short.MAX_VALUE)
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable communicationsTable;
    private javax.swing.JTable frameTable;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JSplitPane jSplitPane3;
    private javax.swing.JTextPane jTextPaneFrameData;
    private javax.swing.JTable lengthTable;
    // End of variables declaration//GEN-END:variables
}

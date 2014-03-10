/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.ctrdn.stuba.pks.netanalyser.am.arp;

import java.awt.Color;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import net.ctrdn.stuba.pks.netanalyser.common.ColorableTableCellRenderer;
import net.ctrdn.stuba.pks.netanalyser.common.DataTypeHelpers;
import net.ctrdn.stuba.pks.netanalyser.common.NonEditableColorableDefaultTableModel;
import net.ctrdn.stuba.pks.netanalyser.exception.AnalyserModuleException;
import net.ctrdn.stuba.pks.netanalyser.exception.DataTypeException;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpFrame;
import net.ctrdn.stuba.pks.netanalyser.parser.ArpOperation;
import org.krakenapps.pcap.util.Buffer;

/**
 *
 * @author castor
 */
public class ArpPanel extends javax.swing.JPanel {

    private List<ArpFrame> frameList;
    private Map<ArpFrame, ArpFrame> arpPairs;
    private Map<ArpFrame, Integer> frameTableMap;

    public ArpPanel() {
        initComponents();
        this.jTableFrameTable.setDefaultRenderer(Object.class, new ColorableTableCellRenderer());
        this.jTableFrameTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                int tableRowId = ArpPanel.this.jTableFrameTable.getSelectedRow();
                if (tableRowId >= 0) {
                    int frameId = (Integer) ArpPanel.this.jTableFrameTable.getModel().getValueAt(tableRowId, 0);
                    if (ArpPanel.this.frameList != null) {
                        ArpFrame frame = ArpPanel.this.frameList.get(frameId);
                        Buffer frameBuffer = frame.getDataBuffer();
                        int posBackup = frameBuffer.position();
                        frameBuffer.rewind();
                        ArpPanel.this.jTextPaneFrameData.setText(DataTypeHelpers.getFrameDataFormatted(frameBuffer, 32));
                        ArpPanel.this.jTextPaneFrameData.setCaretPosition(0);
                        frameBuffer.rewind();
                        frameBuffer.skip(posBackup);
                        ((NonEditableColorableDefaultTableModel) jTableFrameTable.getModel()).removeAllColors();
                        if (arpPairs.containsKey(frame) && frameTableMap.containsKey(arpPairs.get(frame))) {
                            Integer rowIndex = frameTableMap.get(arpPairs.get(frame));
                            ((NonEditableColorableDefaultTableModel) jTableFrameTable.getModel()).setRowColor(rowIndex, Color.CYAN);
                        }
                    }
                }
            }
        });
    }

    protected void update(List<ArpFrame> frameList, int filteredFrameCount, int totalFrameCount) throws AnalyserModuleException {
        try {
            this.frameList = frameList;
            this.arpPairs = new HashMap<>();
            this.frameTableMap = new HashMap<>();
            int index = 0;
            DefaultTableModel tableModel = new NonEditableColorableDefaultTableModel(new Object[]{"#", "Capture #", "Ethernet Source MAC", "Ethernet Destination MAC", "HW Type", "Protocol Type", "HW Address Length", "Protocol Address Length", "Operation", "Sender HW Address", "Sender Protocol Address", "Target HW Address", "Target Protocol Address"}, 0);
            for (ArpFrame frame : frameList) {
                if (!this.arpPairs.containsKey(frame)) {
                    for (ArpFrame searchFrame : frameList) {
                        if (this.arpPairs.containsKey(searchFrame)) {
                            continue;
                        }
                        if ((frame.getArpOperation() == ArpOperation.ARP_REQUEST && searchFrame.getArpOperation() == ArpOperation.ARP_REPLY && Arrays.equals(frame.getArpSenderHardwareAddress(), searchFrame.getArpTargetHardwareAddress()) && Arrays.equals(frame.getArpTargetProtocolAddress(), searchFrame.getArpSenderProtocolAddress()))) {
                            this.arpPairs.put(frame, searchFrame);
                            this.arpPairs.put(searchFrame, frame);
                            break;
                        }
                    }
                }
                tableModel.addRow(new Object[]{index, frame.getCaptureId(), frame.getEthernetSourceMacAddressString(), frame.getEthernetDestinationMacAddressString(), DataTypeHelpers.getArpHardwareTypeString(frame.getArpHardwareType()), DataTypeHelpers.getArpProtocolTypeString(frame.getArpProtocolType()), frame.getArpHardwareAddressLength(), frame.getArpProtocolAddressLength(), DataTypeHelpers.getArpOperationString(frame.getArpOperation()), DataTypeHelpers.getMacAddressString(frame.getArpSenderHardwareAddress()), DataTypeHelpers.getIPv4AddressString(frame.getArpSenderProtocolAddress()), DataTypeHelpers.getMacAddressString(frame.getArpTargetHardwareAddress()), DataTypeHelpers.getIPv4AddressString(frame.getArpTargetProtocolAddress())});
                this.frameTableMap.put(frame, tableModel.getRowCount() - 1);
                index++;
            }
            this.jTableFrameTable.setModel(tableModel);
        } catch (DataTypeException ex) {
            AnalyserModuleException finalEx = new AnalyserModuleException("Failed to update analyser");
            finalEx.addSuppressed(ex);
            throw finalEx;
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSplitPane1 = new javax.swing.JSplitPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTableFrameTable = new javax.swing.JTable();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextPaneFrameData = new javax.swing.JTextPane();

        setName("ARP"); // NOI18N

        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setLastDividerLocation(100);

        jTableFrameTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane1.setViewportView(jTableFrameTable);

        jSplitPane1.setTopComponent(jScrollPane1);

        jTextPaneFrameData.setEditable(false);
        jTextPaneFrameData.setFont(new java.awt.Font("Monospaced", 0, 13)); // NOI18N
        jScrollPane2.setViewportView(jTextPaneFrameData);

        jSplitPane1.setRightComponent(jScrollPane2);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 300, Short.MAX_VALUE)
        );

        jSplitPane1.getAccessibleContext().setAccessibleName("");
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTable jTableFrameTable;
    private javax.swing.JTextPane jTextPaneFrameData;
    // End of variables declaration//GEN-END:variables

    public JTable getTable() {
        return this.jTableFrameTable;
    }
}

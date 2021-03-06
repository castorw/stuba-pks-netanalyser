package net.ctrdn.stuba.pks.netanalyser;

import java.awt.Frame;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.table.DefaultTableModel;
import net.ctrdn.stuba.pks.netanalyser.am.AnalyserModule;
import net.ctrdn.stuba.pks.netanalyser.annotation.Analyser;
import net.ctrdn.stuba.pks.netanalyser.annotation.FrameParser;
import net.ctrdn.stuba.pks.netanalyser.common.NonEditableColorableDefaultTableModel;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;

public class AboutDialog extends javax.swing.JDialog {

    private final AnalyserDialog analyserDialog;

    /**
     * Creates new form AboutDialog
     */
    public AboutDialog(AnalyserDialog parent, boolean modal) {
        super((Frame) parent, modal);
        this.analyserDialog = parent;
        initComponents();
    }

    public void showDialog() {
        this.setVisible(true);
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
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jSplitPane2 = new javax.swing.JSplitPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        analyserModuleTable = new javax.swing.JTable();
        jScrollPane2 = new javax.swing.JScrollPane();
        parserTable = new javax.swing.JTable();

        setTitle("About");
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentShown(java.awt.event.ComponentEvent evt) {
                formComponentShown(evt);
            }
        });

        jSplitPane1.setDividerLocation(128);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        jPanel1.setMinimumSize(new java.awt.Dimension(128, 128));
        jPanel1.setPreferredSize(new java.awt.Dimension(1051, 128));

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 1, 13)); // NOI18N
        jLabel1.setText("STUBA PKS Network Traffic Analyser, v 1.0.1");

        jLabel2.setText("Lubomir Kaplan <castor@castor.sk>, 2014");

        jLabel3.setText("Available analysers and parsers:");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3))
                .addContainerGap(749, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 60, Short.MAX_VALUE)
                .addComponent(jLabel3)
                .addContainerGap())
        );

        jSplitPane1.setTopComponent(jPanel1);

        jSplitPane2.setDividerLocation(250);
        jSplitPane2.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        analyserModuleTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(analyserModuleTable);

        jSplitPane2.setLeftComponent(jScrollPane1);

        parserTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane2.setViewportView(parserTable);

        jSplitPane2.setRightComponent(jScrollPane2);

        jSplitPane1.setRightComponent(jSplitPane2);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 543, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void formComponentShown(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentShown
        DefaultTableModel analyserTableModel = new NonEditableColorableDefaultTableModel(new Object[]{"Name", "Version", "Classpath", "Panel Priority", "Primary Filter"}, 0);
        for (AnalyserModule am : this.analyserDialog.getModules()) {
            Analyser annot = am.getClass().getDeclaredAnnotation(Analyser.class);
            analyserTableModel.addRow(new Object[]{annot.name(), annot.version(), am.getClass().getName(), am.getPanelOrderKey(), am.getFilterClass().getName()});
        }
        analyserModuleTable.setModel(analyserTableModel);
        analyserModuleTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        analyserModuleTable.getColumnModel().getColumn(0).setMaxWidth(200);
        analyserModuleTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        analyserModuleTable.getColumnModel().getColumn(1).setMaxWidth(100);
        analyserModuleTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        analyserModuleTable.getColumnModel().getColumn(3).setPreferredWidth(50);
        analyserModuleTable.getColumnModel().getColumn(3).setMaxWidth(100);

        DefaultTableModel parserTableModel = new NonEditableColorableDefaultTableModel(new Object[]{"Name", "Version", "Layer", "Layer Priority", "Classpath"}, 0);
        for (Map.Entry<Integer, List<Class<? extends EthernetFrame>>> entry : CaptureFileParser.getParsers().entrySet()) {
            for (Class<? extends EthernetFrame> parserClass : entry.getValue()) {
                FrameParser annot = parserClass.getDeclaredAnnotation(FrameParser.class);
                parserTableModel.addRow(new Object[]{annot.name(), annot.version(), "L" + annot.layer(), annot.orderKey(), parserClass.getName()});
            }
        }
        parserTable.setModel(parserTableModel);
        parserTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        parserTable.getColumnModel().getColumn(0).setMaxWidth(200);
        parserTable.getColumnModel().getColumn(1).setPreferredWidth(50);
        parserTable.getColumnModel().getColumn(2).setPreferredWidth(50);
        parserTable.getColumnModel().getColumn(3).setPreferredWidth(80);
        parserTable.getColumnModel().getColumn(1).setMaxWidth(50);
        parserTable.getColumnModel().getColumn(2).setMaxWidth(50);
        parserTable.getColumnModel().getColumn(3).setMaxWidth(100);

        this.jPanel1.removeAll();
        this.jPanel1.add(new JLabel(new ImageIcon(Launcher.getIconImage())));
    }//GEN-LAST:event_formComponentShown


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable analyserModuleTable;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JTable parserTable;
    // End of variables declaration//GEN-END:variables
}

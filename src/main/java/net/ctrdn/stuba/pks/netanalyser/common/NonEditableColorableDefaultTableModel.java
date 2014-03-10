package net.ctrdn.stuba.pks.netanalyser.common;

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;
import javax.swing.table.DefaultTableModel;

public class NonEditableColorableDefaultTableModel extends DefaultTableModel {
    
    private final Map<Integer, Color> colorMap = new HashMap<>();
    
    public NonEditableColorableDefaultTableModel(Object[] columns, int rowCount) {
        super(columns, rowCount);
    }
    
    public void setRowColor(int row, Color color) {
        if (this.colorMap.containsKey(row)) {
            this.colorMap.replace(row, color);
        } else {
            this.colorMap.put(row, color);
        }
        this.fireTableRowsUpdated(row, row);
    }
    
    public void removeRowColor(int row) {
        if (this.colorMap.containsKey(row)) {
            this.colorMap.remove(row);
            this.fireTableRowsUpdated(row, row);
        }
    }
    
    public void removeAllColors() {
        for (Map.Entry<Integer, Color> entry : this.colorMap.entrySet()) {
            this.removeRowColor(entry.getKey());
        }
    }
    
    public Color getRowColor(int row) {
        if (this.colorMap.containsKey(row)) {
            return this.colorMap.get(row);
        }
        return null;
    }
    
    @Override
    public boolean isCellEditable(int a, int b) {
        return false;
    }
}

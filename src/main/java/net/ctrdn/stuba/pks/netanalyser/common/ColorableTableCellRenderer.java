package net.ctrdn.stuba.pks.netanalyser.common;

import java.awt.Color;
import java.awt.Component;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

public class ColorableTableCellRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        NonEditableColorableDefaultTableModel model = (NonEditableColorableDefaultTableModel) table.getModel();
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        Color rowColor = model.getRowColor(row);
        if (rowColor != null) {
            component.setBackground(rowColor);
        } else if (isSelected) {
            component.setBackground(table.getSelectionBackground());
        } else {
            component.setBackground(table.getBackground());
        }
        return component;
    }
}

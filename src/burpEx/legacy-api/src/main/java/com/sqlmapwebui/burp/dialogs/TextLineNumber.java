package com.sqlmapwebui.burp.dialogs;

import javax.swing.*;
import java.awt.*;

/**
 * 行号显示组件
 */
public class TextLineNumber extends JPanel {
    private final JTextArea textArea;
    private final Font font;
    
    public TextLineNumber(JTextArea textArea) {
        this.textArea = textArea;
        this.font = new Font("Monospaced", Font.PLAIN, 12);
        setPreferredSize(new Dimension(45, Integer.MAX_VALUE));
        setBackground(new Color(240, 240, 240));
        
        textArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { repaint(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { repaint(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { repaint(); }
        });
    }
    
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        g.setFont(font);
        g.setColor(Color.GRAY);
        
        FontMetrics fm = g.getFontMetrics();
        int lineHeight = fm.getHeight();
        int ascent = fm.getAscent();
        
        int lines = textArea.getLineCount();
        for (int i = 0; i < lines; i++) {
            String lineNum = String.valueOf(i + 1);
            int y = (i + 1) * lineHeight - (lineHeight - ascent);
            g.drawString(lineNum, 5, y);
        }
    }
}

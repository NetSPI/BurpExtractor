package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class ButtonTabComponent extends JPanel {

    private ExtractorMainTab extractorMainTab;
    private int tabNum;
    public ButtonTabComponent(ExtractorMainTab extractorMainTab, int tabNum) {
        super(new FlowLayout(FlowLayout.LEFT, 0, 0));
        this.extractorMainTab = extractorMainTab;
        this.tabNum = tabNum;

        setOpaque(false);
        //make JLabel read titles from JTabbedPane
        JLabel label = new JLabel(Integer.toString(tabNum));
        add(label);
        //add more space between the label and the button
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
        //tab button
        JButton button = new TabButton();
        add(button);
}

    private class TabButton extends JButton implements ActionListener {

        public TabButton() {
            int size = 15;
            setPreferredSize(new Dimension(size, size));
            setToolTipText("close this tab");
            setText("x");
            //Make it transparent
            setContentAreaFilled(false);
            //No need to be focusable
            setFocusable(false);
            setBorder(BorderFactory.createEtchedBorder());
            setBorderPainted(false);
            //Making nice rollover effect
            //we use the same listener for all buttons
            addMouseListener(buttonMouseListener);
            setRolloverEnabled(true);
            //Close the proper tab by clicking the button
            addActionListener(this);
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            int index = extractorMainTab.getIndexOfTabComponent(ButtonTabComponent.this);
            if (index != -1) {
                extractorMainTab.removeTab(index);
                extractorMainTab.removeExtractor(tabNum);
                ExtractorMainTab.tabsRemoved++;
            }
        }
    }

    private final static MouseListener buttonMouseListener = new MouseAdapter() {
        public void mouseEntered(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(true);
            }
        }

        public void mouseExited(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(false);
            }
        }
    };
}

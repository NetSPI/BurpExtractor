package burp;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;

public class ExtractorMenu implements IContextMenuFactory {
    private ExtractorMainTab extractorMainTab;

    public ExtractorMenu(ExtractorMainTab extractorMainTab) {
        this.extractorMainTab = extractorMainTab;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        JMenuItem menuItem = new JMenuItem("Send to Extractor");


        menuItem.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
               IHttpRequestResponse[] messages = invocation.getSelectedMessages();

               // grab message if one is selected
               if (messages != null) {
                   extractorMainTab.addMessageFromMenu(messages[0]);
               }
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });


        menuItems.add(menuItem);
        return menuItems;
    }
}

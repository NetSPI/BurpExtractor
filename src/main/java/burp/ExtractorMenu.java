package burp;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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


		menuItem.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				IHttpRequestResponse[] messages = invocation.getSelectedMessages();

				// grab message if one is selected
				if (messages != null) {
					extractorMainTab.addMessageFromMenu(messages[0]);
				}
			}
		});

		menuItems.add(menuItem);
		return menuItems;
	}
}

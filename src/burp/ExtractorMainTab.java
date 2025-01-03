package burp;

import burp.persistence.ExtractorTabState;
import burp.persistence.Persistor;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;

public class ExtractorMainTab implements ITab {
	private HashMap extractorTabMap;
	private ExtractorSelectorTab selectorTab;
	private int tabNum = 0;
	static int tabsRemoved = 0;

	private JTabbedPane tabbedPane;

	public ExtractorMainTab(IBurpExtenderCallbacks callbacks) {
		this.extractorTabMap = new HashMap<Integer, ExtractorTab>();
		this.tabbedPane = new JTabbedPane();
		callbacks.customizeUiComponent(this.tabbedPane);
		callbacks.addSuiteTab(ExtractorMainTab.this);

		// Create selection tab
		this.selectorTab = new ExtractorSelectorTab(this, callbacks);
		this.tabbedPane.add(selectorTab.getUiComponent());
		this.tabbedPane.setTabComponentAt(0, new JLabel("Selection"));
	}

	public void addMessageFromMenu(IHttpRequestResponse message) {
		this.selectorTab.addMessageFromMenu(message);
		this.tabbedPane.setSelectedIndex(0);
	}

	public ExtractorTab createExtractorTab(byte[] response, byte[] request, String responseHost, String requestHost, IBurpExtenderCallbacks callbacks) {
		this.tabNum++;
		int index = (this.tabNum) - this.tabsRemoved;

		// Pause Persistor so that we don't write values before the tab loads
		Persistor.pause();
		ExtractorTab extractorTab = new ExtractorTab(response, request, responseHost, requestHost, callbacks);
		this.tabbedPane.add(extractorTab.getUiComponent());
		this.tabbedPane.setTabComponentAt(index, new ButtonTabComponent(this, this.tabNum));
		this.tabbedPane.setSelectedIndex(index);
		this.extractorTabMap.put(this.tabNum, extractorTab);

		// Now unpause, and write the addition
		Persistor.unpause();
		Persistor.persistExtractor();
		return extractorTab;
	}

	public ExtractorTab createExtractorTab(ExtractorTabState tabState, IBurpExtenderCallbacks callbacks) {
		ExtractorTab extractorTab = this.createExtractorTab(tabState.responseState.content.getBytes(),
				tabState.requestState.content.getBytes(),
				tabState.requestState.targetHost,
				tabState.responseState.targetHost,
				callbacks);
		// Pause Persistor so that we don't have unnecessary writes for each change we make
		Persistor.pause();
		extractorTab.setState(tabState);
		Persistor.unpause();
		Persistor.persistExtractor();
		return extractorTab;
	}

	public ArrayList<ExtractorTab> getExtractorTabs() {
		return new ArrayList<ExtractorTab>(this.extractorTabMap.values());
	}

	public int getIndexOfTabComponent(ButtonTabComponent button) {
		return this.tabbedPane.indexOfTabComponent(button);
	}

	public void removeTab(int index) {
		this.tabbedPane.remove(index);
	}

	public void removeExtractor(int tabNum) {
		this.extractorTabMap.remove(tabNum);
		Persistor.persistExtractor();
	}

	@Override
	public String getTabCaption() {
		return "Extractor-serate";
	}

	@Override
	public Component getUiComponent() {
		return this.tabbedPane;
	}
}

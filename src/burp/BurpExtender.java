package burp;

import burp.persistence.Persistor;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Extractor");

        // Create main extractor tab and an extractor, which actually does the work
        ExtractorMainTab extractorMainTab = new ExtractorMainTab(callbacks);
        Extractor extractor = new Extractor(extractorMainTab, callbacks);

        // Initialize the Persistor
        Persistor.init(extractorMainTab, callbacks);

        // Attempt to load a saved state
		Persistor.restoreExtractor();

        // Register Extractor as an HTTP listener
        callbacks.registerHttpListener(extractor);

        // Create menu item
        callbacks.registerContextMenuFactory(new ExtractorMenu(extractorMainTab));
    }
}
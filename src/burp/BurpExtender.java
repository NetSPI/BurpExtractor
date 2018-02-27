package burp;

public class BurpExtender implements burp.IBurpExtender {

    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Extractor");

        // Create main extractor tab and an extractor, which actually does the work
        ExtractorMainTab extractorMainTab = new ExtractorMainTab(callbacks);
        Extractor extractor = new Extractor(extractorMainTab, callbacks);

        // Register Extractor as an HTTP listener
        callbacks.registerHttpListener(extractor);

        // Create menu item
        callbacks.registerContextMenuFactory(new ExtractorMenu(extractorMainTab));
    }
}
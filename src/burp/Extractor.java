package burp;

import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Extractor implements IHttpListener {
    private ExtractorMainTab extractorMainTab;

    private IExtensionHelpers helpers;

    public Extractor(ExtractorMainTab extractorMainTab, IBurpExtenderCallbacks callbacks) {
        this.extractorMainTab = extractorMainTab;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
                byte[] requestBytes = messageInfo.getRequest();
                String request = this.helpers.bytesToString(requestBytes);

            // Loop over each tab to perform whatever replacement is necessary
            String extractedData;
            boolean edited = false;
            for (ExtractorTab extractorTab : this.extractorMainTab.getExtractorTabs()) {

                // Determine if this message is in scope, and the user wants requests edited at this time
                URL url = this.helpers.analyzeRequest(messageInfo.getHttpService(), requestBytes).getUrl();
                if (extractorTab.requestIsInScope(url,
                        messageInfo.getHttpService().getHost()) &&
                        extractorTab.shouldModifyRequests()) {

                    // Check if we have the necessary components to do replacement
                    String requestSelectionRegex = extractorTab.getRequestSelectionRegex();
                    extractedData = extractorTab.getExtractedData();
                    if (extractedData != "" && requestSelectionRegex != "") {
                        request = request.replaceAll(requestSelectionRegex, "$1" + extractedData + "$3");
                        edited = true;
                    }
                }
            }
            if (edited) {
                messageInfo.setRequest(request.getBytes());
            }
        } else if (!messageIsRequest) {

            byte[] responseBytes = messageInfo.getResponse();
            String response = this.helpers.bytesToString(responseBytes);

            // Loop over each tab, and grab whatever data item is necessary
            for (ExtractorTab extractorTab : this.extractorMainTab.getExtractorTabs()) {

                // Check if message is in scope
                URL url = this.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest()).getUrl();
                if (extractorTab.responseIsInScope(url,
                        messageInfo.getHttpService().getHost())) {

                    String regex = extractorTab.getResponseSelectionRegex();

                    // Grab text from response
                    if (regex.length() != 0) {
                        Pattern pattern = Pattern.compile(regex);
                        Matcher matcher = pattern.matcher(response);

                        // If we find a match in this response, replace the current data
                        if (matcher.find()) {
                            extractorTab.setExtractedData(matcher.group(2));
                        }
                    }
                }
            }
        }
    }
}

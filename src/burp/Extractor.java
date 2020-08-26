package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Extractor implements IHttpListener {
    private ExtractorMainTab extractorMainTab;
    private IExtensionHelpers helpers;
    private Logger logger;

    public Extractor(ExtractorMainTab extractorMainTab, IBurpExtenderCallbacks callbacks) {
        this.extractorMainTab = extractorMainTab;
        this.helpers = callbacks.getHelpers();

        this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
        Logger.setLogLevel(Logger.INFO);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            logger.debug("Processing request...");
            byte[] requestBytes = messageInfo.getRequest();
            String request = this.helpers.bytesToString(requestBytes);

            // Loop over each tab to perform whatever replacement is necessary
            String extractedData;
            boolean edited = false;
            for (ExtractorTab extractorTab : this.extractorMainTab.getExtractorTabs()) {

                // Determine if this message is in scope, and the user wants requests edited at this time
                URL url = this.helpers.analyzeRequest(messageInfo.getHttpService(), requestBytes).getUrl();
                if (extractorTab.requestIsInScope(url,
                        messageInfo.getHttpService().getHost(),
                        toolFlag) &&
                        extractorTab.shouldModifyRequests()) {
                    logger.debug("Request is in scope and Extractor tab is active.");

                    // Check if we have the necessary components to do replacement
                    String requestSelectionRegex = extractorTab.getRequestSelectionRegex();
                    extractedData = extractorTab.getDataToInsert();
                    if (!extractedData.equals("") && !requestSelectionRegex.equals("")) {
                        logger.debug("Performing replacement...");

                        // Only do this extra stuff if debugging is on
                        if (Logger.getLogLevel() >= Logger.DEBUG) {
                            Matcher matcher = Pattern.compile(requestSelectionRegex).matcher(request);
                            if (matcher.find()) {
                                logger.debug("Found a match for regex: " + requestSelectionRegex);
                            } else {
                                logger.debug("Did not find a match for regex: " + requestSelectionRegex);
                            }
                        }

                        request = request.replaceAll(requestSelectionRegex, "$1" + extractedData + "$3");
                        logger.debug("Finished replacement.");
                        edited = true;
                    }
                }
            }
            if (edited) {
                messageInfo.setRequest(request.getBytes());
            }
        } else if (!messageIsRequest) {

            logger.debug("Processing response...");
            byte[] responseBytes = messageInfo.getResponse();
            String response = this.helpers.bytesToString(responseBytes);

            // Loop over each tab, and grab whatever data item is necessary
            for (ExtractorTab extractorTab : this.extractorMainTab.getExtractorTabs()) {

                // Check if message is in scope
                URL url = this.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest()).getUrl();
                if (extractorTab.responseIsInScope(url,
                        messageInfo.getHttpService().getHost(),
                        toolFlag)) {
                    logger.debug("Response is in scope.");

                    String regex = extractorTab.getResponseSelectionRegex();

                    // Grab text from response
                    if (regex.length() != 0) {
                        Pattern pattern = Pattern.compile(regex);
                        Matcher matcher = pattern.matcher(response);

                        // If we find a match in this response, replace the current data
                        if (matcher.find()) {
                            logger.debug("Found a match for regex: " + regex);
                            extractorTab.setDataToInsert(matcher.group(2));
                        } else {
                            logger.debug("Did not find a match for regex: " + regex);
                        }
                    }
                }
            }
        }
    }
}

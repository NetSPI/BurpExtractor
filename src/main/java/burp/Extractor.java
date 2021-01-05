package burp;

import java.io.PrintWriter;
import java.net.URL;

public class Extractor implements IHttpListener {
    private ExtractorMainTab extractorMainTab;
    private IExtensionHelpers helpers;
    private Logger logger;

    public Extractor(ExtractorMainTab extractorMainTab, IBurpExtenderCallbacks callbacks) {
        this.extractorMainTab = extractorMainTab;
        this.helpers = callbacks.getHelpers();

        this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
        // Logger.setLogLevel(Logger.INFO);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
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
                    String[] requestSelectionRegex = extractorTab.getRequestSelectionRegex();
                    extractedData = extractorTab.getDataToInsert();
                    if (!extractedData.equals("")
                            && !requestSelectionRegex[0].equals("")
                            && !requestSelectionRegex[1].equals("")) {
                        logger.debug("Attempting replacement...");
                        int[] selectionBounds = Utils.getSelectionBounds(request, requestSelectionRegex[0], requestSelectionRegex[1]);
                        if (selectionBounds != null) {
                            logger.info("Replacing request after regex \"" + requestSelectionRegex[0] + "\" with \"" + extractedData + "\"");
                            int[] clHeaderBounds = Utils.getSelectionBounds(request, "(?i)\\r\\nContent-Length: ", "\\r\\n");
                            int[] headersEndBounds = Utils.getSelectionBounds(request, "\\r\\n\\r\\n", "");
                            // The following rewrite of the Content-Length
                            // header aims at maintaining the integrity between
                            // the header's claim and the rewritten content's
                            // length. The Content-Length rewrite can still be
                            // insufficient.  For example, the rewrite will not
                            // fix the MIME parts of a request body that carry
                            // own content length headers.  The Content-Length
                            // rewrite will not fix the claimed length of a
                            // chunk in a a chunked Transfer-Encoding.
                            String dangerousContentLengthRewrite = null;
                            if ((clHeaderBounds != null) && (headersEndBounds != null) &&
                                    (clHeaderBounds[0] < headersEndBounds[0]) && (headersEndBounds[0] < selectionBounds[0])) {
                                int origContentLength = Integer.parseInt(request.substring(clHeaderBounds[0],
                                            clHeaderBounds[1]));
                                int replacedLength = selectionBounds[1] - selectionBounds[0];
                                int replacedContentLength = origContentLength - replacedLength + extractedData.length();
                                if (origContentLength != replacedContentLength) {
                                    logger.info("Updating Content-Length: " + origContentLength + " with " + replacedContentLength);
                                    dangerousContentLengthRewrite = request.substring(0, clHeaderBounds[0]) + 
                                        Integer.toString(replacedContentLength) +
                                        request.substring(clHeaderBounds[1], selectionBounds[0]);
                                }
                            }
                            String contentBeforeRewrite;
                            if (dangerousContentLengthRewrite == null) {
                                contentBeforeRewrite = request.substring(0, selectionBounds[0]);
                            } else {
                                contentBeforeRewrite = dangerousContentLengthRewrite;
                            }
                            request = contentBeforeRewrite
                                    + extractedData
                                    + request.substring(selectionBounds[1], request.length());
                            edited = true;
                            logger.debug("Finished replacement");
                        }
                    }
                }
            }
            if (edited) {
                messageInfo.setRequest(this.helpers.stringToBytes(request));
            }
        } else if (!messageIsRequest) {

            logger.debug("Processing response...");
            byte[] responseBytes = messageInfo.getResponse();
            String response = this.helpers.bytesToString(responseBytes);

            // Loop over each tab, and grab whatever data item is necessary
            for (ExtractorTab extractorTab : this.extractorMainTab.getExtractorTabs()) {

                // Check if message is in scope
                IHttpService service = messageInfo.getHttpService();
                URL url;
                try {
                    url = new URL(service.getProtocol(), service.getHost(), service.getPort(), "");
                } catch(java.net.MalformedURLException e) {
                    throw new RuntimeException(e);
                }
                if (extractorTab.responseIsInScope(url,
                        service.getHost(),
                        toolFlag)) {
                    logger.debug("Response is in scope.");

                    String[] responseSelectionRegex = extractorTab.getResponseSelectionRegex();

                    // Grab text from response
                    if (responseSelectionRegex[0] != "" && responseSelectionRegex[1] != "") {
                        int[] selectionBounds = Utils.getSelectionBounds(response, responseSelectionRegex[0], responseSelectionRegex[1]);
                        if (selectionBounds != null) {
                            logger.info("Found a match in the response after regex \"" + responseSelectionRegex[0] + "\": \"" +
                                    response.substring(selectionBounds[0], selectionBounds[1]) + "\"");
                            extractorTab.setDataToInsert(response.substring(selectionBounds[0], selectionBounds[1]));
                        }
                    } else {
                        logger.debug("Before and after regex not defined");
                    }
                }
            }
        }
    }
}

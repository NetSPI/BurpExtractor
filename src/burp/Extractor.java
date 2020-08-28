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
					String[] requestSelectionRegex = extractorTab.getRequestSelectionRegex();
					extractedData = extractorTab.getDataToInsert();
					if (!extractedData.equals("")
							&& !requestSelectionRegex[0].equals("")
							&& !requestSelectionRegex[1].equals("")) {
						logger.debug("Attempting replacement...");
						int[] selectionBounds = Utils.getSelectionBounds(request, requestSelectionRegex[0], requestSelectionRegex[1]);
						if (selectionBounds != null) {
							logger.debug("Found a match");
							request = request.substring(0, selectionBounds[0])
									+ extractedData
									+ request.substring(selectionBounds[1], request.length());
							edited = true;
							logger.debug("Finished replacement");
						}
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

					String[] responseSelectionRegex = extractorTab.getResponseSelectionRegex();

					// Grab text from response
					if (responseSelectionRegex[0] != "" && responseSelectionRegex[1] != "") {
						int[] selectionBounds = Utils.getSelectionBounds(response, responseSelectionRegex[0], responseSelectionRegex[1]);
						if (selectionBounds != null) {
							logger.debug("Found a match");
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

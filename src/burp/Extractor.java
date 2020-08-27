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
					String[] requestSelectionRegex = extractorTab.getRequestSelectionRegex();
					extractedData = extractorTab.getDataToInsert();
					if (!extractedData.equals("")
							&& !requestSelectionRegex[0].equals("")
							&& !requestSelectionRegex[1].equals("")) {
						logger.debug("Performing replacement...");

						Matcher beforeMatcher = Pattern.compile(requestSelectionRegex[0]).matcher(request);
						if (beforeMatcher.find()) {
							int endOfBefore = beforeMatcher.end();
							Matcher afterMatcher = Pattern.compile(requestSelectionRegex[1]).matcher(request);
							if (afterMatcher.find(endOfBefore)) {
								logger.debug("Found a match");
								int startOfAfter = afterMatcher.start();
								request = request.substring(0, endOfBefore)
										+ extractedData
										+ request.substring(startOfAfter, request.length());
								edited = true;
                                logger.debug("Finished replacement.");
							}

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
						Matcher beforeMatcher = Pattern.compile(responseSelectionRegex[0]).matcher(response);
						if (beforeMatcher.find()) {
							int endOfBefore = beforeMatcher.end();
							Matcher afterMatcher = Pattern.compile(responseSelectionRegex[1]).matcher(response);
							if (afterMatcher.find(endOfBefore)) {
								logger.debug("Found a match");
								int startOfAfter = afterMatcher.start();
								extractorTab.setDataToInsert(response.substring(endOfBefore, startOfAfter));
							}
						}
					}
				}
			}
		}
	}
}

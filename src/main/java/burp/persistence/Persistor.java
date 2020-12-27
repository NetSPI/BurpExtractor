package burp.persistence;

import burp.*;
import com.google.gson.Gson;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.util.ArrayList;

public class Persistor {
	private static ExtractorMainTab mainTab;
	private static IBurpExtenderCallbacks callbacks;
	private static burp.Logger logger;
	private static IHttpService service;
	private static boolean paused = false;

	public static void init(ExtractorMainTab mainTab, IBurpExtenderCallbacks callbacks) {
		Persistor.mainTab = mainTab;
		Persistor.callbacks = callbacks;
		Persistor.service = callbacks.getHelpers().buildHttpService("com.netspi.burpExtractor", 65535, true);
		logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
	}

	public static void persistExtractor() {
		if (!paused) {
			ArrayList<ExtractorTabState> extractorState = new ArrayList<>();
			for (ExtractorTab tab : mainTab.getExtractorTabs()) {
				extractorState.add(tab.getTabState());
			}
			Gson gson = new Gson();
			String json = gson.toJson(extractorState.toArray());
			ExtractorSetting setting = null;
			try {
				setting = new ExtractorSetting(Persistor.service, json.getBytes(), callbacks);
			} catch (MalformedURLException exception) {
				logger.warn("Failed to save settings...");
				return;
			}
			callbacks.addToSiteMap(setting);
		}
	}

	private static IHttpRequestResponse getExistingSetting() {
		IHttpRequestResponse[] settings = callbacks.getSiteMap(Persistor.service.toString() + ExtractorSetting.settingFile);
		if (settings.length > 0) {
			return settings[0];
		} else {
			return null;
		}
	}

	public static void restoreExtractor() {
		Gson gson = new Gson();
		IHttpRequestResponse currentSetting = getExistingSetting();
		if (currentSetting != null) {
			ExtractorTabState[] tabs = gson.fromJson(callbacks.getHelpers().bytesToString(currentSetting.getResponse()),
					ExtractorTabState[].class);
			for (ExtractorTabState state : tabs) {
				logger.info("Loading tab...");
				mainTab.createExtractorTab(state, callbacks);
			}
		}
	}

	public static void pause() {
		paused = true;
	}

	public static void unpause() {
		paused = false;
	}
}

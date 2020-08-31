package burp.persistence;

import burp.ExtractorMainTab;
import burp.ExtractorTab;
import burp.IBurpExtenderCallbacks;
import burp.Logger;
import com.google.gson.Gson;

import java.io.PrintWriter;
import java.util.ArrayList;

public class Persistor {
	final static String settingName = "EXTRACTOR_STATE";
	private static ExtractorMainTab mainTab;
	private static IBurpExtenderCallbacks callbacks;
	private static burp.Logger logger;
	private static boolean paused = false;

	public static void init(ExtractorMainTab mainTab, IBurpExtenderCallbacks callbacks) {
		Persistor.mainTab = mainTab;
		Persistor.callbacks = callbacks;
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
			callbacks.saveExtensionSetting(settingName, json);
		}
	}

	public static void restoreExtractor() {
		Gson gson = new Gson();
		String extractorStateJson = callbacks.loadExtensionSetting(settingName);
		if (extractorStateJson != null) {
			ExtractorTabState[] tabs = gson.fromJson(extractorStateJson, ExtractorTabState[].class);
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

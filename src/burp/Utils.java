package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {
	public static int[] getSelectionBounds(String request, String beforeRegex, String afterRegex) {
		int[] selectionBounds = new int[2];
		Matcher beforeMatcher = Pattern.compile(beforeRegex).matcher(request);
		if (beforeMatcher.find()) {
			selectionBounds[0] = beforeMatcher.end();
			Matcher afterMatcher = Pattern.compile(afterRegex).matcher(request);
			if (afterMatcher.find(selectionBounds[0])) {
				selectionBounds[1] = afterMatcher.start();
				return selectionBounds;
			}
		}
		return null;
	}
}

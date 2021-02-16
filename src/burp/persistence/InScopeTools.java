package burp.persistence;

public class InScopeTools {
	public boolean allTools;
	public boolean proxy;
	public boolean scanner;
	public boolean intruder;
	public boolean repeater;
        public boolean extender;

	public InScopeTools(boolean allTools,
						boolean proxy,
						boolean scanner,
						boolean intruder,
                                                boolean repeater,
						boolean extender) {
		this.allTools = allTools;
		this.proxy = proxy;
		this.scanner = scanner;
		this.intruder = intruder;
		this.repeater = repeater;
                this.extender = extender;
	}
}

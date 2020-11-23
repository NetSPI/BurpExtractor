package burp.persistence;

public class RequestResponseState {
	public InScopeTools inScopeTools;
	public boolean useSuiteScope;
	public String targetHost;
	public boolean useRegex;
	public String beforeRegex;
	public String afterRegex;
	public String content;

	public RequestResponseState(InScopeTools inScopeTools,
								boolean useSuiteScope,
								String targetHost,
								boolean useRegex,
								String beforeRegex,
								String afterRegex,
								String content) {
		this.inScopeTools = inScopeTools;
		this.useSuiteScope = useSuiteScope;
		this.targetHost = targetHost;
		this.useRegex = useRegex;
		this.beforeRegex = beforeRegex;
		this.afterRegex = afterRegex;
		this.content = content;
	}
}

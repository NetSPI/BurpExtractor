package burp.persistence;

public class ExtractorTabState {
	public RequestResponseState requestState;
	public RequestResponseState responseState;

	public ExtractorTabState(RequestResponseState requestState,
							 RequestResponseState responseState) {
		this.requestState = requestState;
		this.responseState = responseState;
	}
}

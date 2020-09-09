package burp.persistence;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.net.MalformedURLException;
import java.net.URL;

public class ExtractorSetting implements IHttpRequestResponse {

	private IHttpService service;
	private byte[] request;
	private byte[] response;
	public static final String settingFile = "/setting";

	public ExtractorSetting(IHttpService service, byte[] setting, IBurpExtenderCallbacks callbacks) throws MalformedURLException {
		this.request = callbacks.getHelpers().buildHttpRequest(new URL(service.getProtocol(), service.getHost(), settingFile));
		this.service = service;
		this.response = setting;
	}

	@Override
	public byte[] getRequest() {
		return this.request;
	}

	@Override
	public void setRequest(byte[] message) {
		this.request = message;
	}

	@Override
	public byte[] getResponse() {
		return this.response;
	}

	@Override
	public void setResponse(byte[] message) {
		this.response = message;
	}

	@Override
	public String getComment() {
		return null;
	}

	@Override
	public void setComment(String comment) {

	}

	@Override
	public String getHighlight() {
		return null;
	}

	@Override
	public void setHighlight(String color) {

	}

	@Override
	public IHttpService getHttpService() {
		return this.service;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		this.service = httpService;
	}
}
package burp;

import static org.junit.Assert.assertEquals;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;

import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.UnsupportedEncodingException;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;

@RunWith(MockitoJUnitRunner.class)
public class ExtractorTest {
    @Mock
    IHttpRequestResponse resp, req;
    
    @Mock
    IHttpService service;
    
    @Mock
    ExtractorMainTab mainTab;

    @Mock
    IExtensionHelpers helpers;

    @Mock
    IBurpExtenderCallbacks callbacks;

    @Mock
    ExtractorTab pathReplacer, tokenReplacer;

    @Mock
    IRequestInfo reqInfo;

    @Captor
    ArgumentCaptor<String> respCaptor;

    @Captor
    ArgumentCaptor<byte[]> reqCaptor;

    String protocol;
    String host;
    int port;
    String hostPort;
    String urlStr;
    java.net.URL reqUrl;

    String path, detectPathFixture;
    String[] rePathResp, rePathReq;

    String token, detectTokenFixture;
    String[] reTokenResp, reTokenReq;
    int contentLength;

    String respFixture;
    byte[] respFixtureBytes;

    String reqFixture;
    byte[] reqFixtureBytes;

    ByteArrayOutputStream baos;

    @Before
    public void setUp()
            throws MalformedURLException, UnsupportedEncodingException {
        protocol = "https";
        host = "example.test";
        port = 10081;
        hostPort = host + ":" + port;

        detectPathFixture = "/wps/myportal/quux/actions";
        detectTokenFixture = "123456";
        respFixture = "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html\r\n" +
            "\r\n" +
            "<html><head>\r\n" +
            "<script>var portalAction = \"" + detectPathFixture + ".SubmitAction==/\";</script>\r\n" +
            "</head><body>\r\n" +
            "<form><input name=\"test.example.TOKEN\" value=\"" + detectTokenFixture + "\">\r\n" +
            "</body></html>\r\n";
        respFixtureBytes = respFixture.getBytes("UTF-8");

        path = "/wps/myportal/foobar/!ut/p/z1/pZXXXXXXXB=EPortletAction!com.YYYY.ZZZZ.actions.SubmitAction==/";
        urlStr = protocol + "://" + hostPort + path;
        reqUrl = new java.net.URL(urlStr);
        token = "0d5b1d88d9d0a95775781153773dff1c";
        contentLength = 977;

        reqFixture = "POST " + path + " HTTP/1.1\r\n" +
                "Host: " + hostPort + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: " + contentLength + "\r\n" +
                "Cookie: quux=baz\r\n" +
                "\r\n" +
                "test.example.TOKEN=" + token + "&param=123";
        reqFixtureBytes = reqFixture.getBytes("UTF-8");

        rePathResp = new String[] {"var portalAction = \"", "\\.SubmitAction==/\""};
        rePathReq = new String[] {"^POST ", "\\.SubmitAction==/"};

        reTokenResp = new String[] {"\\<input name=\"test\\.example\\.TOKEN\" value=\"", "\""};
        reTokenReq = new String[] {"test\\.example\\.TOKEN=", "\\&"};

        baos = new ByteArrayOutputStream();
    }

    private static Answer<String> bytesToString() {
        return new Answer<String>() {
            public String answer(InvocationOnMock invocation) {
                byte[] ba = (byte[]) (invocation.getArguments()[0]);
                StringBuilder sb = new StringBuilder(ba.length);
                for(int i = 0; i < ba.length; i++) {
                    sb.append((char)(ba[i]));
                }
                return sb.toString();
            }
        };
    }

    private static Answer<byte[]> stringToBytes() {
        return new Answer<byte[]>() {
            public byte[] answer(InvocationOnMock invocation) {
                String s = (String) (invocation.getArguments()[0]);
                byte[] ba = new byte[s.length()];
                for(int i = 0; i < ba.length; i++) {
                    ba[i] = (byte)(s.charAt(i));
                }
                return ba;
            }
        };
    }

    private void stub(ExtractorTab[] tabs) {
        when(mainTab.getExtractorTabs()).thenReturn(new ArrayList<ExtractorTab>(Arrays.asList(tabs)));

        when(resp.getResponse()).thenReturn(respFixtureBytes);
        when(req.getRequest()).thenReturn(reqFixtureBytes);

        when(service.getProtocol()).thenReturn(protocol);
        when(service.getHost()).thenReturn(host);
        when(service.getPort()).thenReturn(port);

        when(resp.getHttpService()).thenReturn(service);
        when(req.getHttpService()).thenReturn(service);

        when(helpers.bytesToString(any(byte[].class))).thenAnswer(bytesToString());
        when(helpers.stringToBytes(any(String.class))).thenAnswer(stringToBytes());

        when(helpers.analyzeRequest(any(IHttpService.class), any(byte[].class))).thenReturn(reqInfo);
        when(reqInfo.getUrl()).thenReturn(reqUrl);

        when(pathReplacer.requestIsInScope(any(java.net.URL.class), any(String.class), anyInt())).thenReturn(true);
        when(pathReplacer.responseIsInScope(any(java.net.URL.class), any(String.class), anyInt())).thenReturn(true);
        when(pathReplacer.shouldModifyRequests()).thenReturn(true);
        when(pathReplacer.getResponseSelectionRegex()).thenReturn(rePathResp);
        when(pathReplacer.getRequestSelectionRegex()).thenReturn(rePathReq);
        when(pathReplacer.getDataToInsert()).thenReturn(detectPathFixture);

        when(callbacks.getHelpers()).thenReturn(helpers);
        when(callbacks.getStdout()).thenReturn(baos);
    }

    @Test
    public void RewritePathTest()
            throws UnsupportedEncodingException {
        stub(new ExtractorTab[] { pathReplacer });

        Extractor extractor = new Extractor(mainTab, callbacks);

        extractor.processHttpMessage(0, false, resp);

        verify(pathReplacer).setDataToInsert(respCaptor.capture());
        assertEquals(detectPathFixture, respCaptor.getValue());

        extractor.processHttpMessage(0, true, req);

        verify(req).setRequest(reqCaptor.capture());

        assertEquals(reqFixture
                    .replace(path, detectPathFixture + ".SubmitAction==/"),
                new String(reqCaptor.getValue(), "UTF-8"));

        assertEquals("Found a match in the response after regex \"var portalAction = \"\": \"" + detectPathFixture + "\"\n" +
                "Replacing request after regex \"^POST \" with \"" + detectPathFixture + "\"\n",
                baos.toString("UTF-8"));
    }

    @Test
    public void RewritePathAndContentTest()
            throws UnsupportedEncodingException {
        stub(new ExtractorTab[] { pathReplacer, tokenReplacer });

        when(tokenReplacer.requestIsInScope(any(java.net.URL.class), any(String.class), anyInt())).thenReturn(true);
        when(tokenReplacer.responseIsInScope(any(java.net.URL.class), any(String.class), anyInt())).thenReturn(true);
        when(tokenReplacer.shouldModifyRequests()).thenReturn(true);
        when(tokenReplacer.getResponseSelectionRegex()).thenReturn(reTokenResp);
        when(tokenReplacer.getRequestSelectionRegex()).thenReturn(reTokenReq);
        when(tokenReplacer.getDataToInsert()).thenReturn(detectTokenFixture);

        Extractor extractor = new Extractor(mainTab, callbacks);

        extractor.processHttpMessage(0, false, resp);

        verify(pathReplacer).setDataToInsert(respCaptor.capture());
        assertEquals(detectPathFixture, respCaptor.getValue());

        verify(tokenReplacer).setDataToInsert(respCaptor.capture());
        assertEquals(detectTokenFixture, respCaptor.getValue());

        extractor.processHttpMessage(0, true, req);

        verify(req).setRequest(reqCaptor.capture());
        
        assertEquals(reqFixture
                    .replace(path, detectPathFixture + ".SubmitAction==/")
                    .replace(token, detectTokenFixture)
                    .replace("" + contentLength, "" + (contentLength - token.length() + detectTokenFixture.length())),
                new String(reqCaptor.getValue(), "UTF-8"));

        assertEquals("Found a match in the response after regex \"var portalAction = \"\": \"" + detectPathFixture + "\"\n" +
                "Found a match in the response after regex \"\\<input name=\"test\\.example\\.TOKEN\" value=\"\": \"" + detectTokenFixture + "\"\n" +
                "Replacing request after regex \"^POST \" with \"" + detectPathFixture + "\"\n" +
                "Replacing request after regex \"test\\.example\\.TOKEN=\" with \"" + detectTokenFixture + "\"\n" +
                "Updating Content-Length: " + contentLength + " with " + (contentLength - token.length() + detectTokenFixture.length()) + "\n",
                baos.toString("UTF-8"));
    }
}

# Burp Extractor
Burp Extractor is intended to be used as a one-size-fits-all tool for extracting data from HTTP responses to be reused in HTTP requests. This can be items such as CSRF tokens, Auth Bearer tokens, timestamps, etc. The extension uses regex to extract needed data from responses, and will insert extracted data into any HTTP request sent through Burp which matches a second regex.

## Send Request/Response to Extractor
Send requests and responses to Extractor using a context menu item.
<img src="https://github.com/NetSPI/BurpExtractor/blob/master/images/contextMenu.PNG?raw=true">

## Select Request/Response Pair
Select requests and responses using a Comparer-like interface.
<img src="https://github.com/NetSPI/BurpExtractor/blob/master/images/requestResponseSelection.PNG?raw=true">

## Highlight Data to Extract
Highlight data in Burp's text editor to automatically create regex strings to extract and insert data. Highlight text in the response to select the location of data to be extracted, and highlight text in the request to select the location that data should be inserted. Configure any necessary scope options or tailor your regex to suit your specific needs. Once a tab in Extractor is turned on, it must capture a response matching the response regex string before inserting data into requests.
<img src="https://github.com/NetSPI/BurpExtractor/blob/master/images/regexSelection.PNG?raw=true">

## Simple Demo of Extractor
<img src="https://github.com/NetSPI/BurpExtractor/blob/master/images/captioned_walkthrough.gif?raw=true">

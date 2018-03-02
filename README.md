# Burp Extractor
Burp Extractor is intended to be used as a one-size-fits-all tool for extracting data from HTTP responses to be reused in HTTP requests. This can be items such as CSRF tokens, Auth Bearer tokens, timestamps, etc. The extension uses regex to select needed data in responses, and will insert captured data into any HTTP request sent through Burp which matches a second regex. 

## Select Request/Response Pair
Select requests and responses using a Comparer-like interface.
<img src="https://github.com/NetSPI/BurpExtractor/blob/master/images/requestResponseSelection.PNG?raw=true">

## Highlight Data to Extract
Highlight data in Burp's text editor to automatically create regex strings to extract and insert data.
<img src="https://github.com/NetSPI/BurpExtractor/blob/master/images/regexSelection.PNG?raw=true">

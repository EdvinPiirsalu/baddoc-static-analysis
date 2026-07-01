# baddoc-static-analysis
Static malware analysis of a malicious Microsoft Office document using VirusTotal, ExifTool, and string analysis.


# Static Analysis of a Suspicious Document (baddoc.doc)

## Static Analysis

Static analysis is the process of examining a file without executing it. The goal is to identify indicators of compromise (IOCs), suspicious code, metadata, and other characteristics that may indicate malicious behavior.

The sample analyzed is `baddoc.doc`.

## 1. Hash Analysis and VirusTotal

The first step is to generate cryptographic hashes of the file to uniquely identify it.

Using the terminal:

```
md5sum baddoc.doc
```

Output:

```
a3b613d128aace09241504e8acc678c2
```

Next, generate the SHA-256 hash:

```
sha256sum baddoc.doc
```

Output:

```
8b92c23b29422131acc150fa1ebac67e1b0b0f8cfc1b727805b842a88de447de
```


<img width="1807" height="1132" alt="1" src="https://github.com/user-attachments/assets/357e2ca1-e1e3-4c27-8fc7-1591450c8fab" />


The MD5 hash is then searched on VirusTotal.


<img width="2367" height="1117" alt="2" src="https://github.com/user-attachments/assets/ce9432d0-1622-4c69-84ad-c735c5250f62" />


VirusTotal reports that 49 security vendors identify the file as malicious, strongly suggesting that the document contains malware.


<img width="2511" height="1212" alt="3" src="https://github.com/user-attachments/assets/0af9e6cc-4b68-4036-8275-81d7af32a9e6" />



The Details tab reveals:
- MD5 and SHA-256 hashes
- File creation and submission history
- First seen and first submission dates
- Known filenames used by the sample

<img width="2535" height="1217" alt="4" src="https://github.com/user-attachments/assets/effb1e48-7d80-4262-afdf-a0b536619318" />


The Relations tab reveals IP addresses contacted by the malware.


<img width="2502" height="1207" alt="5" src="https://github.com/user-attachments/assets/4a69970f-8e8f-4eae-af1f-5441677d074e" />


The Behavior tab displays sandbox analysis, including:
- DNS resolutions
- Network traffic
- Contacted IP addresses
- Files dropped
- Registry modifications
- Process tree

<img width="2517" height="1026" alt="6" src="https://github.com/user-attachments/assets/b56efe54-770d-488c-a27c-01279564050b" />


<img width="2360" height="1202" alt="7" src="https://github.com/user-attachments/assets/982afeb5-2542-4bbd-956b-0555e34e980d" />



<img width="1945" height="736" alt="8" src="https://github.com/user-attachments/assets/e7b5593c-30f2-4a20-b2ab-330dd939b9dd" />



<img width="2432" height="892" alt="9" src="https://github.com/user-attachments/assets/6776e22e-6a1c-443b-88f9-d509ea24e083" />


This information provides valuable insight into the malware's behavior without requiring local execution.

## 2. Metadata Analysis with ExifTool

Next, the document metadata is examined using:

```
exiftool baddoc.doc
```

ExifTool provides detailed metadata, including:
- File name
- File size
- Modification date
- File permissions
- File type
- File extension
- Language
- Template used
- Creation and modification dates


Several suspicious findings stand out:
- The document language is Russian, which may indicate its origin or intended target.
- The template is .dotm, where the "m" indicates that the template supports macros. Since malicious Office documents commonly abuse macros to execute code, this significantly increases suspicion.


<img width="2530" height="1202" alt="10" src="https://github.com/user-attachments/assets/706e9979-2f24-4fc6-bf54-e2cac47e001d" />


Overall, ExifTool provides useful contextual information that helps identify potentially malicious documents.

## 3. String Analysis

The next step is to extract readable strings from the file:

```
strings -n 5 baddoc.doc
```


<img width="2491" height="1064" alt="11" src="https://github.com/user-attachments/assets/fc5d0049-bddb-4235-8712-54f35a00fcf8" />



This command displays all printable strings that are five or more characters long (>=5).

During this analysis, I look for indicators such as:
- IP addresses
- URLs and domains
- Suspicious file paths
- PowerShell commands
- File locations that are suspicious
- Malicious files and codes
- Network communication
- User-Agent strings

Several suspicious indicators were identified:

- `\AppData\Local\Temp\`
  - Indicates the malware may write files to the temporary directory.

 
<img width="2511" height="1122" alt="12" src="https://github.com/user-attachments/assets/ab8b03bc-1ad3-4221-8197-82ccedda78fa" />

    
- `SELECT * FROM Win32_OperatingSystem`
  - A query commonly used to gather system information.
 
<img width="1427" height="616" alt="13" src="https://github.com/user-attachments/assets/0793010e-e683-4cf7-a0b2-9886b2a58a12" />


- IP address `91.220.131...`
  - A hardcoded IP address used for network communication.
 
<img width="1790" height="637" alt="14" src="https://github.com/user-attachments/assets/a4148895-36cb-49c2-9868-4177c9ce8b7f" />



- `If objXMLHTTP.Status = 200 Then`
  - Indicates the document performs HTTP requests and executes additional code after receiving a successful response.
 

<img width="1692" height="972" alt="15" src="https://github.com/user-attachments/assets/3a58a536-e52f-4d3d-b67c-a89a399498c0" />

  
- `$url = 'http://91.220.131...'`
  - Same reference to the same malicious IP address.
 
<img width="1931" height="965" alt="16" src="https://github.com/user-attachments/assets/0c74f9fd-e60b-4a8a-8f2c-b7f6daf828ff" />


- `ping 1.1.2.2 -n`
  - Sleep technique commonly used by malware to delay execution and evade automated sandbox detection.
 
<img width="1767" height="1075" alt="17" src="https://github.com/user-attachments/assets/8fbb293d-6166-475c-b265-26fa2dd500c6" />



- `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X...)`
  - The presence of an HTTP User-Agent string inside an Office document means that it communicates with remote servers.
 

<img width="2042" height="1082" alt="18" src="https://github.com/user-attachments/assets/e5c15c37-51f1-4ffe-b248-746ba73be80d" />


- `Start-Sleep -s 15`
  - A PowerShell command that delays execution, another common anti-analysis technique.
 
<img width="1242" height="990" alt="19" src="https://github.com/user-attachments/assets/955477df-4e83-4798-a260-090a0a1d7d22" />



- `AutoOpen`
  - A Microsoft Office macro function that executes automatically when the document is opened or when macros are enabled.
 
<img width="1592" height="965" alt="20" src="https://github.com/user-attachments/assets/89bb0212-9c04-46ec-adb3-9c36261bbe9f" />



## Conclusion

The static analysis identified numerous indicators commonly associated with malicious Office documents.

These include:
- Detection by 49 antivirus vendors on VirusTotal.
- A macro-enabled template (.dotm).
- Hardcoded IP addresses.
- Network communication through HTTP requests.
- PowerShell commands.
- Queries for system reconnaissance.
- Automatic execution using the AutoOpen macro.
- Delayed execution techniques intended to evade sandbox detection.

Based on these findings, it is reasonable to conclude that baddoc.doc is a malicious document designed to execute malware once the embedded macros are enabled.

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

VirusTotal reports that 49 security vendors identify the file as malicious, strongly suggesting that the document contains malware.

The Details tab reveals:
- MD5 and SHA-256 hashes
- File creation and submission history
- First seen and first submission dates
- Known filenames used by the sample

The Relations tab reveals IP addresses contacted by the malware.

The Behavior tab displays sandbox analysis, including:
- DNS resolutions
- Network traffic
- Contacted IP addresses
- Files dropped
- Registry modifications
- Process tree

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

Overall, ExifTool provides useful contextual information that helps identify potentially malicious documents.

## 3. String Analysis

The next step is to extract readable strings from the file:

```
strings -n 5 baddoc.doc
```

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
- `SELECT * FROM Win32_OperatingSystem`
  - A query commonly used to gather system information.
- IP address `91.220.131...`
  - A hardcoded IP address used for network communication.
- `If objXMLHTTP.Status = 200 Then`
  - Indicates the document performs HTTP requests and executes additional code after receiving a successful response.
- `$url = 'http://91.220.131...'`
  - Same reference to the same malicious IP address.
- `ping 1.1.2.2 -n`
  - Sleep technique commonly used by malware to delay execution and evade automated sandbox detection.
- `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X...)`
  - The presence of an HTTP User-Agent string inside an Office document means that it communicates with remote servers.
- `Start-Sleep -s 15`
  - A PowerShell command that delays execution, another common anti-analysis technique.
- `AutoOpen`
  - A Microsoft Office macro function that executes automatically when the document is opened or when macros are enabled.

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

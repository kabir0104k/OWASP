### Bug Bounty Checklist

### This Checklist May Help You To Have A Good Methodology For Bug Bounty Hunting

Checklist 1
 
> Create 2 accounts on the same website if it has login functionality You can use this [Extension](https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers) to use same browser for creating different account on the same website.

> Try directory brute forcing using tools like "Dirsearch", " FeroxBuster", "Ffuf", might be possible some directory may reveal sensitive information.


```bash
Login Page

> Session Expiration
> Improper Session Validation
> OAuth Bypass (It includes features like login with Google, Microsoft, Instagram or any)
> OAuth Token Stealing
> Authentication Bypass
> Privilege Escalation
> SQLi
```
-------

```bash
Registration Page

> XML File Upload using SVG (If website asks for Documents upload or Profile Upload then you can try this)
> Bypassing Limitation on File Types to Upload (If they just allow jpg,png then try to upload .php or .py)
> Bypassing Mobile or Email Verification
> Brute Forcing OTP Sent
> Try inserting XSS payload wherever possible (Like if you can enter XSS payload in First Name | Last Name |
 Address etc text box make sure to enter because sometimes it may reflect somewhere else or maybe it's stored XSS).
```
-------
```bash
Forgot Password Page

> Password Reset Poisoning (Kind of similar way we do Host Header Injection)
> Reset Token/Link Expiring (Maybe they pay)
> Reset Token Leaks (This can happen when some website interacts to third party services at that point of time maybe
> Password reset token is sent via referrer header part and maybe it can leak)
> Check for Subdomain_Takeover
> Check for Older Version of Service is used by your target and if they do try to find existing exploit for the target.
> [Check For Subdomain Takeover](https://youtu.be/ds7GHLXi5dM)
> [Check for Older Version of Service is used by your target and if they do try to find existing exploit for the target](https://youtu.be/aJqLoXLr5xo)
```
-------
Checklist 2
> Test for Credentials Transported Over Encryption
* When you submit your login/registration data try intercepting the request and changing the requests method. Post to Get / Get to Post.
 If any point of time you find the data submitted by user are transported without encryption you can mark this as low-level bug.
> Test for Default Credentials on admin page/console or any sign in panel.
* Try submitting default username passwords like "admin":"admin", "admin":"password"
> Bypassing the Authentication
* Forced Browsing: Directly visiting the section of the website which requires authentication. For example, if you have to login at https://spinthehack.in/login to visit https://spinthehack.in/information then if you directly type https://spinthehack.in/information in the address bar of your browser and if you get the access to the website. It is Forced Browsing
* Parameter Modification: Try changing Response which comes from the server for example, if your server response https://spinthehack.in/auth=false then try changing the parameter auth=false to auth=true.
* Session ID Brute Forcing: Maybe sometimes it may work.
* SQL Injection: This method may depend on sql injection vuln.
> Check for Broken Access Control
> Remember Password Checking
* Check that is password being stored in the Cookies or being constantly transferred in every request of the website.
The credentials should only be sent in login phase.
> Check for Directory Traversal Includes File Input
* You have to check each and every input which your website and its directories take from user
> Example
* https://spinthehack.in/getuserprofile.jsp>?item=manager.html https://spinthehack.in/index.php?file=content
* https://spinthehack.in/getuserprofile.jsp?item=.../../../../etc/passwd https://spinthehack.in/index.php?file=https://evil.com/
* [Medium](https://medium.com/@nerdy_researcher/directory-traversal-aka-path-traversal-c76dc7bbe61#:~:text=What%20is%20Directory%20Traversal%3F,and%20sensitive%20operating%20system%20files)
> Checking for Privilege Escalation
* You can check for this at some place like if user can make payment, adding something, sending message to someone
* You can intercept request of two different sets of account and try modifying parameter like grp, id, role if they exist.
* https://shahjerry33.medium.com/privilege-escalation-hello-admin-a53ac14fd388
> Check for Insecure Direct Object Reference
* You can try for getting access to other user data by changing parameter in url.
> Example
* https://spinthehack.in/user?id=1 
* https://spinthehack.in/user?id=2
> Check for Bypassing Session Management Object
> P3, P4 category check
* Set-cookie is secure or not?
* Are cookies transmitted in encrypted manner?
* Make sure cookies are not same every time when you browse website?
> P2, P1 category check
* Sometimes website can leak their token structure/information, try to find it?
* Session ID predictability?
* Brute Forcing Session ID?
> Check for CSRF
> Check for XSS (Stored, Reflected, Blind)
> Check for SQL Injection (Blind, In band, Out band, Error Based etc)
> Check for XML Injection
> Check for File Upload
> Check for Open Redirection/ Client-Side Open Redirection
* https://corneacristian.medium.com/top-25-open-redirect-bug-bounty-reports-5ffe11788794
> Checking for WebSocket's Vulnerabilities
> Check for Code Execution
* https://medium.com/@ashishrohra/remote-code-execution-explaination-writeups-and-tools-a8e4c3362259
> Check for Server-Side Request Forgery
> Check for Command Injection
* https://medium.com/ax1al/os-command-injection-beginners-guide-637e1eed1fde
> Checking for Business Logic Flaws
* https://medium.com/armourinfosec/exploiting-business-logic-vulnerabilities-234f97d6c4c0
> Checking for LDAP injection
* https://medium.com/@hunter_55/ldap-admin-account-bypassed-2cc8b264d66e
> Check for HTTP Parameter Pollution
* https://shahjerry33.medium.com/http-parameter-pollution-its-contaminated-85edc0805654
> Check for HTTP Request Smuggling
```
# Table of Contents

* Recon on wildcard domain
* Single domain
* Information Gathering
* Configuration Management
* Secure Transmission
* Authentication
* Session Management
* Authorization
* Data Validation
* Denial of Service
* Business Logic
* Cryptography
* Risky Functionality - File Uploads
* Risky Functionality - Card Payment
* HTML 5


# <a name="Recon_on_wildcard_domain">Recon on wildcard domain</a>  

- [ ] Run amass  
- [ ] Run subfinder  
- [ ] Run assetfinder  
- [ ] Run dnsgen  
- [ ] Run massdns  
- [ ] Use httprobe  
- [ ] Run aquatone (screenshot for alive host)  

# <a name="Single Domain">Single Domain</a>

> Scanning  

- [ ] Nmap scan   
- [ ] Burp crawler   
- [ ] ffuf (directory and file fuzzing)
- [ ] hakrawler/gau/paramspider  
- [ ] Linkfinder  
- [ ] Url with Android application   

> Manual checking  

- [ ] Shodan  
- [ ] Censys  
- [ ] Google dorks  
- [ ] Pastebin  
- [ ] Github  
- [ ] OSINT     

# <a name="Information">Information Gathering</a>
- [ ] Manually explore the site  
- [ ] Spider/crawl for missed or hidden content  
- [ ] Check for files that expose content, such as robots.txt, sitemap.xml, .DS_Store  
- [ ] Check the caches of major search engines for publicly accessible sites  
- [ ] Check for differences in content based on User Agent (eg, Mobile sites, access as a Search engine Crawler)  
- [ ] Perform Web Application Fingerprinting  
- [ ] Identify technologies used  
- [ ] Identify user roles  
- [ ] Identify application entry points  
- [ ] Identify client-side code  
- [ ] Identify multiple versions/channels (e.g. web, mobile web, mobile app, web services)  
- [ ] Identify co-hosted and related applications  
- [ ] Identify all hostnames and ports  
- [ ] Identify third-party hosted content  
- [ ] Identify Debug parameters  


# <a name="Configuration">Configuration Management</a>

- [ ] Check for commonly used application and administrative URLs  
- [ ] Check for old, backup and unreferenced files  
- [ ] Check HTTP methods supported and Cross Site Tracing (XST)  
- [ ] Test file extensions handling  
- [ ] Test for security HTTP headers (e.g. CSP, X-Frame-Options, HSTS)  
- [ ] Test for policies (e.g. Flash, Silverlight, robots)  
- [ ] Test for non-production data in live environment, and vice-versa  
- [ ] Check for sensitive data in client-side code (e.g. API keys, credentials)  


# <a name="Transmission">Secure Transmission</a>

- [ ] Check SSL Version, Algorithms, Key length  
- [ ] Check for Digital Certificate Validity (Duration, Signature and CN)  
- [ ] Check credentials only delivered over HTTPS  
- [ ] Check that the login form is delivered over HTTPS  
- [ ] Check session tokens only delivered over HTTPS  
- [ ] Check if HTTP Strict Transport Security (HSTS) in use  



# <a name="Authentication">Authentication</a>
- [ ] Test for user enumeration  
- [ ] Test for authentication bypass  
- [ ] Test for bruteforce protection  
- [ ] Test password quality rules  
- [ ] Test remember me functionality  
- [ ] Test for autocomplete on password forms/input  
- [ ] Test password reset and/or recovery  
- [ ] Test password change process  
- [ ] Test CAPTCHA  
- [ ] Test multi factor authentication  
- [ ] Test for logout functionality presence  
- [ ] Test for cache management on HTTP (eg Pragma, Expires, Max-age)  
- [ ] Test for default logins  
- [ ] Test for user-accessible authentication history  
- [ ] Test for out-of channel notification of account lockouts and successful password changes  
- [ ] Test for consistent authentication across applications with shared authentication schema / SSO  



# <a name="Session">Session Management</a>
- [ ] Establish how session management is handled in the application (eg, tokens in cookies, token in URL)  
- [ ] Check session tokens for cookie flags (httpOnly and secure)  
- [ ] Check session cookie scope (path and domain)  
- [ ] Check session cookie duration (expires and max-age)  
- [ ] Check session termination after a maximum lifetime  
- [ ] Check session termination after relative timeout  
- [ ] Check session termination after logout  
- [ ] Test to see if users can have multiple simultaneous sessions  
- [ ] Test session cookies for randomness  
- [ ] Confirm that new session tokens are issued on login, role change and logout  
- [ ] Test for consistent session management across applications with shared session management  
- [ ] Test for session puzzling  
- [ ] Test for CSRF and clickjacking  



# <a name="Authorization">Authorization</a>
- [ ] Test for path traversal  
- [ ] Test for bypassing authorization schema  
- [ ] Test for vertical Access control problems (a.k.a. Privilege Escalation)  
- [ ] Test for horizontal Access control problems (between two users at the same privilege level)  
- [ ] Test for missing authorization  


# <a name="Validation">Data Validation</a>
- [ ] Test for Reflected Cross Site Scripting  
- [ ] Test for Stored Cross Site Scripting  
- [ ] Test for DOM based Cross Site Scripting  
- [ ] Test for Cross Site Flashing  
- [ ] Test for HTML Injection  
- [ ] Test for SQL Injection  
- [ ] Test for LDAP Injection  
- [ ] Test for ORM Injection  
- [ ] Test for XML Injection  
- [ ] Test for XXE Injection  
- [ ] Test for SSI Injection  
- [ ] Test for XPath Injection  
- [ ] Test for XQuery Injection  
- [ ] Test for IMAP/SMTP Injection  
- [ ] Test for Code Injection  
- [ ] Test for Expression Language Injection  
- [ ] Test for Command Injection  
- [ ] Test for Overflow (Stack, Heap and Integer)  
- [ ] Test for Format String  
- [ ] Test for incubated vulnerabilities  
- [ ] Test for HTTP Splitting/Smuggling  
- [ ] Test for HTTP Verb Tampering  
- [ ] Test for Open Redirection  
- [ ] Test for Local File Inclusion  
- [ ] Test for Remote File Inclusion  
- [ ] Compare client-side and server-side validation rules  
- [ ] Test for NoSQL injection  
- [ ] Test for HTTP parameter pollution  
- [ ] Test for auto-binding  
- [ ] Test for Mass Assignment  
- [ ] Test for NULL/Invalid Session Cookie  

# <a name="Denial">Denial of Service</a>
- [ ] Test for anti-automation  
- [ ] Test for account lockout  
- [ ] Test for HTTP protocol DoS  
- [ ] Test for SQL wildcard DoS  


# <a name="Business">Business Logic</a>
- [ ] Test for feature misuse  
- [ ] Test for lack of non-repudiation  
- [ ] Test for trust relationships  
- [ ] Test for integrity of data  
- [ ] Test segregation of duties  


# <a name="Cryptography">Cryptography</a>
- [ ] Check if data which should be encrypted is not  
- [ ] Check for wrong algorithms usage depending on context  
- [ ] Check for weak algorithms usage  
- [ ] Check for proper use of salting  
- [ ] Check for randomness functions  


# <a name="File">Risky Functionality - File Uploads</a>
- [ ] Test that acceptable file types are whitelisted  
- [ ] Test that file size limits, upload frequency and total file counts are defined and are enforced  
- [ ] Test that file contents match the defined file type  
- [ ] Test that all file uploads have Anti-Virus scanning in-place.  
- [ ] Test that unsafe filenames are sanitised  
- [ ] Test that uploaded files are not directly accessible within the web root  
- [ ] Test that uploaded files are not served on the same hostname/port  
- [ ] Test that files and other media are integrated with the authentication and authorisation schemas  


# <a name="Card">Risky Functionality - Card Payment</a>
- [ ] Test for known vulnerabilities and configuration issues on Web Server and Web Application  
- [ ] Test for default or guessable password  
- [ ] Test for non-production data in live environment, and vice-versa  
- [ ] Test for Injection vulnerabilities  
- [ ] Test for Buffer Overflows  
- [ ] Test for Insecure Cryptographic Storage  
- [ ] Test for Insufficient Transport Layer Protection  
- [ ] Test for Improper Error Handling  
- [ ] Test for all vulnerabilities with a CVSS v2 score > 4.0  
- [ ] Test for Authentication and Authorization issues  
- [ ] Test for CSRF  


# <a name="HTML">HTML 5</a>
- [ ] Test Web Messaging  
- [ ] Test for Web Storage SQL injection  
- [ ] Check CORS implementation  
- [ ] Check Offline Web Application  

  





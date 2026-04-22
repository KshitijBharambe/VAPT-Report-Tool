"""Finding manipulation helpers for the VAPT report tool."""

import re
import unicodedata

from report_core.finding_defaults import (
    _BUSINESS_IMPACT_TEMPLATES,
    _CATEGORY_KEYWORDS,
    _GENERIC_AUDIT_REQUIREMENT_FALLBACK,
    _GENERIC_CONTROL_NAME_FALLBACK,
    _GENERIC_CONTROL_OBJECTIVE_FALLBACK,
    _GENERIC_REFERENCE_FALLBACK,
    _GENERIC_REMEDIATION_PHRASES,
    _MIN_LEN,
    _PLACEHOLDER_TEXT,
    _REC_TIER_LABELS,
    _STRUCTURED_GENERIC_LOOKUP_VALUES,
)

_CONTROL_MAP = {
    # ── Injection ────────────────────────────────────────────────────────────
    "sql injection": {
        "control_objective": "Prevent unauthorised database access and data manipulation by ensuring all database queries use parameterised statements and strict input validation, eliminating direct inclusion of user-controlled data in SQL commands.",
        "control_name": "Input Validation and Parameterised Queries",
        "audit_requirement": "Verify that all database queries use parameterised statements or prepared statements. Test representative endpoints with SQL metacharacters and confirm no query manipulation occurs.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "sqli": {
        "control_objective": "Prevent unauthorised database access and data manipulation by ensuring all database queries use parameterised statements and strict input validation, eliminating direct inclusion of user-controlled data in SQL commands.",
        "control_name": "Input Validation and Parameterised Queries",
        "audit_requirement": "Verify that all database queries use parameterised statements or prepared statements. Test representative endpoints with SQL metacharacters and confirm no query manipulation occurs.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ldap injection": {
        "control_objective": "Prevent manipulation of LDAP queries through user-supplied input by enforcing strict input escaping and using safe LDAP APIs.",
        "control_name": "LDAP Input Validation and Escaping",
        "audit_requirement": "Test LDAP-bound endpoints with LDAP metacharacters and confirm no unintended query modification occurs. Review LDAP query construction for parameterised equivalents.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "xpath injection": {
        "control_objective": "Prevent manipulation of XPath queries through user-supplied input by enforcing parameterised XPath expressions and input validation.",
        "control_name": "XPath Input Validation",
        "audit_requirement": "Test XML/XPath-bound endpoints with XPath metacharacters and confirm no unintended query modification occurs.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "cross-site scripting": {
        "control_objective": "Ensure all user-supplied input rendered in web pages is contextually encoded using a vetted output encoding library, and that Content-Security-Policy headers restrict execution of injected scripts.",
        "control_name": "Output Encoding and Content Security Policy",
        "audit_requirement": "Test all user-input reflection points with XSS payloads. Verify Content-Security-Policy response headers prohibit inline script execution. Confirm HTML, JavaScript, and URL contexts are encoded separately.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    " xss": {
        "control_objective": "Ensure all user-supplied input rendered in web pages is contextually encoded using a vetted output encoding library, and that Content-Security-Policy headers restrict execution of injected scripts.",
        "control_name": "Output Encoding and Content Security Policy",
        "audit_requirement": "Test all user-input reflection points with XSS payloads. Verify Content-Security-Policy response headers prohibit inline script execution.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "csrf": {
        "control_objective": "Prevent unauthorised state-changing requests by ensuring all sensitive operations require anti-CSRF tokens bound to the authenticated user session, and that SameSite cookie attributes are correctly set.",
        "control_name": "CSRF Token Validation and SameSite Cookie Policy",
        "audit_requirement": "Verify that all state-changing requests require a valid CSRF token. Confirm the token is unpredictable, session-bound, and validated server-side. Check SameSite cookie attribute is set to Strict or Lax.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ssrf": {
        "control_objective": "Prevent server-side requests from being redirected to internal or unintended resources by enforcing allowlist-based URL validation and blocking outbound requests to private IP ranges.",
        "control_name": "Allowlist-Based URL Validation and Network Egress Control",
        "audit_requirement": "Test all URL-accepting parameters with internal IP addresses (127.0.0.1, 169.254.x.x, 10.x.x.x) and confirm requests are blocked. Verify an egress firewall restricts server outbound connections.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "remote code execution": {
        "control_objective": "Prevent attackers from executing arbitrary code on the server by applying timely vendor patches, restricting access to vulnerable services, and monitoring for exploitation attempts.",
        "control_name": "Patch Management and Service Exposure Control",
        "audit_requirement": "Verify the affected component version against the vendor security advisory and confirm the patch has been applied. Review network access controls to confirm the service is not unnecessarily internet-exposed.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "command injection": {
        "control_objective": "Prevent arbitrary OS command execution via application inputs by using parameterised system call APIs and strict input validation, and avoiding shell invocation with user-controlled data.",
        "control_name": "Input Validation and Restricted System Call Usage",
        "audit_requirement": "Test all inputs that interact with system commands with OS metacharacters. Confirm parameterised APIs (subprocess with list args) are used and shell=True invocations are absent.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Access Control ────────────────────────────────────────────────────────
    "privilege escalation": {
        "control_objective": "Ensure least-privilege principles are enforced across all system accounts and processes, preventing unauthorised elevation of access rights.",
        "control_name": "Role-Based Access Control and Privilege Separation",
        "audit_requirement": "Review user and service account privilege assignments against documented least-privilege policy. Test for vertical privilege escalation on representative endpoints.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "authentication bypass": {
        "control_objective": "Ensure all authentication mechanisms are enforced on every sensitive endpoint and cannot be circumvented by request manipulation, token forging, or parameter tampering.",
        "control_name": "Authentication Enforcement and Session Management",
        "audit_requirement": "Test all sensitive endpoints for direct access without valid session tokens. Verify authentication checks cannot be bypassed by removing or altering session cookies or headers.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "missing authentication": {
        "control_objective": "Ensure every critical function and management interface enforces authentication before execution, with no unauthenticated access paths to sensitive operations.",
        "control_name": "Authentication Enforcement",
        "audit_requirement": "Test and verify that only authenticated and authorised users can access the service. Review configuration and access-control policies periodically and monitor access event logs.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "default credentials": {
        "control_objective": "Ensure all vendor-supplied default credentials are changed before deployment, and that account lockout and password complexity policies are enforced across all services.",
        "control_name": "Default Credential Elimination",
        "audit_requirement": "Verify no service accepts vendor-default usernames or passwords. Test common default credential pairs against all authentication interfaces. Confirm a credential management procedure is in place.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "default community": {
        "control_objective": "Ensure SNMP community strings are changed from default values to non-guessable strings, and that SNMP access is restricted to authorised management hosts only.",
        "control_name": "SNMP Community String Hardening",
        "audit_requirement": "Verify that SNMP community strings have been changed from default values ('public', 'private', 'cisco'). Confirm SNMP access is restricted via ACL to authorised management hosts only, and consider upgrading to SNMPv3 with authentication and encryption.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "snmp agent default": {
        "control_objective": "Ensure SNMP community strings are changed from default values to non-guessable strings, and that SNMP access is restricted to authorised management hosts only.",
        "control_name": "SNMP Community String Hardening",
        "audit_requirement": "Verify that SNMP community strings have been changed from default values ('public', 'private', 'cisco'). Confirm SNMP access is restricted via ACL to authorised management hosts only, and consider upgrading to SNMPv3 with authentication and encryption.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "snmp": {
        "control_objective": "Ensure SNMP is configured with strong authentication and encryption (SNMPv3), non-default community strings, and access restricted to authorised management hosts via ACL.",
        "control_name": "SNMP Service Hardening",
        "audit_requirement": "Verify SNMP version and community string configuration. Confirm ACL rules restrict SNMP access to authorised management hosts. Validate that SNMPv3 is used with authentication and privacy enabled where supported.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "hard-coded credential": {
        "control_objective": "Ensure credentials are sourced from a secure secrets management store and never embedded in application source code, configuration files, or build artefacts.",
        "control_name": "Secrets Management Control",
        "audit_requirement": "Scan source code and build artefacts for hardcoded credential patterns. Verify a secrets management solution is in use and credentials are rotated on a documented schedule.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "hardcoded credential": {
        "control_objective": "Ensure credentials are sourced from a secure secrets management store and never embedded in application source code, configuration files, or build artefacts.",
        "control_name": "Secrets Management Control",
        "audit_requirement": "Scan source code and build artefacts for hardcoded credential patterns. Verify a secrets management solution is in use and credentials are rotated on a documented schedule.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Path / File Access ────────────────────────────────────────────────────
    "directory traversal": {
        "control_objective": "Prevent access to files and directories outside the intended web root by canonicalising file paths and enforcing strict allowlist-based access controls.",
        "control_name": "Path Canonicalisation and File Access Restrictions",
        "audit_requirement": "Test file-serving endpoints with path traversal sequences (../). Verify the application resolves canonical paths and confirms they remain within the allowed base directory before serving content.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "path traversal": {
        "control_objective": "Prevent access to files and directories outside the intended web root by canonicalising file paths and enforcing strict allowlist-based access controls.",
        "control_name": "Path Canonicalisation and File Access Restrictions",
        "audit_requirement": "Test file-serving endpoints with path traversal sequences (../). Verify the application resolves canonical paths and confirms they remain within the allowed base directory before serving content.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "backup file": {
        "control_objective": "Ensure backup, temporary, and archive files are not accessible through the web root or any anonymously accessible path, preventing unintended source code or configuration disclosure.",
        "control_name": "Sensitive Backup File Exposure Control",
        "audit_requirement": "Review web roots and exposed directories for backup, temporary, and archive files. Verify that such files are removed or access-restricted and do not expose sensitive content.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "backup files disclosure": {
        "control_objective": "Ensure backup, temporary, and archive files are not accessible through the web root or any anonymously accessible path, preventing unintended source code or configuration disclosure.",
        "control_name": "Sensitive Backup File Exposure Control",
        "audit_requirement": "Review web roots and exposed directories for backup, temporary, and archive files. Verify that such files are removed or access-restricted and do not expose sensitive content.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "directory browsing": {
        "control_objective": "Ensure directory listing is disabled on all web servers so that directory contents are not exposed to unauthenticated users.",
        "control_name": "Directory Listing Hardening",
        "audit_requirement": "Verify directory listing is disabled on the web server and confirm that sensitive directories, backup files, and static assets are not anonymously browsable.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "directory listing": {
        "control_objective": "Ensure directory listing is disabled on all web servers so that directory contents are not exposed to unauthenticated users.",
        "control_name": "Directory Listing Hardening",
        "audit_requirement": "Verify directory listing is disabled on the web server and confirm that sensitive directories, backup files, and static assets are not anonymously browsable.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "browsable web directories": {
        "control_objective": "Ensure directory listing is disabled on all web servers so that directory contents are not exposed to unauthenticated users.",
        "control_name": "Directory Listing Hardening",
        "audit_requirement": "Verify directory listing is disabled on the web server and confirm that sensitive directories, backup files, and static assets are not anonymously browsable.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Cryptography / TLS ────────────────────────────────────────────────────
    "weak tls": {
        "control_objective": "Ensure only TLS 1.2 and TLS 1.3 are accepted and all deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are explicitly disabled across all services.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Verify TLS configuration using a TLS scanner (e.g., testssl.sh). Confirm only TLS 1.2 and 1.3 are accepted and deprecated protocol versions are rejected.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "weak cipher": {
        "control_objective": "Ensure only strong, up-to-date TLS protocols and cipher suites are used.",
        "control_name": "TLS Configuration Hardening",
        "audit_requirement": "Verify that SSL/TLS configurations do not support medium strength ciphers such as 3DES or those with key lengths between 64 and 112 bits. Confirm use of strong cipher suites only using a TLS scanner.",
        "reference": "OWASP Web Security Top 10, SANS25; CWE-326",
    },
    "medium strength cipher": {
        "control_objective": "Ensure only strong, up-to-date TLS protocols and cipher suites are used.",
        "control_name": "TLS Configuration Hardening",
        "audit_requirement": "Verify that SSL/TLS configurations do not support medium strength ciphers such as 3DES or those with key lengths between 64 and 112 bits. Confirm use of strong cipher suites only using a TLS scanner.",
        "reference": "OWASP Web Security Top 10, SANS25; CWE-326",
    },
    "sweet32": {
        "control_objective": "Ensure only strong, up-to-date TLS protocols and cipher suites are used.",
        "control_name": "TLS Configuration Hardening",
        "audit_requirement": "Verify that 3DES and other 64-bit block ciphers are disabled in the TLS configuration. Confirm cipher suite selection using a TLS scanner and verify only AEAD ciphers are accepted.",
        "reference": "OWASP Web Security Top 10, SANS25; CWE-326",
    },
    "ssl certificate": {
        "control_objective": "Ensure SSL/TLS certificates are issued by a trusted Certificate Authority, are within their validity period, match the hostname of the service, and use key lengths meeting current standards.",
        "control_name": "SSL Certificate Lifecycle Management",
        "audit_requirement": "Verify the certificate issuer, validity period, subject CN/SAN match, and key strength. Confirm an automated certificate renewal process is in place to prevent expiry.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "self-signed certificate": {
        "control_objective": "Ensure all production services use SSL/TLS certificates issued by a trusted Certificate Authority to prevent client-side certificate validation errors and man-in-the-middle attacks.",
        "control_name": "SSL Certificate Lifecycle Management",
        "audit_requirement": "Verify the certificate issuer is a trusted CA. Confirm automated certificate renewal is in place. Check that clients and browsers do not display certificate trust warnings.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "certificate expired": {
        "control_objective": "Ensure SSL/TLS certificates are renewed before expiry and an automated certificate lifecycle management process is in place to prevent service disruption and trust failures.",
        "control_name": "SSL Certificate Lifecycle Management",
        "audit_requirement": "Verify the certificate expiry date against the current date. Confirm an automated renewal process (e.g., ACME/Let's Encrypt, PKI automation) is in place with alerting before expiry.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "tls 1.0": {
        "control_objective": "Ensure deprecated TLS 1.0 and TLS 1.1 protocols are disabled and only TLS 1.2 and TLS 1.3 are accepted to prevent exploitation of known protocol weaknesses.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Confirm TLS 1.0 and 1.1 are explicitly disabled using a TLS scanner. Verify server configuration files reflect the change and test with a TLS 1.0 client to confirm rejection.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "tls 1.1": {
        "control_objective": "Ensure deprecated TLS 1.0 and TLS 1.1 protocols are disabled and only TLS 1.2 and TLS 1.3 are accepted to prevent exploitation of known protocol weaknesses.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Confirm TLS 1.0 and 1.1 are explicitly disabled using a TLS scanner. Verify server configuration files reflect the change and test with a TLS 1.1 client to confirm rejection.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Network Services ──────────────────────────────────────────────────────
    "smb signing": {
        "control_objective": "Ensure SMB signing is required (not merely supported) on all servers and domain-joined clients to prevent man-in-the-middle relay attacks against SMB traffic.",
        "control_name": "SMB Service Configuration",
        "audit_requirement": "Review GPO/domain policy and client configurations to confirm SMB signing is set to required (not just enabled). Use an SMB scanner to verify the policy is enforced in production.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "smb": {
        "control_objective": "Ensure SMB is securely configured with signing enforced, access restricted to authorised hosts, and legacy SMBv1 disabled to prevent relay and exploitation attacks.",
        "control_name": "SMB Service Configuration",
        "audit_requirement": "Verify SMB signing is required and SMBv1 is disabled via group policy or server configuration. Confirm access to SMB shares is restricted to authorised users and hosts.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "rdp": {
        "control_objective": "Ensure Remote Desktop Protocol is protected with Network Level Authentication, strong encryption, MFA, and restricted to authorised source IP ranges via firewall rules.",
        "control_name": "RDP Access Control and Encryption",
        "audit_requirement": "Verify Network Level Authentication (NLA) is enforced on all RDP endpoints. Confirm RDP access is restricted to VPN or trusted IP ranges via firewall. Test that weak RDP configurations (no NLA, RC4 encryption) are rejected.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "remote desktop": {
        "control_objective": "Ensure Remote Desktop Protocol is protected with Network Level Authentication, strong encryption, MFA, and restricted to authorised source IP ranges via firewall rules.",
        "control_name": "RDP Access Control and Encryption",
        "audit_requirement": "Verify Network Level Authentication (NLA) is enforced on all RDP endpoints. Confirm RDP access is restricted to VPN or trusted IP ranges via firewall.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ssh": {
        "control_objective": "Ensure SSH is configured with strong algorithms, key-based authentication, root login disabled, and access restricted to authorised hosts and users.",
        "control_name": "SSH Service Hardening",
        "audit_requirement": "Verify SSH configuration disables weak algorithms, password authentication for privileged accounts, and root direct login. Confirm SSH access is restricted to authorised source IP ranges.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "openssh": {
        "control_objective": "Ensure OpenSSH is running a supported, patched version with strong cryptographic algorithms and secure configuration to prevent exploitation of known vulnerabilities.",
        "control_name": "SSH Service Hardening",
        "audit_requirement": "Verify the running OpenSSH version against the latest vendor security release. Confirm weak algorithms (arcfour, blowfish, DES-based MACs) are disabled in the server configuration.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "echo service": {
        "control_objective": "Ensure unnecessary network services such as the Echo service are disabled on all hosts to reduce the attack surface and prevent abuse in amplification and DoS attacks.",
        "control_name": "Unnecessary Service Disablement",
        "audit_requirement": "Verify the Echo service is disabled on all hosts by checking inetd/xinetd configuration and confirming port 7 is not reachable. Review all enabled legacy services against the hardening baseline.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "chargen": {
        "control_objective": "Ensure the Character Generator (chargen) service is disabled on all hosts to eliminate the risk of UDP amplification and bandwidth exhaustion attacks.",
        "control_name": "Unnecessary Service Disablement",
        "audit_requirement": "Verify the chargen service is disabled in inetd/xinetd configuration and port 19 is not reachable. Confirm all legacy inetd services are reviewed and disabled where not required.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "daytime": {
        "control_objective": "Ensure unnecessary legacy network services are disabled on all hosts to reduce the attack surface.",
        "control_name": "Unnecessary Service Disablement",
        "audit_requirement": "Verify the daytime service is disabled in inetd/xinetd configuration and the service port is not reachable. Review all enabled legacy inetd services.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "quote of the day": {
        "control_objective": "Ensure the Quote of the Day (QOTD) service is disabled to reduce unnecessary attack surface.",
        "control_name": "Unnecessary Service Disablement",
        "audit_requirement": "Verify the QOTD service is disabled in inetd configuration. Confirm port 17 is not accessible from the network.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "finger": {
        "control_objective": "Ensure the Finger service is disabled to prevent information leakage about system users and reduce unnecessary attack surface.",
        "control_name": "Unnecessary Service Disablement",
        "audit_requirement": "Verify the Finger service is disabled and port 79 is not reachable. Confirm no user enumeration is possible via the service.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ntp": {
        "control_objective": "Ensure NTP is configured to use authenticated time sources, restrict mode 6/7 queries, and disable monlist to prevent amplification attacks and time manipulation.",
        "control_name": "NTP Service Hardening",
        "audit_requirement": "Verify NTP configuration disables monlist (ntpdc -c monlist should fail), restricts control queries, and uses authenticated peers. Confirm NTP version is current.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "dns": {
        "control_objective": "Ensure DNS is configured to prevent zone transfers to unauthorised hosts, recursion is restricted to internal clients, and DNSSEC is enabled where supported.",
        "control_name": "DNS Service Hardening",
        "audit_requirement": "Verify zone transfers are restricted to authorised secondaries. Test recursive queries from external IPs to confirm they are refused. Verify BIND/DNS version against current vendor release.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "bind": {
        "control_objective": "Ensure BIND is running a supported, patched version with recursion restricted to internal clients, zone transfers restricted to authorised secondaries, and version string suppressed.",
        "control_name": "DNS Service Hardening",
        "audit_requirement": "Verify the BIND version against the latest vendor security release. Confirm recursion is restricted to internal clients only and zone transfers are limited to authorised secondary servers.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Web / Application ─────────────────────────────────────────────────────
    "open redirect": {
        "control_objective": "Prevent users from being redirected to malicious external sites by enforcing allowlist-based URL validation on all redirect parameters.",
        "control_name": "URL Allowlist Validation for Redirects",
        "audit_requirement": "Test all redirect parameters with external URLs. Verify the application only redirects to allowlisted domains and rejects arbitrary external URLs.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "xxe": {
        "control_objective": "Prevent XML parsers from processing external entity references by disabling DTD processing and external entity resolution in all XML parsing libraries.",
        "control_name": "Disable External Entity Processing in XML Parsers",
        "audit_requirement": "Verify all XML parsers have external entity resolution and DTD processing explicitly disabled. Test with an XXE payload targeting an internal resource and confirm it is not processed.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "insecure deserialization": {
        "control_objective": "Prevent exploitation of insecure deserialisation by accepting only signed or type-validated payloads from trusted sources, and using safe deserialisation libraries.",
        "control_name": "Safe Deserialisation Control",
        "audit_requirement": "Identify all deserialisation points. Verify payloads are validated before deserialisation and integrity is confirmed via HMAC or digital signature. Test with known gadget chains to confirm they are not exploitable.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "missing security header": {
        "control_objective": "Enforce browser security policies by configuring appropriate HTTP security response headers including Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security.",
        "control_name": "HTTP Security Header Configuration",
        "audit_requirement": "Verify all required HTTP security headers are present in responses from the application. Confirm Content-Security-Policy restricts script sources and X-Frame-Options prevents framing.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "clickjacking": {
        "control_objective": "Prevent the application from being embedded in malicious iframes by setting X-Frame-Options or Content-Security-Policy frame-ancestors headers on all responses.",
        "control_name": "Clickjacking Protection Header",
        "audit_requirement": "Verify X-Frame-Options or CSP frame-ancestors header is present on all HTML responses. Confirm the header value is DENY or SAMEORIGIN (not ALLOWALL).",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "x-frame-options": {
        "control_objective": "Prevent the application from being embedded in malicious iframes by setting X-Frame-Options or Content-Security-Policy frame-ancestors headers on all responses.",
        "control_name": "Clickjacking Protection Header",
        "audit_requirement": "Verify X-Frame-Options or CSP frame-ancestors header is present on all HTML responses.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "hsts": {
        "control_objective": "Ensure HTTP Strict Transport Security is configured to force all connections over HTTPS and prevent protocol downgrade attacks.",
        "control_name": "HTTPS Enforcement and HSTS Configuration",
        "audit_requirement": "Verify the Strict-Transport-Security header is present with a max-age of at least 31536000 seconds and includes the includeSubDomains directive. Confirm HTTP requests are redirected to HTTPS.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "autocomplete": {
        "control_objective": "Ensure sensitive form fields have autocomplete disabled to prevent browsers from caching and auto-filling credentials or sensitive personal data.",
        "control_name": "Form Field Autocomplete Control",
        "audit_requirement": "Verify all sensitive form fields (passwords, PINs, financial data) have the autocomplete='off' attribute set. Confirm browsers do not retain field values between sessions.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "http methods": {
        "control_objective": "Ensure only the HTTP methods required by the application are enabled, and dangerous methods such as PUT, DELETE, TRACE, and OPTIONS are disabled on production endpoints.",
        "control_name": "HTTP Method Restriction",
        "audit_requirement": "Test all application endpoints with non-standard HTTP methods (OPTIONS, PUT, DELETE, TRACE). Verify the server responds with 405 Method Not Allowed for disallowed methods.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Information Disclosure ────────────────────────────────────────────────
    "version disclosure": {
        "control_objective": "Minimise information leakage that aids attacker reconnaissance by suppressing server banners, version strings, and error messages from all HTTP responses.",
        "control_name": "Server Banner and Version Suppression",
        "audit_requirement": "Verify verbose server banners and application version strings are suppressed in HTTP response headers (Server, X-Powered-By), default pages, and error messages.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "information disclosure": {
        "control_objective": "Ensure sensitive information is restricted to authorised actors and not leaked through error messages, HTTP headers, API responses, or publicly accessible files.",
        "control_name": "Sensitive Information Exposure to Unauthorized Actor",
        "audit_requirement": "Test and verify that error messages, HTTP headers, and API responses do not expose sensitive system information. Review access control policies and monitor access event logs.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "sensitive information": {
        "control_objective": "Ensure sensitive information is restricted to authorised actors and not leaked through error messages, HTTP headers, API responses, or publicly accessible files.",
        "control_name": "Sensitive Information Exposure to Unauthorized Actor",
        "audit_requirement": "Test and verify that error messages, HTTP headers, and API responses do not expose sensitive system information.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Object / Authorisation ────────────────────────────────────────────────
    "idor": {
        "control_objective": "Prevent users from accessing objects belonging to other users by enforcing object-level authorisation checks on every data access operation.",
        "control_name": "Object-Level Authorisation Checks",
        "audit_requirement": "Test all object references with credentials from a different user account. Verify the application enforces ownership validation server-side, not just client-side.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "insecure direct object": {
        "control_objective": "Prevent users from accessing objects belonging to other users by enforcing object-level authorisation checks on every data access operation.",
        "control_name": "Object-Level Authorisation Checks",
        "audit_requirement": "Test all object references with credentials from a different user account. Verify the application enforces ownership validation server-side.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Outdated / EOL software ───────────────────────────────────────────────
    "unsupported version": {
        "control_objective": "Ensure that remote servers run the most updated version of the software, operating systems, or applications, or have security guardrails such as network isolation or privileged access control to ensure the legacy/outdated system runs securely.",
        "control_name": "Outdated Version Control",
        "audit_requirement": "Review the version of the software via an automated asset and patch management system or manually periodically. Verify the running version matches the latest vendor-published security release.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "end-of-life": {
        "control_objective": "Ensure that remote servers run the most updated version of the software, operating systems, or applications, or have security guardrails such as network isolation or privileged access control to ensure the legacy/outdated system runs securely.",
        "control_name": "Outdated Version Control",
        "audit_requirement": "Review the version of the software via an automated asset and patch management system or manually periodically. Verify the running version matches the latest vendor-published security release.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "outdated": {
        "control_objective": "Ensure that remote servers run the most updated version of the software, operating systems, or applications, or have security guardrails such as network isolation or privileged access control to ensure the legacy/outdated system runs securely.",
        "control_name": "Outdated Version Control",
        "audit_requirement": "Review the version of the software via an automated asset and patch management system or manually periodically. Verify the running version matches the latest vendor-published security release.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "eol": {
        "control_objective": "Ensure that remote servers run the most updated version of the software, operating systems, or applications, or have security guardrails such as network isolation or privileged access control to ensure the legacy/outdated system runs securely.",
        "control_name": "Outdated Version Control",
        "audit_requirement": "Review the version of the software via an automated asset and patch management system or manually periodically. Verify the running version matches the latest vendor-published security release.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Password / Session ─────────────────────────────────────────────────────
    "weak password": {
        "control_objective": "Ensure password policies enforce minimum complexity, length, and rotation requirements, and that weak or previously breached passwords cannot be set.",
        "control_name": "Password Policy Enforcement",
        "audit_requirement": "Verify the password policy is enforced server-side with minimum length (12+ characters), complexity requirements, and breach password checks. Test account registration and password change flows.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "password policy": {
        "control_objective": "Ensure password policies enforce minimum complexity, length, and rotation requirements, and that weak or previously breached passwords cannot be set.",
        "control_name": "Password Policy Enforcement",
        "audit_requirement": "Verify the password policy is enforced server-side with minimum length, complexity, and breach password checks.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "cleartext": {
        "control_objective": "Ensure all authentication credentials and sensitive data are transmitted exclusively over encrypted channels (TLS 1.2+) and never in cleartext.",
        "control_name": "Cleartext Transmission Prevention",
        "audit_requirement": "Capture network traffic between client and server and confirm no credentials or sensitive data are transmitted in cleartext. Verify HTTP endpoints redirect to HTTPS.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "plaintext": {
        "control_objective": "Ensure all authentication credentials and sensitive data are transmitted exclusively over encrypted channels (TLS 1.2+) and never in plaintext.",
        "control_name": "Cleartext Transmission Prevention",
        "audit_requirement": "Capture network traffic between client and server and confirm no credentials or sensitive data are transmitted in plaintext.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Components ────────────────────────────────────────────────────────────
    "jquery": {
        "control_objective": "Ensure jQuery and all front-end libraries are updated to a supported, patched version to eliminate known cross-site scripting and prototype pollution vulnerabilities.",
        "control_name": "Third-Party Library Version Control",
        "audit_requirement": "Identify jQuery version in use via page source or HTTP response headers. Verify the version has no known security vulnerabilities by checking against the NVD or Snyk database.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "third-party component": {
        "control_objective": "Ensure all third-party libraries and dependencies are inventoried, actively maintained, and updated against a tracked Software Bill of Materials (SBOM).",
        "control_name": "Third-Party Component Lifecycle Control",
        "audit_requirement": "Review all third-party component versions against known vulnerability databases (NVD, Snyk). Confirm a Software Composition Analysis (SCA) tool is integrated into the CI/CD pipeline.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "known vulnerable component": {
        "control_objective": "Ensure all third-party libraries and dependencies are inventoried, actively maintained, and updated against a tracked Software Bill of Materials (SBOM).",
        "control_name": "Third-Party Component Lifecycle Control",
        "audit_requirement": "Review all third-party component versions against known vulnerability databases. Confirm an automated dependency scanning process is in place.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Network Services (common LLM triggers) ────────────────────────────────
    "rdp": {
        "control_objective": "Ensure Remote Desktop Protocol (RDP) services are protected with Network Level Authentication (NLA), restricted to authorized users via firewall ACLs, and monitored for brute-force attempts.",
        "control_name": "RDP Service Hardening",
        "audit_requirement": "Verify NLA is enabled, RDP access is restricted to authorized IP ranges via firewall rules, and account lockout policies are enforced.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "remote desktop": {
        "control_objective": "Ensure Remote Desktop Protocol (RDP) services are protected with Network Level Authentication (NLA), restricted to authorized users via firewall ACLs, and monitored for brute-force attempts.",
        "control_name": "RDP Service Hardening",
        "audit_requirement": "Verify NLA is enabled, RDP access is restricted to authorized IP ranges via firewall rules, and account lockout policies are enforced.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "nfs": {
        "control_objective": "Ensure NFS exports are restricted to authorized hosts only with read-only access where possible and no_root_squash is disabled.",
        "control_name": "NFS Export Hardening",
        "audit_requirement": "Verify NFS exports do not allow world-accessible shares. Confirm no_root_squash is disabled and exports are restricted to specific IP ranges.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ftp": {
        "control_objective": "Ensure FTP services are disabled or replaced with SFTP/FTPS, and if required, restrict access to authorized users with strong authentication.",
        "control_name": "FTP Service Hardening",
        "audit_requirement": "Verify anonymous FTP is disabled. Confirm TLS encryption is enforced (FTPS) or service is replaced with SFTP.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "telnet": {
        "control_objective": "Disable Telnet services and replace with SSH for secure remote administration.",
        "control_name": "Cleartext Protocol Elimination",
        "audit_requirement": "Verify Telnet service is disabled on all systems. Confirm SSH is used for all remote administration.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ipmi": {
        "control_objective": "Ensure IPMI/BMC interfaces are isolated on a dedicated management network, use strong credentials, and have firmware updated to latest version.",
        "control_name": "IPMI/BMC Hardening",
        "audit_requirement": "Verify IPMI interfaces are not accessible from production networks. Confirm default credentials are changed and firmware is current.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "smb signing": {
        "control_objective": "Ensure SMB message signing is required on all domain controllers and file servers to prevent relay attacks and session hijacking.",
        "control_name": "SMB Signing Enforcement",
        "audit_requirement": "Verify RequireSecuritySignature is enabled via Group Policy. Test SMB connections and confirm signing is enforced, not merely supported.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "smb": {
        "control_objective": "Ensure SMB services use SMB 3.x with encryption, disable SMBv1, and require message signing on all connections.",
        "control_name": "SMB Protocol Hardening",
        "audit_requirement": "Verify SMBv1 is disabled. Confirm SMB signing is required and encryption is enabled where supported. Review share permissions for least-privilege access.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "icmp timestamp": {
        "control_objective": "Disable ICMP timestamp responses to prevent system uptime and clock skew information disclosure.",
        "control_name": "ICMP Information Disclosure Prevention",
        "audit_requirement": "Verify ICMP timestamp requests are blocked at the host firewall level. Confirm no timestamp responses are received from external probing.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "echo service": {
        "control_objective": "Disable legacy TCP/UDP echo services that are unnecessary and can be abused for amplification attacks.",
        "control_name": "Legacy Service Elimination",
        "audit_requirement": "Verify echo service (port 7) is disabled on all systems. Confirm inetd/xinetd configuration does not enable legacy services.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "chargen": {
        "control_objective": "Disable legacy chargen service that can be abused for amplification attacks.",
        "control_name": "Legacy Service Elimination",
        "audit_requirement": "Verify chargen service (port 19) is disabled on all systems. Confirm inetd/xinetd configuration does not enable legacy services.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "daytime": {
        "control_objective": "Disable legacy daytime service that provides system time information to unauthenticated requesters.",
        "control_name": "Legacy Service Elimination",
        "audit_requirement": "Verify daytime service (port 13) is disabled on all systems.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "quote of the day": {
        "control_objective": "Disable legacy QOTD service that is unnecessary and can be abused for amplification attacks.",
        "control_name": "Legacy Service Elimination",
        "audit_requirement": "Verify QOTD service (port 17) is disabled on all systems.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Database Exposure ─────────────────────────────────────────────────────
    "elasticsearch": {
        "control_objective": "Ensure Elasticsearch clusters require authentication, are isolated on internal networks, and do not expose administrative endpoints to untrusted sources.",
        "control_name": "Database Access Control",
        "audit_requirement": "Verify Elasticsearch requires X-Pack security or equivalent authentication. Confirm cluster is not accessible from public networks.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "mongodb": {
        "control_objective": "Ensure MongoDB instances require authentication, bind to internal interfaces only, and do not expose administrative endpoints to untrusted sources.",
        "control_name": "Database Access Control",
        "audit_requirement": "Verify MongoDB requires authentication. Confirm bindIp is set to internal interfaces only and not 0.0.0.0.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "redis": {
        "control_objective": "Ensure Redis instances require authentication, bind to internal interfaces only, and have dangerous commands disabled.",
        "control_name": "Database Access Control",
        "audit_requirement": "Verify Redis requirepass is configured. Confirm bind directive restricts to internal interfaces. Verify dangerous commands (FLUSHALL, CONFIG) are disabled.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "memcached": {
        "control_objective": "Ensure Memcached instances bind to internal interfaces only and are not accessible from untrusted networks.",
        "control_name": "Cache Service Access Control",
        "audit_requirement": "Verify Memcached binds to internal interfaces only. Confirm no UDP amplification exposure exists.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Web Server Hardening ──────────────────────────────────────────────────
    "server version": {
        "control_objective": "Suppress server version and technology stack information in HTTP response headers and error pages to prevent reconnaissance.",
        "control_name": "Server Banner Hardening",
        "audit_requirement": "Verify Server, X-Powered-By, and X-AspNet-Version headers are suppressed or generic. Confirm error pages do not reveal stack traces or version numbers.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "server_tokens": {
        "control_objective": "Suppress server version and technology stack information in HTTP response headers and error pages to prevent reconnaissance.",
        "control_name": "Server Banner Hardening",
        "audit_requirement": "Verify server_tokens is set to off in nginx config. Confirm Server header is generic.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "http trace": {
        "control_objective": "Disable HTTP TRACE method to prevent cross-site tracing attacks that can steal authentication cookies.",
        "control_name": "HTTP Method Hardening",
        "audit_requirement": "Verify TRACE method returns 405 Method Not Allowed. Confirm all unnecessary HTTP methods are disabled.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "http options": {
        "control_objective": "Restrict HTTP OPTIONS responses to prevent disclosure of allowed methods that could aid attackers.",
        "control_name": "HTTP Method Hardening",
        "audit_requirement": "Verify OPTIONS method is disabled or returns minimal information. Confirm unnecessary methods are not enabled.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── End of Life / Unsupported ─────────────────────────────────────────────
    "unsupported": {
        "control_objective": "Ensure all software and operating systems are within their vendor-supported lifecycle and receive security updates, or have compensating controls in place.",
        "control_name": "End-of-Life Software Remediation",
        "audit_requirement": "Verify software version against vendor end-of-life dates. Confirm migration plan exists for unsupported software.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "end of life": {
        "control_objective": "Ensure all software and operating systems are within their vendor-supported lifecycle and receive security updates, or have compensating controls in place.",
        "control_name": "End-of-Life Software Remediation",
        "audit_requirement": "Verify software version against vendor end-of-life dates. Confirm migration plan exists for unsupported software.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "eol": {
        "control_objective": "Ensure all software and operating systems are within their vendor-supported lifecycle and receive security updates, or have compensating controls in place.",
        "control_name": "End-of-Life Software Remediation",
        "audit_requirement": "Verify software version against vendor end-of-life dates. Confirm migration plan exists for unsupported software.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Application Version Vulnerabilities ───────────────────────────────────
    "jenkins": {
        "control_objective": "Ensure Jenkins is updated to a supported version with all security advisories applied, and that administrative access is restricted to authorized users.",
        "control_name": "CI/CD Platform Patch Management",
        "audit_requirement": "Verify Jenkins version against vendor security advisories. Confirm security plugins are enabled and administrative access requires strong authentication.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "kibana": {
        "control_objective": "Ensure Kibana is updated to a supported version with all security advisories applied, and that access is restricted to authorized users.",
        "control_name": "Observability Platform Patch Management",
        "audit_requirement": "Verify Kibana version against Elastic security advisories. Confirm X-Pack security is enabled and administrative access requires authentication.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "elastic": {
        "control_objective": "Ensure Elasticsearch and Kibana are updated to supported versions with all security advisories applied, and that access is restricted to authorized users.",
        "control_name": "Observability Platform Patch Management",
        "audit_requirement": "Verify Elasticsearch/Kibana versions against Elastic security advisories. Confirm X-Pack security is enabled.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ssl version 2": {
        "control_objective": "Ensure only TLS 1.2 and TLS 1.3 are accepted and all deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are explicitly disabled.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Verify SSLv2 is disabled using a TLS scanner (testssl.sh, nmap ssl-enum-ciphers). Confirm only TLS 1.2+ is accepted.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "ssl version 3": {
        "control_objective": "Ensure only TLS 1.2 and TLS 1.3 are accepted and all deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are explicitly disabled.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Verify SSLv3 is disabled using a TLS scanner. Confirm only TLS 1.2+ is accepted.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "sslv2": {
        "control_objective": "Ensure only TLS 1.2 and TLS 1.3 are accepted and all deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are explicitly disabled.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Verify SSLv2 is disabled. Confirm only TLS 1.2+ protocols are accepted.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "sslv3": {
        "control_objective": "Ensure only TLS 1.2 and TLS 1.3 are accepted and all deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are explicitly disabled.",
        "control_name": "TLS Protocol Version Hardening",
        "audit_requirement": "Verify SSLv3 is disabled. Confirm only TLS 1.2+ protocols are accepted.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "message queuing": {
        "control_objective": "Ensure message queuing services are updated with all security patches applied and access is restricted to authorized internal hosts only.",
        "control_name": "Message Queue Service Hardening",
        "audit_requirement": "Verify MSMQ/RabbitMQ/ActiveMQ version against security advisories. Confirm service is not exposed to untrusted networks.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "msmq": {
        "control_objective": "Ensure Microsoft Message Queuing (MSMQ) is updated with all security patches applied and access is restricted to authorized internal hosts only.",
        "control_name": "Message Queue Service Hardening",
        "audit_requirement": "Verify MSMQ patches are applied per Microsoft security advisories. Confirm service is not internet-exposed.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    # ── Generic version vulnerability patterns ────────────────────────────────
    "< ": {
        "control_objective": "Ensure software components are updated to vendor-recommended versions with all security patches applied.",
        "control_name": "Software Patch Management",
        "audit_requirement": "Verify software version against vendor security advisories. Confirm patch management process includes timely application of security updates.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "multiple vulnerabilities": {
        "control_objective": "Ensure affected software components are updated to vendor-recommended versions with all security patches applied.",
        "control_name": "Software Patch Management",
        "audit_requirement": "Verify software version against vendor security advisories. Confirm all identified vulnerabilities have been addressed by vendor patches.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
    "code execution": {
        "control_objective": "Prevent arbitrary code execution by applying timely vendor patches, restricting access to vulnerable services, and monitoring for exploitation attempts.",
        "control_name": "Patch Management and Service Exposure Control",
        "audit_requirement": "Verify the affected component version against vendor security advisory. Confirm the patch has been applied and service is not unnecessarily exposed.",
        "reference": "OWASP Web Security Top 10, SANS25",
    },
}

def _is_placeholder_text(value: str) -> bool:
    return str(value or "").strip().lower() in _PLACEHOLDER_TEXT


def _dedupe_findings(findings: list) -> list:
    """Merge findings with identical normalised name. Affected assets are concatenated.

    Rationale: scanners often emit the same vulnerability once per host; handmade
    reports collapse to one row per vuln listing all hosts together.
    """
    if not isinstance(findings, list):
        return findings
    by_key: dict[str, dict] = {}
    order: list[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        name = re.sub(r"\s+", " ", str(f.get("name") or "").strip().lower())
        sev = str(f.get("severity") or "").strip().lower()
        key = f"{name}|{sev}"
        if not name:
            key = f"__anon_{len(order)}"
        if key not in by_key:
            by_key[key] = dict(f)
            order.append(key)
            continue
        merged = by_key[key]
        # merge affected_assets (comma-joined, dedupe)
        existing = str(merged.get("affected_assets") or "")
        incoming = str(f.get("affected_assets") or "")
        parts = []
        seen = set()
        for chunk in re.split(r"[,\n;]+", existing + "," + incoming):
            c = chunk.strip()
            if c and c.lower() not in seen:
                seen.add(c.lower())
                parts.append(c)
        merged["affected_assets"] = ", ".join(parts)
        # keep richer fields if the merged one is empty
        for k in (
            "description",
            "business_impact",
            "proof_of_concept",
            "recommendation",
            "recommendations",
            "remediation",
            "control_objective",
            "control_name",
            "audit_requirement",
            "cve",
            "cvss",
            "reference",
        ):
            if not merged.get(k) and f.get(k):
                merged[k] = f[k]
    return [by_key[k] for k in order]


def _try_parse_python_list_repr(value: str) -> list[str] | None:
    """Detect and parse a Python list repr like "['a', 'b', 'c']" into a list of strings.

    LLMs sometimes output JSON string values that are Python list literals instead of JSON
    arrays. This recovers the items so they can be rendered as proper bullets.
    Returns None if the string does not look like a Python list repr.
    """
    s = value.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return None
    try:
        import ast

        parsed = ast.literal_eval(s)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except (ValueError, SyntaxError):
        pass
    return None


def _format_recommendation_cell(recommendation) -> str:
    """Render recommendation (dict tiered | list | str) into a docx cell string.

    Tiered dict → plain bullets (matching handmade style, no "Primary:"/"Secondary:" labels).
    List → bullets. Python list-repr string → parsed then bullets. Plain string → passthrough.
    """

    def _norm(value) -> str:
        if isinstance(value, dict):
            # Match handmade style: plain bullets, no tier labels
            lines: list[str] = []
            for key, _label in _REC_TIER_LABELS:
                val = value.get(key)
                if isinstance(val, str) and val.strip():
                    lines.append(f"- {val.strip()}")
            return "\n".join(lines)
        if isinstance(value, list):
            items = [str(x).strip() for x in value if str(x).strip()]
            return "\n".join(f"- {item}" for item in items)
        if isinstance(value, str):
            text = value.strip()
            # Detect and unwrap Python list repr (e.g. from small LLMs)
            parsed = _try_parse_python_list_repr(text)
            if parsed:
                return "\n".join(f"- {item}" for item in parsed)
            return text
        return ""

    return _norm(recommendation)


def _is_cwe_or_cve_ref(title: str, url: str) -> bool:
    """CWE/CVE entries belong in the CVE/CWE row, not Reference."""
    blob = f"{title} {url}".lower()
    if "cwe.mitre.org" in blob or "nvd.nist.gov" in blob:
        return True
    t = title.strip().upper()
    return t.startswith("CWE-") or t.startswith("CVE-") or t.startswith("NVD ")


def _format_reference_cell(reference) -> str:
    """Render reference (list of {title,url} | str) into a docx cell string.

    CWE/CVE/NVD entries are filtered out — those belong in the CVE/CWE row.
    """
    if isinstance(reference, list):
        lines: list[str] = []
        for item in reference:
            if isinstance(item, dict):
                title = (item.get("title") or "").strip()
                url = (item.get("url") or "").strip()
                if _is_cwe_or_cve_ref(title, url):
                    continue
                if title and url and title != url:
                    lines.append(title)
                elif url:
                    lines.append(url)
                elif title:
                    lines.append(title)
            elif isinstance(item, str) and item.strip():
                s = item.strip()
                if _is_cwe_or_cve_ref(s, ""):
                    continue
                lines.append(s)
        if lines:
            return "\n".join(lines)
        return ""
    if isinstance(reference, str):
        return re.sub(r"[;,]\s*CWE-\d+", "", reference).strip()
    return ""


def _normalize_report_text(value: str) -> str:
    text = str(value or "")
    text = text.replace("_x000D_", "\n")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\xa0", " ")
    text = "".join(
        ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C"
    )
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _looks_noisy_line(line: str) -> bool:
    stripped = str(line or "").strip()
    if not stripped:
        return False
    if re.fullmatch(r"[.\-\[\]]{3,}", stripped):
        return True
    if re.fullmatch(r"[- ]*snip[- ]*", stripped, re.IGNORECASE):
        return True
    if "_x000d_" in stripped.lower():
        return True

    visible = [ch for ch in stripped if not ch.isspace()]
    if len(visible) < 16:
        return False

    allowed_punct = set(".,:;/-_()[]{}'\"%#@&+=<>!?*|\\")
    weird = sum(1 for ch in visible if not (ch.isalnum() or ch in allowed_punct))
    punctuation = sum(1 for ch in visible if not ch.isalnum())
    alnum = sum(1 for ch in visible if ch.isalnum())

    weird_ratio = weird / len(visible)
    punctuation_ratio = punctuation / len(visible)
    alnum_ratio = alnum / len(visible)
    return weird_ratio >= 0.12 or (punctuation_ratio >= 0.45 and alnum_ratio <= 0.55)


def _looks_like_evidence_text(value: str) -> bool:
    text = _normalize_report_text(value)
    if _is_placeholder_text(text):
        return False

    lowered = text.lower()
    if any(
        token in lowered
        for token in (
            "response body snippet",
            "proof of concept",
            "steps to reproduce",
            "manual validation",
        )
    ):
        return True

    evidence_prefixes = (
        "file",
        "url",
        "request",
        "response",
        "payload",
        "step ",
        "nmap",
        "curl",
        "wget",
        "powershell",
    )
    lines = text.splitlines()
    evidence_lines = sum(
        1 for line in lines if line.lower().startswith(evidence_prefixes)
    )
    return evidence_lines >= 2 or any(_looks_noisy_line(line) for line in lines)


def _derive_audit_requirement(finding: dict) -> str:
    combined = " ".join(
        str(finding.get(field) or "")
        for field in ("name", "description", "control_name", "remediation")
    ).lower()

    keyword_fallbacks = [
        (
            ("backup files disclosure", "backup file", "backup disclosure"),
            "Review web roots and exposed directories for backup, temporary, and archive files. Verify that such files are removed or access-restricted and do not expose sensitive content.",
        ),
        (
            (
                "browsable web directories",
                "directory browsing",
                "directory listing",
                "autoindex",
            ),
            "Verify directory listing is disabled on the web server and confirm that sensitive directories, backup files, and static assets are not anonymously browsable.",
        ),
        (
            ("version disclosure", "server banner"),
            "Verify verbose server banners and application version strings are suppressed in HTTP responses, default pages, and error messages.",
        ),
        (
            ("unsupported version", "outdated", "end-of-life", "unsupported"),
            "Review software and operating system versions regularly and verify supported releases with current vendor security patches are in use.",
        ),
    ]
    for keywords, statement in keyword_fallbacks:
        if any(keyword in combined for keyword in keywords):
            return statement

    remediation = _normalize_report_text(finding.get("remediation", ""))
    if not _is_placeholder_text(remediation):
        first_sentence = re.split(r"(?<=[.!?])\s+", remediation, maxsplit=1)[0].strip()
        if first_sentence:
            return (
                "Verify that the recommended control is implemented and periodically reviewed: "
                + first_sentence
            )

    # No generic fallback — return empty so LLM detail lookup fills it with something specific.
    return ""


def _prepare_audit_requirement(finding: dict) -> str:
    audit_req = _normalize_report_text(finding.get("audit_requirement", ""))
    if _is_placeholder_text(audit_req) or _looks_like_evidence_text(audit_req):
        return _derive_audit_requirement(finding)
    return audit_req


def _prepare_proof_of_concept(finding: dict) -> str:
    return ""


def infer_severity_from_cvss(cvss_str: str) -> str:
    """Map a CVSS score string to a severity label. Returns '' if not parseable."""
    import re as _re

    m = _re.search(r"(\d+(?:\.\d+)?)", str(cvss_str or ""))
    if not m:
        return ""
    try:
        score = float(m.group(1))
    except ValueError:
        return ""
    for threshold, label in _CVSS_RANGES:
        if score >= threshold:
            return label
    return "Informational"


def infer_severity_from_keywords(name: str, description: str = "") -> str:
    """Infer severity from vulnerability name/description keywords. Returns '' if no match."""
    combined = (str(name or "") + " " + str(description or "")).lower()
    for severity, keywords in _SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in combined:
                return severity
    return ""


def _normalize_lookup_field_value(value):
    if isinstance(value, set):
        value = sorted(value, key=lambda item: str(item))
    if isinstance(value, (list, tuple)):
        # Preserve structured reference lists (list of {title,url} dicts)
        if any(isinstance(item, dict) for item in value):
            return list(value)
        parts = []
        for item in value:
            text = str(item or "").strip()
            if text:
                parts.append(text)
        return "; ".join(parts)
    # Preserve tiered recommendation dicts
    if isinstance(value, dict) and any(
        k in value for k in ("primary", "secondary", "defensive")
    ):
        return value
    return value


_EMPTY_FIELD_STRINGS = {"[PLACEHOLDER]", "[INSUFFICIENT DATA]", "", None}


def _is_empty_lookup_value(value) -> bool:
    """Return True only for scalar empties. Structured values (list/dict) count as filled."""
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return value in _EMPTY_FIELD_STRINGS


def _structured_field_is_generic(value, field: str) -> bool:
    """Return True if the value is known generic boilerplate for the given field."""
    if not isinstance(value, str):
        return False
    generic_set = _STRUCTURED_GENERIC_LOOKUP_VALUES.get(field, set())
    return value.strip() in generic_set or value.strip().lower() in {
        v.lower() for v in generic_set
    }


_TFIDF_CACHE: dict = {}


def _semantic_template_match(
    text: str, min_score: float = 0.30
) -> tuple[str, float] | None:
    """Return (keyword, score) best TF-IDF cosine match above threshold."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        return None

    if "vec" not in _TFIDF_CACHE:
        keys = list(_CONTROL_MAP.keys())
        corpus = []
        for k in keys:
            defaults = _CONTROL_MAP[k]
            corpus.append(
                k
                + " "
                + defaults.get("control_name", "")
                + " "
                + defaults.get("control_objective", "")
            )
        vec = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        try:
            mat = vec.fit_transform(corpus)
        except ValueError:
            _TFIDF_CACHE["vec"] = None
            return None
        _TFIDF_CACHE["vec"] = vec
        _TFIDF_CACHE["mat"] = mat
        _TFIDF_CACHE["keys"] = keys

    if _TFIDF_CACHE.get("vec") is None:
        return None

    vec = _TFIDF_CACHE["vec"]
    try:
        q = vec.transform([text])
    except ValueError:
        return None
    sims = cosine_similarity(q, _TFIDF_CACHE["mat"])[0]
    if len(sims) == 0:
        return None
    best_idx = int(sims.argmax())
    best_score = float(sims[best_idx])
    if best_score < min_score:
        return None
    return _TFIDF_CACHE["keys"][best_idx], best_score


_IPV4_HOST_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b")
_URL_HOST_RE = re.compile(
    r"https?://|\bwww\.|\.(?:com|net|org|io|app|local|internal)\b",
    re.IGNORECASE,
)

def _derive_category_from_finding(finding: dict) -> str:
    """Deterministically derive a category from affected_assets and vuln name.

    Tried in order: subnet from IP, URL/domain hint, keyword classification.
    Falls back to 'Network Infrastructure' so the validator never sees an
    empty value after deterministic backfill.
    """

    assets_blob = " ".join(
        str(finding.get(field) or "")
        for field in ("affected_assets", "affected_assets_raw", "category")
    )

    subnets: list[str] = []
    for host in _IPV4_HOST_RE.findall(assets_blob):
        parts = host.split(".")
        if len(parts) != 4:
            continue
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            continue
        if any(o < 0 or o > 255 for o in octets):
            continue
        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        if subnet not in subnets:
            subnets.append(subnet)

    if subnets:
        if len(subnets) == 1:
            return f"Internal Network - {subnets[0]}"
        return "Internal Network - Multiple Subnets"

    if _URL_HOST_RE.search(assets_blob):
        return "Web Application"

    haystack = (
        str(finding.get("name") or "") + " " + str(finding.get("description") or "")
    ).lower()
    for keywords, label in _CATEGORY_KEYWORDS:
        if any(kw in haystack for kw in keywords):
            return label

    return "Network Infrastructure"


def _derive_business_impact_from_finding(finding: dict) -> str:
    """Deterministically derive a business impact statement from severity + name.

    Severity-tiered template, name-substituted. Used as a guaranteed backfill so
    the structured validator never crashes after expensive detail lookup.
    """

    severity = str(finding.get("severity") or "").strip().title()
    name_raw = str(finding.get("name") or "").strip()
    name = name_raw if name_raw else "this finding"
    template = _BUSINESS_IMPACT_TEMPLATES.get(severity)
    if not template:
        template = _BUSINESS_IMPACT_TEMPLATES["Medium"]
    return template.format(name=name)


def fill_missing_fields(finding: dict) -> dict:
    """Normalize lookup fields and derive lightweight structural metadata only.

    Intentionally does not inject static control-objective/control-name/audit/reference
    filler so cloud/database enrichment remains the source of narrative detail.
    """
    for field in (
        "control_objective",
        "control_name",
        "audit_requirement",
        "reference",
    ):
        value = finding.get(field)
        normalized = _normalize_lookup_field_value(value)
        if normalized != value:
            finding[field] = normalized

    if _is_empty_lookup_value(finding.get("category")):
        finding["category"] = _derive_category_from_finding(finding)

    return finding


def _structured_field_is_incomplete(value, *, generic_values=()) -> bool:
    normalized = _normalize_lookup_field_value(value)
    text = str(normalized or "").strip()
    if _is_placeholder_text(text):
        return True
    return text in generic_values


def _too_short_or_boilerplate(field: str, value) -> bool:
    text = str(_normalize_lookup_field_value(value) or "").strip()
    if not text:
        return True
    if len(text) < _MIN_LEN.get(field, 0):
        return True
    low = text.lower()
    if field == "remediation":
        # Must have multi-tier remediation (3 lines) — lacking → LLM
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if len(lines) < 2:
            return True
        if any(p in low for p in _GENERIC_REMEDIATION_PHRASES) and len(text) < 120:
            return True
    return False


def _structured_finding_needs_llm_lookup(finding: dict) -> bool:
    for field in ("description", "remediation"):
        if _structured_field_is_incomplete(finding.get(field)):
            return True
        if _too_short_or_boilerplate(field, finding.get(field)):
            return True

    for field, generic_values in _STRUCTURED_GENERIC_LOOKUP_VALUES.items():
        if _structured_field_is_incomplete(
            finding.get(field), generic_values=generic_values
        ):
            return True
        if _too_short_or_boilerplate(field, finding.get(field)):
            return True

    return False


def _structured_value_is_less_specific(candidate, baseline) -> bool:
    candidate_text = str(_normalize_lookup_field_value(candidate) or "").strip()
    baseline_text = str(_normalize_lookup_field_value(baseline) or "").strip()

    if not candidate_text or not baseline_text:
        return False
    if candidate_text.casefold() == baseline_text.casefold():
        return False
    if candidate_text.casefold() in baseline_text.casefold():
        return True

    candidate_words = re.findall(r"[A-Za-z0-9]+", candidate_text)
    baseline_words = re.findall(r"[A-Za-z0-9]+", baseline_text)
    if len(candidate_words) <= 8 and len(baseline_words) >= 14:
        return True

    candidate_tokens = set(re.findall(r"[A-Za-z0-9]+", candidate_text.casefold()))
    baseline_tokens = set(re.findall(r"[A-Za-z0-9]+", baseline_text.casefold()))
    return bool(candidate_tokens) and candidate_tokens < baseline_tokens


def _structured_should_preserve_prior_value(
    prior_value,
    parsed_value,
    *,
    generic_values=(),
) -> bool:
    if _structured_field_is_incomplete(prior_value, generic_values=generic_values):
        return False
    if _structured_field_is_incomplete(parsed_value, generic_values=generic_values):
        return True
    return _structured_value_is_less_specific(parsed_value, prior_value)


def _merge_structured_lookup_result(finding: dict, parsed: dict) -> dict:
    merged = dict(parsed or {})

    for key, value in finding.items():
        if key not in merged or merged[key] in (
            None,
            "",
            "[INSUFFICIENT DATA]",
            "[PLACEHOLDER]",
        ):
            if key != "_web_search_context":
                merged[key] = value

    # Structured lookup must never mutate source-of-truth scan fields.
    for field in (
        "name",
        "severity",
        "cvss",
        "cve",
        "affected_assets",
        "observation",
        "remediation_status",
        "risk_status",
        "affected_assets_raw",
        "affected_assets_short",
    ):
        if field in finding:
            merged[field] = finding.get(field)

    for field in ("control_name", "reference"):
        if _structured_should_preserve_prior_value(
            finding.get(field),
            merged.get(field),
            generic_values=_STRUCTURED_GENERIC_LOOKUP_VALUES.get(field, ()),
        ):
            merged[field] = finding.get(field)

    for field in (
        "description",
        "business_impact",
        "control_objective",
        "audit_requirement",
        "remediation",
    ):
        if _structured_should_preserve_prior_value(
            finding.get(field),
            merged.get(field),
        ):
            merged[field] = finding.get(field)

    return merged


# ── Config ────────────────────────────────────────────────────────────────────

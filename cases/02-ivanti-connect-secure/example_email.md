Subject: [Detection] CVE-2023-46805, CVE-2024-21887 | Not covered, rule change proposed | Ivanti Connect Secure
To: detection-engineering@ashgrove.example

## What was found
- Active Exploitation of Two Zero-Day Vulnerabilities in Ivanti Connect Secure VPN
- Source: https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/
- Listed in CISA KEV since 2024-01-10, used in ransomware campaigns
- Earliest known exploitation: 2023-12-03
- Volexity found active exploitation of two chained zero-days in Ivanti Connect Secure (formerly Pulse Connect Secure). CVE-2023-46805 is an authentication bypass and CVE-2024-21887 is a command injection, together giving unauthenticated remote code execution. Suspicious activity on the appliance goes back to 3 December 2023. The attacker wiped logs and disabled logging, backdoored the legitimate compcheckresult.cgi and modified a JavaScript file to capture credentials. Requests chain paths under /api/v1/totp/user-backup-code/ with traversal to reach system maintenance and license endpoints.

## Why it matters to us
- Ivanti Connect Secure 22.3R1 on vpn01.ag.example, vpn02.ag.example (internet, high criticality). Version is in the affected range.

## Current coverage
Verdict: Not covered, rule change proposed.
- Not covered (uri): /api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection
- Not covered (uri): /api/v1/totp/user-backup-code/../../license/keys-status/
Related rules reviewed: Citrix NetScaler Known Exploit Paths; Path Traversal Sequences in Request URL; Pulse Secure and Ivanti Connect Secure Known Exploit Paths

## Proposed change (pull request: not opened yet)
Nothing is applied to the SIEM. Review the diff and merge the pull request if it looks right.

### UPDATE: rules/splunk/web_vpn_known_exploit_paths.yml
```diff
--- a/rules/splunk/web_vpn_known_exploit_paths.yml
+++ b/rules/splunk/web_vpn_known_exploit_paths.yml
@@ -1,7 +1,7 @@
 name: Pulse Secure and Ivanti Connect Secure Known Exploit Paths
 id: e8c20b57-1f3a-4d96-a7b1-5c9d0e4f2a80
-version: 2
+version: 3
 date: '2021-05-04'
-modification_date: '2022-01-20'
+modification_date: '2026-10-23'
 author: Ashgrove Detection Engineering
 status: production
@@ -10,5 +10,5 @@
 logsource: webserver
 search: |-
-  | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url IN ("*/dana/html5acc/guacamole/*", "*/dana-na/auth/url_admin/welcome.cgi*", "*/dana-ws/saml20.ws*") by Web.src Web.dest Web.http_method Web.url Web.status
+  | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url IN ("*/dana/html5acc/guacamole/*", "*/dana-na/auth/url_admin/welcome.cgi*", "*/dana-ws/saml20.ws*", "*/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection*", "*/api/v1/totp/user-backup-code/../../license/keys-status/*") by Web.src Web.dest Web.http_method Web.url Web.status
   | `drop_dm_object_name("Web")`
 how_to_implement: Needs the Web data model populated from the appliance HTTP logs or from a network sensor in front of it.
@@ -16,7 +16,11 @@
 references:
   - https://attack.mitre.org/techniques/T1190/
+  - https://research.splunk.com/web/1f32a7e0-a060-4545-b7de-73fcf9ad536e/
+  - https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/
 cve:
   - CVE-2019-11510
   - CVE-2021-22893
+  - CVE-2023-46805
+  - CVE-2024-21887
 mitre_attack_id:
   - T1190
```

## Replay check
Replay was not run (it needs a Sigma rule). Test the Splunk or Elastic change on sample data.

## Possible false positives
- Vulnerability scanners and authorised penetration tests requesting the same paths

## Sources
- https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/
- https://research.splunk.com/web/1f32a7e0-a060-4545-b7de-73fcf9ad536e/

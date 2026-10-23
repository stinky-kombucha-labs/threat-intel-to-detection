Subject: [Detection] CVE-2023-34362 | Not covered, rule change proposed | MOVEit Transfer
To: detection-engineering@ashgrove.example

## What was found
- Zero-Day Vulnerability in MOVEit Transfer Exploited for Data Theft
- Source: https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft
- Listed in CISA KEV since 2023-06-02, used in ransomware campaigns
- Earliest known exploitation: 2023-05-27
- Mandiant saw wide exploitation of a zero-day in MOVEit Transfer, announced by Progress on 31 May 2023 as CVE-2023-34362. The earliest evidence of exploitation is 27 May 2023. Attackers deployed the LEMURLOOT web shell under names that imitate the legitimate human.aspx, seen as human2.aspx and _human2.aspx in the MOVEit Transfer web root. POST requests to guestaccess.aspx before web shell use point to SQL injection. In some cases data theft happened minutes after the web shell was placed.

## Why it matters to us
- MOVEit Transfer 2022.1.3 on mft01.ag.example (internet, high criticality). Version is in the affected range.

## Current coverage
Verdict: Not covered, rule change proposed.
- Not covered (uri): /human2.aspx
- Not covered (uri): /_human2.aspx
- Not covered (dir): \MOVEit Transfer\wwwroot\
- Not covered (dir): \MOVEitTransfer\wwwroot\
Related rules reviewed: Generic Web Shell Requests; Citrix NetScaler Known Exploit Paths; Path Traversal Sequences in Request URL; Pulse Secure and Ivanti Connect Secure Known Exploit Paths; Server-Side Script File Created in Default IIS Web Root and 4 more

## Proposed change (pull request: not opened yet)
Nothing is applied to the SIEM. Review the diff and merge the pull request if it looks right.

### UPDATE: rules/splunk/web_generic_webshell_requests.yml
```diff
--- a/rules/splunk/web_generic_webshell_requests.yml
+++ b/rules/splunk/web_generic_webshell_requests.yml
@@ -1,7 +1,7 @@
 name: Generic Web Shell Requests
 id: 5e0b9a41-7d2c-4a6f-8c13-b4f7e1d90a68
-version: 3
+version: 4
 date: '2022-06-09'
-modification_date: '2023-02-17'
+modification_date: '2026-10-23'
 author: Ashgrove Detection Engineering
 status: production
@@ -10,5 +10,5 @@
 logsource: webserver
 search: |-
-  | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url IN ("*/cmd.aspx*", "*/shell.aspx*", "*/c99.php*", "*/r57.php*", "*/b374k.php*", "*/wso.php*") by Web.src Web.dest Web.http_method Web.url Web.status
+  | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url IN ("*/cmd.aspx*", "*/shell.aspx*", "*/c99.php*", "*/r57.php*", "*/b374k.php*", "*/wso.php*", "*/human2.aspx*", "*/_human2.aspx*") by Web.src Web.dest Web.http_method Web.url Web.status
   | `drop_dm_object_name("Web")`
 how_to_implement: Needs the Web data model populated from IIS, Apache or Nginx logs.
@@ -16,5 +16,8 @@
 references:
   - https://attack.mitre.org/techniques/T1505/003/
-cve: []
+  - https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023
+  - https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft
+cve:
+  - CVE-2023-34362
 mitre_attack_id:
   - T1505.003
```

### UPDATE: rules/sigma/file_event_win_script_in_iis_webroot.yml
```diff
--- a/rules/sigma/file_event_win_script_in_iis_webroot.yml
+++ b/rules/sigma/file_event_win_script_in_iis_webroot.yml
@@ -5,10 +5,14 @@
 references:
   - https://attack.mitre.org/techniques/T1505/003/
+  - https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023
+  - https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft
 author: Ashgrove Detection Engineering
 date: 2022-03-14
+modified: 2026-10-23
 tags:
   - attack.persistence
   - attack.t1505.003
   - product.windows_iis
+  - cve.2023-34362
 logsource:
   category: file_event
@@ -18,4 +22,6 @@
     TargetFilename|contains:
       - '\inetpub\wwwroot\'
+      - '\MOVEit Transfer\wwwroot\'
+      - '\MOVEitTransfer\wwwroot\'
     TargetFilename|endswith:
       - '.aspx'
```

## Replay check
| Rule | Test event | Old rule | New rule |
|---|---|---|---|
| rules/sigma/file_event_win_script_in_iis_webroot.yml | attack event (TargetFilename=\MOVEit Transfer\wwwroot\update.aspx) | no match | match |
| rules/sigma/file_event_win_script_in_iis_webroot.yml | benign event (TargetFilename=C:\Windows\Temp\notes.txt) | no match | no match |
| rules/sigma/file_event_win_script_in_iis_webroot.yml | benign event (TargetFilename=\MOVEit Transfer\wwwroot\readme.txt) | no match | no match |

## Possible false positives
- Vulnerability scanners and authorised penetration tests requesting the same paths
- Product upgrades and hotfixes that write script files into the web root
- Administrators deploying legitimate pages (check the change calendar)

## Sources
- https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft
- https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023

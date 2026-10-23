Subject: [Detection] CVE-2023-4966 | Not covered, rule change proposed | NetScaler Gateway
To: detection-engineering@ashgrove.example

## What was found
- Investigation of Session Hijacking via Citrix NetScaler ADC and Gateway Vulnerability (CVE-2023-4966)
- Source: https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966
- Listed in CISA KEV since 2023-10-18, used in ransomware campaigns
- Earliest known exploitation: 2023-08
- Citrix released a bulletin on 10 October 2023 for CVE-2023-4966 in NetScaler ADC and NetScaler Gateway. Mandiant saw zero-day exploitation from late August 2023. A GET request to /oauth/idp/.well-known/openid-configuration with an oversized HTTP Host header makes the appliance return memory contents, which can include a valid AAA session cookie. Session takeover bypasses passwords and multi-factor authentication. The web server on the appliance does not record requests to this endpoint, so evidence comes only from a WAF or other device that logs HTTP requests to the appliance.

## Why it matters to us
- NetScaler Gateway 13.1-48.47 on gw01.ag.example (internet, high criticality). Version is in the affected range.

## Current coverage
Verdict: Not covered, rule change proposed.
- Not covered (uri_long_host): /oauth/idp/.well-known/openid-configuration
Related rules reviewed: Citrix NetScaler Known Exploit Paths; Path Traversal Sequences in Request URL; Pulse Secure and Ivanti Connect Secure Known Exploit Paths

## Log source gaps
- NetScaler Gateway (gw01.ag.example) has no proxy or webserver logs in the SIEM, so a rule on 'uri_long_host' indicators cannot fire

## Proposed change (pull request: not opened yet)
Nothing is applied to the SIEM. Review the diff and merge the pull request if it looks right.

### NEW: rules/splunk/cve_2023_4966_uri_long_host.yml
```diff
--- /dev/null
+++ b/rules/splunk/cve_2023_4966_uri_long_host.yml
@@ -0,0 +1,28 @@
+name: CVE-2023-4966 NetScaler Gateway - Oversized Host Header
+id: 9b96fe13-78e8-5f3b-9b66-12f21658c0eb
+version: 1
+date: '2026-10-23'
+author: intel-to-rule (draft, requires analyst review)
+status: experimental
+type: TTP
+description: Detects oversized host header linked to CVE-2023-4966. Draft built from public reporting, requires analyst review before use.
+logsource: proxy
+search: |-
+  index=proxy url="*/oauth/idp/.well-known/openid-configuration*"
+  | eval host_length=len(http_host)
+  | where host_length>=150
+  | stats count min(_time) as firstTime max(_time) as lastTime by src dest url host_length
+how_to_implement: Needs the proxy log source in Splunk. Scope the saved search to gw01.ag.example.
+known_false_positives: Exposure-management scanners that send oversized Host headers; Normal OpenID discovery requests carry a short Host header, so only long values are suspicious
+references:
+  - https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966
+  - https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967
+  - https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966
+cve:
+  - CVE-2023-4966
+mitre_attack_id:
+  - T1190
+  - T1550.004
+inventory_products:
+  - netscaler_gateway
+level: high
```

## Replay check
Replay was not run (it needs a Sigma rule). Test the Splunk or Elastic change on sample data.

## Possible false positives
- Exposure-management scanners that send oversized Host headers
- Normal OpenID discovery requests carry a short Host header, so only long values are suspicious

## Notes
- The Host header length condition cannot be added to an existing list rule, so it is a new rule.

## Sources
- https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966
- https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966
- https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967

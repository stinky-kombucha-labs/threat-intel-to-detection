# Case 2: Ivanti Connect Secure (CVE-2023-46805 and CVE-2024-21887)

The company, hosts and the "before" rule are fictional. Attack facts come from the linked sources. Generated files
come from `py scripts/build_cases.py`.

## What happened

- Volexity published on 10 January 2024. Two chained zero-days gave unauthenticated command execution on Ivanti
  Connect Secure VPN appliances. CVE-2023-46805 is an authentication bypass and CVE-2024-21887 a command injection.
  Suspicious activity on the victim appliance went back to 3 December 2023. The attacker wiped logs, disabled logging
  and backdoored the legitimate `compcheckresult.cgi`.
  ([Volexity](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/))
- Both CVEs entered CISA KEV on 10 January 2024, flagged as used in ransomware campaigns.
- Exploit requests use paths under `/api/v1/totp/user-backup-code/` with `../../` to reach maintenance and license
  endpoints ([Splunk detection](https://research.splunk.com/web/1f32a7e0-a060-4545-b7de-73fcf9ad536e/)).

## Our fictional setup

Two Ivanti Connect Secure appliances, `vpn01` and `vpn02`, version 22.3R1, exposed to the internet. HTTP requests
reach the SIEM through the Web data model.

## The rule before

"Pulse Secure and Ivanti Connect Secure Known Exploit Paths" (Splunk, tagged with the product) listed paths from the
2019 and 2021 Pulse Secure vulnerabilities (CVE-2019-11510, CVE-2021-22893). The new paths were not in it.

The generic "Path Traversal Sequences in Request URL" rule did not help. It looks for three consecutive `../`, and the
exploit path has two, so it stays silent.

## What the pipeline did

1. Merged the Volexity post with both KEV records into one finding (the second CVE does not create a second alert).
2. Matched the product alias "Pulse Connect Secure" and "Ivanti Connect Secure" to the inventory.
3. Found the product-tagged rule as the best candidate and added both exploit paths to its `Web.url IN (...)` list.
4. Updated `version`, `modification_date`, `cve` and `references`, so the diff stays small and reviewable.

See [`rule.diff`](rule.diff) and [`example_email.md`](example_email.md).

## What still needs a human

- The Splunk Security Content version of this detection only alerts on HTTP status 200. Our rule does not filter on
  status, so it also shows failed attempts. Decide if that is the right trade-off for this appliance.
- The attacker removed logs on the appliance itself. Detection must rely on a copy of the traffic (network sensor,
  proxy) and not on the device. The email says this, the rule cannot fix it.
- A detection of requests does not show whether the appliance was already compromised. The Ivanti integrity checker
  and an external scan are separate steps.

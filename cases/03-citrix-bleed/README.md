# Case 3: Citrix Bleed (CVE-2023-4966)

The company, hosts and the "before" rules are fictional. Attack facts come from the linked sources. Generated files
come from `py scripts/build_cases.py`.

## What happened

- Citrix published a bulletin on 10 October 2023. Mandiant saw zero-day exploitation from late August 2023.
  A GET request to `/oauth/idp/.well-known/openid-configuration` with an oversized Host header makes the appliance
  return memory, which can contain a valid session cookie. Session takeover bypasses the password and MFA.
  ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966))
- The appliance web server does not log requests to that endpoint. Evidence has to come from a WAF or another device
  that records HTTP requests to the appliance (same Mandiant post).
- CISA added it to KEV on 18 October 2023, flagged as used in ransomware campaigns.
- The public Sigma rule from SigmaHQ matches that path with a Host header of at least 150 characters.
  ([rule](https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/Exploits/CVE-2023-4966/web_exploit_cve_2023_4966_citrix_sensitive_information_disclosure_exploit_attempt.yml))
  The vulnerable function and fixed versions are described by
  [Assetnote](https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966).

## Our fictional setup

One NetScaler Gateway on `gw01.nw.example`, version 13.1-48.47 (fixed in 13.1-49.15). The SIEM gets appliance syslog
and firewall logs. There is no WAF and no reverse proxy in front of it.

## The rule before

"Citrix NetScaler Known Exploit Paths" (Splunk) covered the July 2023 CVE-2023-3519 paths. The OpenID discovery path
is a normal request, so a path-only rule would alert on every legitimate login flow. The signal is the Host header
length, and no existing rule checked it.

## What the pipeline did

1. Extracted the path together with its condition (Host header length 150 or more) as a conditional indicator.
2. Concluded that this cannot be added to a list, because adding the path alone would alert on normal traffic.
   It wrote a new Splunk rule with `host_length>=150` on the proxy index.
3. Flagged a **log source gap** in the email. The inventory shows `gw01` has no proxy or web server logs in the SIEM,
   so the new rule would never fire until a WAF or proxy feed is onboarded.

See [`rule.diff`](rule.diff) and [`example_email.md`](example_email.md).

## What still needs a human

- Onboard HTTP logs for the appliance. Without them the rule is correct but useless, and the email says so.
- Patch to a fixed version and kill active sessions. Rules do not undo session theft.
- Behavioural detection (the same session ID from two source IPs) needs appliance authentication logs and a
  correlation search. The pipeline does not write correlation searches yet, see the limitations in the main README.

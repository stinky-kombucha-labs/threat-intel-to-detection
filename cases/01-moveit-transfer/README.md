# Case 1: MOVEit Transfer (CVE-2023-34362)

A worked example of the pipeline on a real public attack. The company, hosts and the "before" rules are fictional.
The attack facts come from the sources linked below. Everything under `before/`, `after/`, `generated/`,
`rule.diff` and `example_email.md` is produced by `py scripts/build_cases.py` from the offline fixtures.

## What happened

- Progress announced the MOVEit Transfer vulnerability on 31 May 2023. Mandiant found the earliest exploitation on
  27 May 2023 and described a web shell, LEMURLOOT, deployed under names that imitate the legitimate `human.aspx`:
  `human2.aspx` and `_human2.aspx`. SQL injection requests to `guestaccess.aspx` came first.
  ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft))
- CISA added it to KEV on 2 June 2023, flagged as used in ransomware campaigns.
- Public Sigma rules for this CVE look for the two file names and for files under the MOVEit web root
  ([example](https://sigma.controlassurance.com/rules/file_event_win_exploit_cve_2023_34362_moveit_transfer/)).

## Our fictional setup

Ashgrove runs MOVEit Transfer 2022.1.3 on `mft01.ag.example`, exposed to the internet (version 2022.1.5 fixed it).
The SIEM receives IIS logs and Sysmon file events from that host.

## The rules before

| Rule | Format | What it does | Why it missed |
|---|---|---|---|
| Server-Side Script File Created in Default IIS Web Root | Sigma | Alerts on `.aspx`, `.ashx`, `.asmx` created under `\inetpub\wwwroot\` | MOVEit does not use `inetpub`. Its web root is `\MOVEit Transfer\wwwroot\`, so the web shell drop was invisible. |
| Generic Web Shell Requests | Splunk | Alerts on requests to `cmd.aspx`, `shell.aspx`, `c99.php` and similar | The list had no `human2.aspx`, so later requests to the web shell did not alert. |

## What the pipeline did

1. Read the Mandiant post (recorded extraction in `data/fixtures/items/moveit.json`) and the KEV record.
2. Matched "MOVEit Transfer" to the inventory and checked the version, 2022.1.3 is below the fixed 2022.1.5.
3. Compared the indicators with all rules. None covered the two URIs or the MOVEit web root.
4. Extended the two closest rules in their own formats instead of writing new ones.
5. Replayed a synthetic attack event against the old and new Sigma rule. The old one stayed silent, the new one fired.
   A benign file in the same folder did not fire.

See [`rule.diff`](rule.diff) for the exact change and [`example_email.md`](example_email.md) for the message the analyst gets.

## What still needs a human

- The `\MOVEit Transfer\wwwroot\` rule covers every new script in that folder. MOVEit upgrades also write files there,
  so tune it with the change calendar.
- `guestaccess.aspx` is a legitimate page. The SQL injection that reaches it needs request body or WAF visibility,
  which this log setup does not have.
- Data theft can be seen only with outbound volume and database or storage logs. A rule change cannot replace
  a threat hunt on `mft01`.

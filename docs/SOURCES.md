# References and credits

No code was copied from the projects below. They were read for ideas, formats and facts, and the pipeline depends on
the libraries marked as dependencies.

**Dependencies**

- [pySigma](https://github.com/SigmaHQ/pySigma), [pySigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk)
  and [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch) convert Sigma to SPL and Lucene.
- [PyYAML](https://github.com/yaml/pyyaml) parses rules and config.

**Related projects and formats**

- [christina23/kitsune](https://github.com/christina23/kitsune) starts from one threat report URL and generates Sigma
  rules for gaps in a baseline corpus. This project differs by monitoring feeds, filtering by an asset inventory,
  checking log source availability and editing rules in their native format.
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) defines the Sigma format. The public rules for MOVEit and Citrix
  Bleed served as references for the case studies.
- [splunk/security_content](https://github.com/splunk/security_content) is the model for the Splunk detection YAML
  layout and the source of the public Ivanti Connect Secure detection the Ivanti case compares against.
- [edwardjgriggs/detection-as-code](https://github.com/edwardjgriggs/detection-as-code) and
  [infosecB/detection-as-code](https://github.com/infosecB/detection-as-code) are examples of validating and
  converting Sigma rules in CI.

**Data sources**

- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (public domain),
  schema in [cisagov/kev-data](https://github.com/cisagov/kev-data).
- [NVD API 2.0](https://nvd.nist.gov/developers/start-here). This product uses data from the NVD API but is not
  endorsed or certified by the NVD.

**Case study sources**

- MOVEit: [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft),
  [Progress advisory](https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023).
- Ivanti Connect Secure: [Volexity](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/),
  [Splunk detection](https://research.splunk.com/web/1f32a7e0-a060-4545-b7de-73fcf9ad536e/).
- Citrix Bleed: [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966),
  [Assetnote](https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966),
  [Citrix bulletin](https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967).

Report texts in `data/fixtures/` are short paraphrases of these sources, not copies.


# Online Validation

## Scope

This validation used public documentation, standards, public reports, and public GitHub repositories only.

It did not probe, fuzz, brute-force, exploit, crawl, or actively test any third-party website. The goal was to validate whether K-Guard MCP is aligned with real security needs and market direction.

Product direction note: K-Guard itself now supports authorized external-origin dynamic probes when the operator records ownership, partner approval, bug-bounty scope, configured allowlist, or dashboard domain proof. This online validation document is still only a public-source validation record.

## Conclusion

K-Guard MCP's direction is externally validated.

The strongest support comes from five independent signals:

1. AI-generated/vibe-coded code is measurably insecure often enough to justify a pre-deploy security gate.
2. OWASP still treats broken access control, exposed metadata, backup files, and CORS mistakes as core web risk.
3. MCP's own official documentation now highlights authorization, consent, tool visibility, and security best practices.
4. The market already has MCP/agent scanners, proving demand, but most focus on generic MCP/agent risks rather than Korean privacy flow.
5. Korean privacy rules and public guidance support K-Guard's focus on resident registration numbers, passport numbers, driver license numbers, foreign registration numbers, and broader personal-data categories.

## Evidence

| Claim | Online validation | K-Guard implication |
|---|---|---|
| Vibe-coded/AI-generated code needs security review | Veracode reported that 45% of AI-generated code samples failed security tests; Java had a 72% failure rate. | A pre-deploy MCP security gate is a real need, not a toy scanner idea. |
| Broken access control and IDOR/BOLA remain core web risks | OWASP A01 says access-control failures can cause unauthorized disclosure/modification/destruction, and specifically mentions IDOR, CORS mistakes, force browsing, exposed `.git`, and backup files. | K-Guard's admin/API checks, bounded deep exposure paths, and future IDOR/RLS rules are well aligned. |
| MCP security needs explicit authorization and consent | MCP official docs say authorization is strongly recommended for user-specific data, auditability, enterprise access controls, and rate limiting. MCP tool docs also recommend visible tools and human-in-the-loop confirmation. | K-Guard's disabled-by-default dynamic probe, separate session/deep-active opt-ins, and MCP config scanning fit the official security direction. |
| Deployed apps need real runtime confirmation | OWASP A01 explicitly includes force browsing, IDOR, CORS mistakes, exposed `.git`, backup files, and unauthorized access to privileged pages. | K-Guard should not stop at static review; it needs authorized external read-only probes against actual deployed origins. |
| MCP security scanners are an existing market category | Public tools such as Snyk Agent Scan, Ant Group MCPScan, MCP-Shield, Agentic Radar, Cisco AI Defense MCP Scanner, and Invariant MCP-Scan already scan MCP/agent risks. | Demand is validated. K-Guard should differentiate on Korean privacy, raw-free evidence graph, runtime MCP observer, local connectors, and cross-plane PII-to-sink verdicts. |
| Korean privacy-specific detection matters | Korean legal/public guidance recognizes unique identifiers such as resident registration number, passport number, driver license number, and foreign registration number; privacy portal materials also discuss broader personal-data categories. | K-Guard's Korean PII and composite PII corpus is a strong differentiator, not a generic regex feature. |

## Source Notes

- Veracode 2025 GenAI Code Security Report summary: https://www.veracode.com/blog/genai-code-security-report/
- OWASP A01 Broken Access Control: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MCP Security Best Practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- MCP Authorization: https://modelcontextprotocol.io/docs/tutorials/security/authorization
- MCP Tools trust/safety guidance: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- Korean unique identifier guidance: https://www.easylaw.go.kr/CSP/CnpClsMainBtr.laf?ccfNo=2&cciNo=3&cnpClsNo=2&csmSeq=1257&menuType=onhunqna&popMenu=ov
- Korean privacy guideline source page: https://www.law.go.kr/LSW//admRulLsInfoP.do?admRulId=73445&efYd=0
- Snyk Agent Scan: https://github.com/snyk/agent-scan
- Ant Group MCPScan: https://github.com/antgroup/MCPScan
- MCP-Shield: https://github.com/riseandignite/mcp-shield
- Agentic Radar: https://github.com/splx-ai/agentic-radar
- Cisco AI Defense MCP Scanner: https://github.com/cisco-ai-defense/mcp-scanner

## Market Gap K-Guard Can Own

Existing MCP/agent security scanners validate the category but leave space for K-Guard:

- Korean privacy-aware detection and explanations.
- Composite personal-data judgment, not just standalone regex hits.
- Raw-free evidence graph that can be shown to users without leaking the data being audited.
- Runtime MCP observer for tool result -> LLM/MCP/external sink flow.
- Read-only local SQLite/log/storage connectors.
- Retention/deletion marker review.
- Dashboard for non-security vibe coders.
- MCP workflows and installation paths for ChatGPT, Grok, Codex, and Antigravity. Other client configuration files remain audit inputs only.

## Guardrail

Online validation supports the product opportunity and technical direction. It does not prove legal compliance, zero false positives/false negatives, or all-domain L5 audit completeness.

Next validation should be:

- independent Korean privacy corpus,
- real pilot with consenting users,
- competitor dogfood benchmark against the listed scanners,
- large repository performance benchmark,
- deeper inter-procedural JS/TS type/framework analysis and transport coverage beyond the current stdio JSON-RPC proxy.

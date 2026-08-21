# References — Verification Tracker

Companion to `docs/LITERATURE.md`. "Verified = yes" means the canonical source page
(arXiv abstract, publisher page, or an authoritative index) was fetched during the
literature session and the title, author list, and identifier were confirmed from it.
"needs-check" means the reference is real and its identifier confirmed, but one listed
detail (usually the final venue string, page range, or DOI) was **not** confirmed from
a primary source and must be checked before camera-ready.

| # | Citation (IEEE format) | DOI / arXiv ID | Venue | Year | Verified? |
|---|---|---|---|---|---|
| 1 | Y. Liu, G. Deng, Y. Li, K. Wang, Z. Wang, X. Wang, T. Zhang, Y. Liu, H. Wang, Y. Zheng, L. Y. Zhang, and Y. Liu, "Prompt injection attack against LLM-integrated applications," arXiv:2306.05499, 2023. | arXiv:2306.05499 | arXiv preprint (check for a peer-reviewed version) | 2023 | yes (venue needs-check) |
| 2 | Y. Liu, Y. Jia, R. Geng, J. Jia, and N. Z. Gong, "Formalizing and benchmarking prompt injection attacks and defenses," in *Proc. 33rd USENIX Security Symposium*, 2024. | arXiv:2310.12815 | USENIX Security | 2024 | yes |
| 3 | X. Liu, Z. Yu, Y. Zhang, N. Zhang, and C. Xiao, "Automatic and universal prompt injection attacks against large language models," arXiv:2403.04957, 2024. | arXiv:2403.04957 | arXiv preprint | 2024 | yes |
| 4 | E. Wallace, K. Xiao, R. Leike, L. Weng, J. Heidecke, and A. Beutel, "The instruction hierarchy: Training LLMs to prioritize privileged instructions," arXiv:2404.13208, 2024. | arXiv:2404.13208 | arXiv preprint | 2024 | yes |
| 5 | K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, "Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection," arXiv:2302.12173, 2023. | arXiv:2302.12173 | Published version appeared at the ACM Workshop on Artificial Intelligence and Security (AISec) — confirm exact venue string and pages | 2023 | yes (venue needs-check) |
| 6 | Q. Zhan, Z. Liang, Z. Ying, and D. Kang, "InjecAgent: Benchmarking indirect prompt injections in tool-integrated large language model agents," in *Findings of the ACL: ACL 2024*, 2024. | arXiv:2403.02691 | ACL 2024 Findings | 2024 | yes (page range needs-check) |
| 7 | Y. Ruan, H. Dong, A. Wang, S. Pitis, Y. Zhou, J. Ba, Y. Dubois, C. J. Maddison, and T. Hashimoto, "Identifying the risks of LM agents with an LM-emulated sandbox," arXiv:2309.15817, 2023. | arXiv:2309.15817 | arXiv preprint (ICLR 2024 acceptance claimed elsewhere — confirm) | 2023 | yes (venue needs-check) |
| 8 | E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and F. Tramèr, "AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents," in *NeurIPS Datasets and Benchmarks Track*, 2024. | arXiv:2406.13352 | NeurIPS 2024 D&B Track | 2024 | yes (exact venue string needs-check) |
| 9 | M. Andriushchenko et al., "AgentHarm: A benchmark for measuring harmfulness of LLM agents," in *Proc. ICLR*, 2025. | arXiv:2410.09024 | ICLR | 2025 | yes |
| 10 | H. Zhang, J. Huang, K. Mei, Y. Yao, Z. Wang, C. Zhan, H. Wang, and Y. Zhang, "Agent Security Bench (ASB): Formalizing and benchmarking attacks and defenses in LLM-based agents," in *Proc. ICLR*, 2025. | arXiv:2410.02644 | ICLR | 2025 | yes |
| 11 | K. Hines, G. Lopez, M. Hall, F. Zarfati, Y. Zunger, and E. Kiciman, "Defending against indirect prompt injection attacks with spotlighting," arXiv:2403.14720, 2024. | arXiv:2403.14720 | arXiv preprint | 2024 | yes |
| 12 | S. Chen, J. Piet, C. Sitawarin, and D. Wagner, "StruQ: Defending against prompt injection with structured queries," in *Proc. 34th USENIX Security Symposium*, 2025. | arXiv:2402.06363 | USENIX Security | 2025 | yes |
| 13 | S. Chen, A. Zharmagambetov, S. Mahloujifar, K. Chaudhuri, D. Wagner, and C. Guo, "SecAlign: Defending against prompt injection with preference optimization," in *Proc. ACM CCS*, 2025. | arXiv:2410.05451 | ACM CCS | 2025 | yes (pages needs-check) |
| 14 | A. C. Myers and B. Liskov, "A decentralized model for information flow control," in *Proc. 16th ACM SOSP*, 1997, pp. 129–142. | 10.1145/268998.266669 | ACM SOSP | 1997 | yes (via ACM DL / DBLP index) |
| 15 | A. Sabelfeld and A. C. Myers, "Language-based information-flow security," *IEEE J. Sel. Areas Commun.*, vol. 21, no. 1, pp. 5–19, 2003. | 10.1109/JSAC.2002.806121 | IEEE JSAC | 2003 | yes (via publisher-hosted PDF) |
| 16 | E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern, C. Shi, A. Terzis, and F. Tramèr, "Defeating prompt injections by design," arXiv:2503.18813, 2025. | arXiv:2503.18813 | arXiv preprint | 2025 | yes |
| 17 | L. Beurer-Kellner et al., "Design patterns for securing LLM agents against prompt injections," arXiv:2506.08837, 2025. | arXiv:2506.08837 | arXiv preprint | 2025 | yes |
| 18 | F. Wu, E. Cecchetti, and C. Xiao, "System-level defense against indirect prompt injection attacks: An information flow control perspective," arXiv:2409.19091, 2024. | arXiv:2409.19091 | arXiv preprint | 2024 | yes |
| 19 | Y. Wu, F. Roesner, T. Kohno, N. Zhang, and U. Iqbal, "IsolateGPT: An execution isolation architecture for LLM-based agentic systems," in *Proc. NDSS*, 2025. | arXiv:2403.04960 | NDSS | 2025 | yes |
| 20 | OWASP Foundation, "MCP03:2025 – Tool poisoning," *OWASP MCP Top 10*, 2025. | — (project URL) | OWASP project page | 2025 | yes |
| 21 | Z. Wang, Y. Gao, Y. Wang, S. Liu, H. Sun, H. Cheng, G. Shi, H. Du, and X. Li, "MCPTox: A benchmark for tool poisoning attack on real-world MCP servers," arXiv:2508.14925, 2025. | arXiv:2508.14925 | arXiv preprint | 2025 | yes |
| 22 | Y. Guo, P. Liu, W. Ma, Z. Deng, X. Zhu, P. Di, X. Xiao, and S. Wen, "MCPXKIT: The unified toolkit for analyzing Model Context Protocol security," arXiv:2508.12538, 2025. | arXiv:2508.12538 | arXiv preprint | 2025 | yes |
| 23 | B. Wang, Z. Liu, H. Yu, A. Yang, Y. Huang, J. Guo, H. Cheng, H. Li, and H. Wu, "MCPGuard: Automatically detecting vulnerabilities in MCP servers," arXiv:2510.23673, 2025. | arXiv:2510.23673 | arXiv preprint | 2025 | yes |
| 24 | E. Perez, S. Huang, F. Song, T. Cai, R. Ring, J. Aslanides, A. Glaese, N. McAleese, and G. Irving, "Red teaming language models with language models," in *Proc. EMNLP*, 2022. | arXiv:2202.03286 | EMNLP | 2022 | yes (venue + pages needs-check) |
| 25 | P. Chao, A. Robey, E. Dobriban, H. Hassani, G. J. Pappas, and E. Wong, "Jailbreaking black box large language models in twenty queries," arXiv:2310.08419, 2023. | arXiv:2310.08419 | arXiv preprint | 2023 | yes |
| 26 | T. Shi, J. He, Z. Wang, H. Li, L. Wu, W. Guo, and D. Song, "Progent: Securing AI agents with privilege control," arXiv:2504.11703, 2025. | arXiv:2504.11703 | arXiv preprint | 2025 | yes |
| 27 | Anthropic, "Model Context Protocol specification." | — | Online specification | — | needs-check (pin the exact spec revision the evaluation agent targets) |

## Outstanding checks before camera-ready

- **#27** — not fetched this session; pin the spec revision string.
- **Venue strings** for #1, #5, #7, #8, #24: identifier and authors confirmed, final
  publication venue not confirmed from a primary source.
- **Page ranges** for #6, #13, #24.
- Recheck #1 and #7 for a peer-reviewed version superseding the preprint.

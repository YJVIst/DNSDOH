# DNSDOH development constraints

- This is an independent Rust / MariaDB private DoH product with a Chinese admin dashboard and multiple independently deployed DoH nodes.
- Work alone. Do not delegate to other agents.
- All project files, dependency caches, build outputs and runtime/test data must live under `/mnt/youlin-data`.
- Do not create or push a GitHub repository until the user explicitly authorizes publication after acceptance.
- Do not commit credentials, generated runtime configuration, databases, certificates or tokens. Do not log token-bearing request paths.
- Cloudflare credentials are authorized for DNSDOH tests and deployment; never persist them in the repository or print them. Read existing DNS records before changing only dedicated DNSDOH names. Do not overwrite unrelated records.
- Test against real MariaDB, real DNS wire messages, two node processes, and the actual dashboard. Record limits honestly: two local node processes are not multi-region validation.
- Document bounded token revocation propagation and DNS cache effects. Never claim a DNS token revokes already established node/proxy connections.

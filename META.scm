;; SPDX-License-Identifier: PMPL-1.0-or-later
;; META.scm - Architectural decisions and project meta-information for seambot
;; Media-Type: application/meta+scheme

(define-meta seambot
  (version "1.0.0")

  (architecture-decisions
    ((adr-001 accepted "2026-01-30"
      "Need to establish repository structure and standards"
      "Adopt RSR (Rhodium Standard Repository) conventions from rsr-template-repo"
      "Ensures consistency with 500+ repos in hyperpolymath ecosystem.")

     (adr-002 accepted "2026-01-30"
      "Seam boundaries need a machine-readable representation"
      "Use JSON seam register format with explicit boundary declarations,
       conformance examples, and freeze stamps for version pinning."
      "Enables automated verification. Human-readable and machine-parseable.
       Schema is extensible for future seam types.")

     (adr-003 accepted "2026-01-30"
      "Need to detect undeclared coupling across architectural boundaries"
      "Implement hidden channel detection covering imports, global state,
       filesystem coupling, database coupling, network calls, and env vars."
      "Catches the most insidious form of architecture rot — coupling that
       bypasses declared interfaces. Six channel types cover the main vectors
       of undeclared dependency.")

     (adr-004 accepted "2026-01-30"
      "Architecture evolves but changes should be tracked"
      "Implement drift detection against freeze stamps. A freeze stamp is an
       immutable SHA-256 hash of the seam state at a release point. Any
       subsequent change to a seam interface is detected as drift."
      "Provides an audit trail of architectural evolution. Makes intentional
       refactoring visible and accidental coupling detectable.")

     (adr-005 accepted "2026-02-05"
      "Need to support multiple code forges for seam analysis"
      "Multi-forge abstraction with GitHub, GitLab, and Bitbucket adapters.
       Common trait interface with forge-specific implementations."
      "Enables seambot to work across the entire .git-private-farm mirror
       network. Findings are consistent regardless of which forge hosts
       the repository.")

     (adr-006 proposed "2026-02-05"
      "Seam contracts could benefit from formal verification"
      "Integrate with echidnabot to formally verify seam invariants.
       If a seam declares a contract (e.g. 'this API always returns valid JSON'),
       echidnabot could prove this holds using Coq/Lean/Z3."
      "Would provide mathematical guarantees about architectural boundaries.
       Requires echidnabot's multi-prover infrastructure to be accessible.")))

  (development-practices
    (code-style
      "Rust with rustfmt defaults. Modules organized by concern:
       seam.rs (data structures), checks.rs (analysis), register.rs (I/O),
       hidden_channels.rs (detection), github.rs (forge), report.rs (output).")
    (security
      "JWT/RSA for forge authentication. SHA-256 for freeze stamp hashing.
       No shell injection vectors. CORS not applicable (CLI tool).
       Hypatia neurosymbolic scanning enabled.")
    (testing
      "Unit tests for all analysis modules. Integration tests for forge APIs.
       SARIF output validation against specification.")
    (versioning "Semantic versioning (semver).")
    (documentation "README.adoc for overview. Seam register schema documented inline.")
    (branching "Main branch protected. Feature branches for new work. PRs required."))

  (design-rationale
    (why-seams-matter
      "Architecture rot is the #1 cause of technical debt in large systems.
       It happens silently at boundaries — when interfaces drift, when
       undeclared coupling creeps in, when what was designed diverges from
       what was built. Seambot makes this invisible rot visible and measurable.")
    (why-freeze-stamps
      "Release points need architectural snapshots, not just code snapshots.
       A git tag captures code state but not architectural intent. Freeze stamps
       capture the intended seam boundaries at each release, making it possible
       to track how architecture evolves across versions.")
    (why-hidden-channels
      "Declared interfaces are easy to audit. It is the undeclared coupling —
       shared global state, filesystem conventions, implicit database schemas,
       environment variable contracts — that causes the hardest bugs. Hidden
       channel detection finds exactly these invisible dependencies.")
    (why-finisher-tier
      "Seambot is a Finisher (not Verifier) because it needs structural
       findings from rhodibot to understand repo layout before analyzing
       seam boundaries. The tier system ensures correct execution order.")))

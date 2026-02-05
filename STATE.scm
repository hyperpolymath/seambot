;; SPDX-License-Identifier: PMPL-1.0-or-later
;; STATE.scm - Project state tracking for seambot
;; Media-Type: application/vnd.state+scm

(define-state seambot
  (metadata
    (version "0.2.0")
    (schema-version "1.0.0")
    (created "2026-01-30")
    (updated "2026-02-05")
    (project "seambot")
    (repo "hyperpolymath/seambot"))

  (project-context
    (name "seambot")
    (tagline "Architectural seam hygiene auditor — tracks, enforces, and detects drift in architectural boundaries")
    (tech-stack
      "Rust 1.83+"
      "Tokio async runtime"
      "Clap CLI framework"
      "Reqwest HTTP client"
      "SHA2 cryptographic hashing"
      "JSONWebToken + RSA (forge auth)"
      "Serde JSON/YAML"
      "Multi-forge abstraction (GitHub, GitLab, Bitbucket)"))

  (current-position
    (phase "active-development")
    (overall-completion 60)
    (components
      (("Seam Register" . ((status . "complete") (completion . 100)
         (description . "JSON-based seam register format defining architectural boundaries")))
       ("Register Verification" . ((status . "complete") (completion . 100)
         (description . "Validates seam register completeness and structural correctness")))
       ("Conformance Checking" . ((status . "complete") (completion . 100)
         (description . "Verifies examples exist and demonstrate correct seam usage")))
       ("Drift Detection" . ((status . "complete") (completion . 100)
         (description . "Detects changes to seam interfaces since baseline freeze stamps")))
       ("Freeze Stamps" . ((status . "complete") (completion . 100)
         (description . "Immutable seam state snapshots at release points")))
       ("Hidden Channel Detection" . ((status . "partial") (completion . 60)
         (description . "Detects undeclared coupling across boundaries")
         (implemented . ("Undeclared imports" "Shared global state" "Filesystem coupling"))
         (planned . ("Database coupling" "Network calls" "Environment variables"))))
       ("Multi-Forge Support" . ((status . "complete") (completion . 100)
         (description . "GitHub, GitLab, Bitbucket webhook integration")))
       ("Output Formats" . ((status . "complete") (completion . 100)
         (description . "Text, JSON, Markdown, SARIF for CI integration")))
       ("CLI Interface" . ((status . "complete") (completion . 100)
         (description . "Full CLI with verify, check, drift, freeze, hidden-channels commands")))
       ("GitHub App Integration" . ((status . "partial") (completion . 40)
         (description . "Webhook handlers, check runs on PRs")))
       ("Auto-fix" . ((status . "planned") (completion . 0)
         (description . "Automatic seam register updates for simple drift")))))
    (working-features
      "Seam register JSON schema and validation"
      "Register completeness verification (all boundaries documented)"
      "Conformance examples checking (examples prove correct usage)"
      "Drift detection against freeze stamps (interface changes over time)"
      "Freeze stamp creation and validation (immutable release snapshots)"
      "Hidden channel detection: undeclared imports across boundaries"
      "Hidden channel detection: shared global state"
      "Hidden channel detection: filesystem coupling"
      "Multi-forge abstraction (GitHub, GitLab, Bitbucket)"
      "Multiple output formats (text, JSON, Markdown, SARIF)"
      "CLI with verify, check, drift, freeze, hidden-channels subcommands"))

  (route-to-mvp
    (milestones
      ((name "Core Seam Analysis")
       (status "complete")
       (completion 100)
       (items
         ("Seam register JSON format" . done)
         ("Register verification" . done)
         ("Conformance checking" . done)
         ("Drift detection" . done)
         ("Freeze stamps" . done)
         ("CLI interface" . done)))

      ((name "Hidden Channel Detection")
       (status "in-progress")
       (completion 60)
       (items
         ("Import analysis" . done)
         ("Global state detection" . done)
         ("Filesystem coupling" . done)
         ("Database coupling" . todo)
         ("Network call detection" . todo)
         ("Environment variable leakage" . todo)))

      ((name "Forge Integration")
       (status "in-progress")
       (completion 50)
       (items
         ("Multi-forge abstraction" . done)
         ("GitHub webhook handlers" . in-progress)
         ("GitLab integration" . in-progress)
         ("Bitbucket integration" . in-progress)
         ("Check runs on PRs" . in-progress)))

      ((name "Fleet Integration & Release")
       (status "planned")
       (completion 0)
       (items
         ("Gitbot-fleet shared-context integration" . todo)
         ("Finding format standardization" . todo)
         ("Integration tests" . todo)
         ("Documentation" . todo)
         ("v1.0 release" . todo)))))

  (blockers-and-issues
    (critical ())
    (high
      ("Hidden channel detection covers only 3 of 6 planned channel types"
       "Forge integration not fully tested end-to-end"))
    (medium
      ("No integration tests yet"
       "Need fleet integration with shared-context"
       "SARIF output needs validation against spec"))
    (low
      ("Could expand seam register schema"
       "Need comprehensive documentation")))

  (critical-next-actions
    (immediate
      "Complete database coupling detection in hidden channels"
      "Add network call detection to hidden channels"
      "Test forge integrations end-to-end")
    (this-week
      "Add integration tests for all analysis modes"
      "Implement fleet integration with gitbot-shared-context"
      "Update README.adoc with actual capabilities")
    (this-month
      "Add environment variable leakage detection"
      "Complete forge integration and webhook handling"
      "Prepare v1.0 release with full hidden channel coverage"
      "Run seambot on all hyperpolymath repos to validate seam health"))

  (session-history
    ((date "2026-02-05")
     (session "opus-checkpoint-update")
     (accomplishments
       "Updated STATE.scm from 5% stub to comprehensive 60% state"
       "Updated ECOSYSTEM.scm with full relationship mapping"
       "Updated META.scm with domain-specific ADRs"
       "Fixed SPDX header from PMPL-1.0-or-later to PMPL-1.0-or-later")
     (notes "Seambot has 2129 lines of Rust across 7+ modules. Core seam analysis is complete. Hidden channel detection is the key remaining work area."))))

;; Theoretical foundation:
;; Seambot treats architectural seams as FIRST-CLASS CITIZENS requiring the same
;; rigor as types, tests, and dependencies. The core insight is that architecture
;; rot happens at boundaries — when seam interfaces drift without detection,
;; systems silently become coupled in ways their architects never intended.
;;
;; Key concepts:
;; - Seam: An explicit architectural boundary between components
;; - Register: A machine-readable declaration of all seams in a system
;; - Conformance: Proof (via examples) that seams are used correctly
;; - Drift: Undocumented changes to seam interfaces over time
;; - Freeze stamp: Immutable snapshot of seam state at a release point
;; - Hidden channel: Undeclared coupling that bypasses declared seams
;;
;; Philosophy: "If finishbot tells us whether a repo is ready to release,
;; seambot tells us whether it is still the same system we thought we built."

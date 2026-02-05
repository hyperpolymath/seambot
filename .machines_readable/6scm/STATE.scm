;; SPDX-License-Identifier: PMPL-1.0-or-later
;; SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
;; STATE.scm - Project state tracking for seambot
;; Media-Type: application/vnd.state+scm

(define-state seambot
  (metadata
    (version "0.3.0")
    (schema-version "1.0.0")
    (created "2025-12-01")
    (updated "2026-02-05")
    (project "seambot")
    (repo "hyperpolymath/seambot"))

  (project-context
    (name "seambot")
    (tagline "Architectural seam analysis - hidden coupling and drift detection")
    (tech-stack ("rust")))

  (current-position
    (phase "beta")
    (overall-completion 55)
    (components
      ((seam-register
        ((status . "complete")
         (completion . 90)
         (notes . "TOML-based register definition, validation, multi-format output")))
       (drift-detection
        ((status . "active")
         (completion . 70)
         (notes . "Import analysis, global state detection, filesystem coupling")))
       (hidden-channels
        ((status . "active")
         (completion . 60)
         (notes . "Import, global state, filesystem, database, network coupling detection")))
       (symbol-extraction
        ((status . "stub")
         (completion . 10)
         (notes . "Tree-sitter planned but not yet integrated")))
       (github-app
        ((status . "partial")
         (completion . 40)
         (notes . "Manifest exists, webhook scaffolding, PR comment generation")))
       (conformance-checking
        ((status . "partial")
         (completion . 30)
         (notes . "Basic boundary validation, deeper analysis TODO")))))
    (working-features
      ("Seam register TOML parsing and validation"
       "Seam boundary definition (owner, visibility, allowed-consumers)"
       "Import-based hidden channel detection"
       "Global state coupling detection"
       "Filesystem coupling detection"
       "Database coupling detection (SQL + ORM patterns)"
       "Network coupling detection (HTTP, gRPC, WebSocket)"
       "Multi-format output (text, JSON, SARIF)"
       "GitHub App manifest for developer programme"
       "PR comment generation with findings"
       "Severity classification (Critical, High, Medium, Low, Info)"
       "Drift detection between declared and actual seam boundaries")))

  (route-to-mvp
    (milestones
      ((v0.1.0
        ((name . "Core Seam Analysis")
         (status . "complete")
         (items
           ("Seam register TOML format" . done)
           ("Import-based coupling detection" . done)
           ("Global state detection" . done)
           ("CLI with analyze/check commands" . done))))
       (v0.3.0
        ((name . "Extended Coupling Detection")
         (status . "in-progress")
         (items
           ("Filesystem coupling detection" . done)
           ("Database coupling detection" . done)
           ("Network coupling detection" . done)
           ("Symbol-level extraction" . todo)
           ("Tree-sitter integration" . todo))))
       (v0.5.0
        ((name . "Deep Conformance")
         (status . "planned")
         (items
           ("Runtime coupling detection" . todo)
           ("Cross-language analysis" . todo)
           ("Temporal coupling detection" . todo)
           ("Fleet integration via shared-context" . todo))))
       (v1.0.0
        ((name . "Production Release")
         (status . "planned")
         (items
           ("Full GitHub App integration" . todo)
           ("CI/CD gate mode" . todo)
           ("Baseline comparison" . todo)
           ("Performance optimization" . todo)))))))

  (blockers-and-issues
    (critical ())
    (high
      ("Tree-sitter integration needed for accurate symbol extraction"))
    (medium
      ("3 of 5 hidden channel types fully implemented (import, global, filesystem)"
       "Database and network detection are pattern-based, not AST-based"))
    (low
      ("18 compiler warnings (unused functions/variables) need cleanup")))

  (critical-next-actions
    (immediate
      "Integrate tree-sitter for symbol-level extraction"
      "Add tests for database and network coupling detection")
    (this-week
      "Implement deeper conformance checking"
      "Wire up shared-context library for fleet integration")
    (this-month
      "Add temporal coupling detection"
      "Implement baseline comparison for drift tracking"))

  (session-history
    ((date . "2026-02-05")
     (session . "opus-continuation")
     (accomplishments
       ("Fixed license across 28+ files: AGPL-3.0-or-later → PMPL-1.0-or-later"
        "Fixed author in Cargo.toml to Jonathan D.A. Jewell"
        "Implemented detect_database_coupling() - SQL + ORM pattern detection"
        "Implemented detect_network_coupling() - HTTP, gRPC, WebSocket detection"
        "Both follow established WalkDir + regex + HashMap cross-reference pattern"
        "Verified compilation with cargo check (0 errors, 18 pre-existing warnings)"
        "Rewrote STATE.scm from template stub to actual project data")))))

;; Helper functions
(define (get-completion-percentage state)
  (current-position 'overall-completion state))

(define (get-blockers state severity)
  (blockers-and-issues severity state))

(define (get-milestone state name)
  (find (lambda (m) (equal? (car m) name))
        (route-to-mvp 'milestones state)))

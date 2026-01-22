;; SPDX-License-Identifier: PMPL-1.0-or-later
;; AGENTIC.scm - AI agent interaction patterns for seambot

(define agentic-config
  `((version . "1.0.0")
    (project . "seambot")

    (patterns
      ((seam-auditing
         (focus . ("boundary-integrity" "architectural-consistency" "drift-detection"))
         (check-for
           ("Imports violating declared seams"
            "Undeclared dependencies"
            "Seam definitions out of sync with code"
            "Accidental coupling between components")))

       (architectural-governance
         (principles
           ("Seams are first-class artifacts"
            "Boundaries must be explicit and justified"
            "Changes to seams require design review"
            "Drift is a signal of design problems"))
         (enforcement
           ("Block PRs with seam violations"
            "Require architects to approve boundary changes"
            "Track seam stability metrics")))))

    (constraints
      ((languages
         (primary . "rust")
         (config . "toml"))

       (banned . ("typescript" "node" "python" "go"))

       (architectural-rules
         ("Never silently allow violations"
          "Seam definitions are version-controlled"
          "Changes to seams are rare and deliberate"
          "Audit results are reproducible"))))))

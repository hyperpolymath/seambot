;; SPDX-License-Identifier: PMPL-1.0-or-later
;; NEUROSYM.scm - Neurosymbolic integration config for seambot

(define neurosym-config
  `((version . "1.0.0")
    (project . "seambot")

    (symbolic-layer
      ((type . "static-analysis-boundary-checker")
       (reasoning . "graph-traversal")
       (verification . "import-graph-validation")
       (guarantees
         ("All imports are analyzed"
          "Seam violations detected precisely"
          "No false negatives on boundary crossings"))))

    (neural-layer
      ((llm-guidance
         (model . "claude-sonnet-4-5-20250929")
         (use-cases
           ("Explain why a seam violation matters"
            "Suggest refactoring to fix violations"
            "Identify patterns in drift"
            "Recommend seam boundary improvements"))
         (constraints
           ("Must respect declared architectural decisions"
            "Never suggest removing seams without justification"
            "Always explain impact of boundary changes")))))

    (integration
      ((boundary-enforcement
         "Symbolic graph analysis detects violations -> Neural reasoning explains impact -> Architects decide on action")

       (drift-pattern-recognition
         "Symbolic drift detection + Neural pattern analysis -> Architectural insights -> Proactive seam refinement")))))

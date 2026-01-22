;; SPDX-License-Identifier: PMPL-1.0-or-later
;; PLAYBOOK.scm - Operational runbook for seambot

(define playbook
  `((version . "1.0.0")
    (project . "seambot")

    (procedures
      ((audit-seams
         (steps
           ("1. Parse declared seams from .seams.toml"
            "2. Analyze actual dependencies via static analysis"
            "3. Detect violations (imports across forbidden boundaries)"
            "4. Check for drift (seam definitions out of sync)"
            "5. Generate seam health report"))
         (troubleshooting
           ((issue . "False positive boundary violation")
            (solution . "Review .seams.toml, verify allowed exceptions"))))

       (detect-drift
         (description . "Seam definitions diverge from actual architecture")
         (steps
           ("1. Compare .seams.toml with import graph"
            "2. Identify undeclared dependencies"
            "3. Flag accidental coupling"
            "4. Suggest seam boundary updates or refactoring")))

       (enforce-seam-hygiene
         (steps
           ("1. Block PR if seam violations detected"
            "2. Require justification for new cross-boundary imports"
            "3. Enforce seam stability (no frequent boundary changes)")))))

    (alerts
      ((high-priority
         (trigger . "Critical seam violation")
         (response
           ("1. Block PR merge"
            "2. Alert architects"
            "3. Require design review"))
         (escalation . "Architecture review board"))))))

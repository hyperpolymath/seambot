;; SPDX-License-Identifier: PMPL-1.0-or-later
;; ECOSYSTEM.scm - Ecosystem relationships for seambot
;; Media-Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0.0")
  (name "seambot")
  (type "architecture-bot")
  (purpose "Architectural seam hygiene auditor — tracks, enforces, and detects drift
    in architectural boundaries. Treats seams as first-class citizens requiring
    the same rigor as types, tests, and dependencies.")

  (position-in-ecosystem
    (role "finisher-tier-bot")
    (layer "architecture-integrity")
    (fleet-tier "finisher")
    (execution-order 6)
    (description "Runs after rhodibot and echidnabot in the fleet pipeline.
      Consumes structural findings from rhodibot to understand repo layout,
      and formal verification results from echidnabot to validate seam contracts.
      Produces architectural integrity findings consumed by finishbot for
      release readiness gating."))

  (related-projects
    (parent
      (gitbot-fleet
        (relationship "fleet-member")
        (description "Seambot is one of six specialized bots in the gitbot-fleet.
          It contributes architectural findings to the shared context layer.")
        (integration "Publishes Finding structs via shared-context API")))
    (engine
      (hypatia
        (relationship "rules-engine")
        (description "Hypatia's neurosymbolic rules determine when seambot runs
          and which seam checks are applicable per repository.")
        (integration "Receives execution instructions and rule configurations")))
    (executor
      (robot-repo-automaton
        (relationship "fix-executor")
        (description "When seambot identifies fixable seam issues (e.g. stale
          freeze stamps), robot-repo-automaton executes the fixes.")
        (integration "Sends FixRequest actions for auto-fixable issues")))
    (dependencies
      (rhodibot
        (relationship "dependency")
        (description "Seambot depends on rhodibot completing first.
          Rhodibot's structural analysis identifies where seam boundaries
          should exist based on directory layout and module structure.")
        (tier-relationship "rhodibot is Verifier tier, seambot is Finisher tier"))
      (echidnabot
        (relationship "dependency")
        (description "Seambot can use echidnabot's formal verification results
          to validate that seam contracts are mathematically proven.
          E.g. if a seam has an invariant, echidnabot proves it holds."))
      (finishingbot
        (relationship "consumer")
        (description "Finishbot consumes seambot's architectural integrity findings
          as part of release readiness validation. A repo with drifted seams
          cannot pass finishbot's release gate.")))
    (siblings
      (glambot
        (relationship "peer")
        (description "Both are Finisher tier bots. Glambot handles presentation,
          seambot handles architecture. No direct dependency."))
      (sustainabot
        (relationship "peer")
        (description "Sustainabot's efficiency analysis could inform seambot about
          architectural boundaries that cause performance bottlenecks.")))
    (infrastructure
      (git-private-farm
        (relationship "propagation")
        (description "Seam analysis results propagate across all forges via
          .git-private-farm mirroring. Seam registers should be consistent
          across GitHub, GitLab, Bitbucket mirrors."))
      (rsr-template-repo
        (relationship "standard")
        (description "RSR defines the standard directory structure that seambot
          uses as the baseline for identifying architectural boundaries."))))

  (what-this-is
    "An architectural boundary auditor that treats seams as first-class citizens"
    "A hidden channel detector that finds undeclared coupling between components"
    "A drift detector that identifies when seam interfaces change without documentation"
    "A Finisher-tier bot in the gitbot-fleet that runs after Verifier bots"
    "A multi-forge tool supporting GitHub, GitLab, and Bitbucket")

  (what-this-is-not
    "Not a code quality tool — that is glambot's responsibility"
    "Not a structural compliance checker — that is rhodibot's job"
    "Not a release gater — that is finishbot (but seambot feeds it findings)"
    "Not a formal verifier — that is echidnabot (but seambot uses its results)"
    "Not a standalone tool — it is designed to work within the gitbot-fleet"))

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core checking logic for seam hygiene

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};

use crate::seam::{
    CheckResult, DriftBaseline, Finding, InterfaceFingerprint, SeamFreezeStamp,
    SeamRegister, Severity,
};

/// Run all seam checks on a repository
pub async fn run_all_checks(repo_path: &Path) -> Result<CheckResult> {
    info!("Running all seam checks");
    let mut result = CheckResult::new();

    // Check 1: Register exists and is valid
    let register_path = repo_path.join("spec/seams/seam-register.json");
    if register_path.exists() {
        let register_result = check_register(repo_path, &register_path).await?;
        result.merge(register_result);
    } else {
        result.add_finding(Finding {
            check: "register-exists".to_string(),
            severity: Severity::Error,
            message: "Seam register not found at spec/seams/seam-register.json".to_string(),
            location: Some("spec/seams/seam-register.json".to_string()),
            suggestion: Some("Run 'seambot init' to create seam infrastructure".to_string()),
            seam_id: None,
        });
        return Ok(result);
    }

    // Check 2: Conformance examples
    let conformance_result = check_conformance(repo_path, None).await?;
    result.merge(conformance_result);

    // Check 3: Hidden channels (basic heuristic)
    let hidden_result = check_hidden_channels(repo_path).await?;
    result.merge(hidden_result);

    // Check 4: Drift (if baseline exists)
    let baseline_path = repo_path.join("spec/seams/drift-baseline.json");
    if baseline_path.exists() {
        let drift_result = check_drift(repo_path, Some(&baseline_path)).await?;
        result.merge(drift_result);
    }

    result.summary.total_seams = count_seams(repo_path).await.unwrap_or(0);
    result.summary.checked_seams = result.summary.total_seams;

    Ok(result)
}

/// Check seam register completeness
pub async fn check_register(repo_path: &Path, register_path: &Path) -> Result<CheckResult> {
    info!("Checking seam register at {}", register_path.display());
    let mut result = CheckResult::new();

    // Parse register
    let content = fs::read_to_string(register_path)
        .await
        .context("Failed to read seam register")?;

    let register: SeamRegister = serde_json::from_str(&content)
        .context("Failed to parse seam register")?;

    // Check each seam
    for seam in &register.seams {
        debug!("Checking seam: {}", seam.id);

        // Check 1: Has checklist
        if seam.checklist_path.is_none() {
            result.add_finding(Finding {
                check: "seam-has-checklist".to_string(),
                severity: Severity::Warning,
                message: format!("Seam '{}' has no checklist path defined", seam.id),
                location: None,
                suggestion: Some("Add a checklist_path to the seam definition".to_string()),
                seam_id: Some(seam.id.clone()),
            });
        } else if let Some(ref path) = seam.checklist_path {
            let full_path = repo_path.join(path);
            if !full_path.exists() {
                result.add_finding(Finding {
                    check: "checklist-exists".to_string(),
                    severity: Severity::Error,
                    message: format!("Checklist file not found for seam '{}'", seam.id),
                    location: Some(path.clone()),
                    suggestion: Some(format!("Create checklist at {}", path)),
                    seam_id: Some(seam.id.clone()),
                });
            }
        }

        // Check 2: Has at least one conformance example
        if seam.conformance_paths.is_empty() {
            result.add_finding(Finding {
                check: "seam-has-conformance".to_string(),
                severity: Severity::Warning,
                message: format!("Seam '{}' has no conformance examples", seam.id),
                location: None,
                suggestion: Some("Add at least one conformance example".to_string()),
                seam_id: Some(seam.id.clone()),
            });
        } else {
            for path in &seam.conformance_paths {
                let full_path = repo_path.join(path);
                if !full_path.exists() {
                    result.add_finding(Finding {
                        check: "conformance-exists".to_string(),
                        severity: Severity::Error,
                        message: format!("Conformance example not found for seam '{}'", seam.id),
                        location: Some(path.clone()),
                        suggestion: Some(format!("Create conformance example at {}", path)),
                        seam_id: Some(seam.id.clone()),
                    });
                }
            }
        }

        // Check 3: Has invariants
        if seam.invariants.is_empty() {
            result.add_finding(Finding {
                check: "seam-has-invariants".to_string(),
                severity: Severity::Info,
                message: format!("Seam '{}' has no invariants defined", seam.id),
                location: None,
                suggestion: Some("Consider defining invariants for this seam".to_string()),
                seam_id: Some(seam.id.clone()),
            });
        }

        // Check 4: Components are specified
        if seam.side_a.is_empty() || seam.side_b.is_empty() {
            result.add_finding(Finding {
                check: "seam-has-components".to_string(),
                severity: Severity::Warning,
                message: format!("Seam '{}' has incomplete component specification", seam.id),
                location: None,
                suggestion: Some("Specify components on both sides of the seam".to_string()),
                seam_id: Some(seam.id.clone()),
            });
        }
    }

    info!("Register check complete: {} seams checked", register.seams.len());
    Ok(result)
}

/// Check for seam drift
pub async fn check_drift(repo_path: &Path, baseline: Option<&Path>) -> Result<CheckResult> {
    info!("Checking for seam drift");
    let mut result = CheckResult::new();

    let Some(baseline_path) = baseline else {
        result.add_finding(Finding {
            check: "drift-baseline".to_string(),
            severity: Severity::Info,
            message: "No drift baseline found - drift detection skipped".to_string(),
            location: None,
            suggestion: Some("Run 'seambot drift --update-baseline' to create baseline".to_string()),
            seam_id: None,
        });
        return Ok(result);
    };

    // Load baseline
    let baseline_content = fs::read_to_string(baseline_path)
        .await
        .context("Failed to read drift baseline")?;

    let baseline: DriftBaseline = serde_json::from_str(&baseline_content)
        .context("Failed to parse drift baseline")?;

    // Load current register
    let register_path = repo_path.join("spec/seams/seam-register.json");
    let register_content = fs::read_to_string(&register_path)
        .await
        .context("Failed to read seam register")?;

    let register: SeamRegister = serde_json::from_str(&register_content)?;

    // Compare fingerprints
    for seam in &register.seams {
        if let Some(baseline_fp) = baseline.fingerprints.get(&seam.id) {
            let current_fp = compute_fingerprint(repo_path, seam).await?;

            if current_fp.signature_hash != baseline_fp.signature_hash {
                result.add_finding(Finding {
                    check: "seam-drift".to_string(),
                    severity: if seam.frozen {
                        Severity::Error
                    } else {
                        Severity::Warning
                    },
                    message: format!(
                        "Seam '{}' has drifted from baseline{}",
                        seam.id,
                        if seam.frozen { " (FROZEN)" } else { "" }
                    ),
                    location: None,
                    suggestion: Some(
                        "Review changes and update baseline if intentional".to_string()
                    ),
                    seam_id: Some(seam.id.clone()),
                });
            }
        } else {
            result.add_finding(Finding {
                check: "seam-drift".to_string(),
                severity: Severity::Info,
                message: format!("Seam '{}' not in baseline (new seam)", seam.id),
                location: None,
                suggestion: None,
                seam_id: Some(seam.id.clone()),
            });
        }
    }

    Ok(result)
}

/// Update the drift baseline
pub async fn update_drift_baseline(repo_path: &Path) -> Result<()> {
    let register_path = repo_path.join("spec/seams/seam-register.json");
    let register_content = fs::read_to_string(&register_path).await?;
    let register: SeamRegister = serde_json::from_str(&register_content)?;

    let mut fingerprints = std::collections::HashMap::new();

    for seam in &register.seams {
        let fp = compute_fingerprint(repo_path, seam).await?;
        fingerprints.insert(seam.id.clone(), fp);
    }

    let baseline = DriftBaseline {
        version: "1.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        fingerprints,
    };

    let baseline_path = repo_path.join("spec/seams/drift-baseline.json");
    let content = serde_json::to_string_pretty(&baseline)?;
    fs::write(&baseline_path, content).await?;

    info!("Updated drift baseline at {}", baseline_path.display());
    Ok(())
}

/// Check conformance examples
pub async fn check_conformance(repo_path: &Path, seam_filter: Option<&str>) -> Result<CheckResult> {
    info!("Checking conformance examples");
    let mut result = CheckResult::new();

    let register_path = repo_path.join("spec/seams/seam-register.json");
    if !register_path.exists() {
        return Ok(result);
    }

    let register_content = fs::read_to_string(&register_path).await?;
    let register: SeamRegister = serde_json::from_str(&register_content)?;

    for seam in &register.seams {
        if let Some(filter) = seam_filter {
            if seam.id != filter {
                continue;
            }
        }

        for path in &seam.conformance_paths {
            let full_path = repo_path.join(path);
            if full_path.exists() {
                // Basic validation: check file is not empty
                let content = fs::read_to_string(&full_path).await?;
                if content.trim().is_empty() {
                    result.add_finding(Finding {
                        check: "conformance-valid".to_string(),
                        severity: Severity::Warning,
                        message: format!("Conformance example is empty for seam '{}'", seam.id),
                        location: Some(path.clone()),
                        suggestion: Some("Add content to the conformance example".to_string()),
                        seam_id: Some(seam.id.clone()),
                    });
                }
            }
        }
    }

    Ok(result)
}

/// Check for hidden channels (basic heuristic)
async fn check_hidden_channels(repo_path: &Path) -> Result<CheckResult> {
    info!("Checking for hidden channels");
    let mut result = CheckResult::new();

    // This is a basic heuristic check for common hidden channel patterns
    // A more sophisticated implementation would do actual dependency analysis

    let suspicious_patterns = [
        ("global state", r"(?i)(global|singleton|static\s+mut)"),
        ("environment variables", r"(?i)(env::var|getenv|process\.env)"),
        ("file system side effects", r"(?i)(write_all|create_dir|remove_file)"),
        ("network calls", r"(?i)(reqwest::get|http::request|fetch\()"),
    ];

    // Check src directory for suspicious patterns
    let src_dir = repo_path.join("src");
    if src_dir.exists() {
        let register_path = repo_path.join("spec/seams/seam-register.json");
        if register_path.exists() {
            let register_content = fs::read_to_string(&register_path).await?;
            let register: SeamRegister = serde_json::from_str(&register_content)?;

            // If any seam has "no hidden channels" invariant, flag potential violations
            for seam in &register.seams {
                for invariant in &seam.invariants {
                    if invariant.id.contains("no-hidden-channels")
                        || invariant.description.to_lowercase().contains("hidden channel")
                    {
                        result.add_finding(Finding {
                            check: "hidden-channels".to_string(),
                            severity: Severity::Info,
                            message: format!(
                                "Seam '{}' declares no-hidden-channels invariant - manual review recommended",
                                seam.id
                            ),
                            location: None,
                            suggestion: Some(
                                "Review code for global state, env vars, and implicit dependencies".to_string()
                            ),
                            seam_id: Some(seam.id.clone()),
                        });
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Check freeze stamp for a stage
pub async fn check_freeze_stamp(repo_path: &Path, stage: &str) -> Result<CheckResult> {
    info!("Checking freeze stamp for stage: {}", stage);
    let mut result = CheckResult::new();

    let stamp_path = repo_path.join(format!("spec/seams/freeze-stamps/{}.json", stage));

    if !stamp_path.exists() {
        result.add_finding(Finding {
            check: "freeze-stamp-exists".to_string(),
            severity: Severity::Error,
            message: format!("Freeze stamp not found for stage '{}'", stage),
            location: Some(stamp_path.display().to_string()),
            suggestion: Some(format!(
                "Create freeze stamp before marking stage {} as frozen",
                stage
            )),
            seam_id: None,
        });
        return Ok(result);
    }

    let content = fs::read_to_string(&stamp_path).await?;
    let stamp: SeamFreezeStamp = serde_json::from_str(&content)?;

    // Verify the stamp matches the stage
    if stamp.stage != stage {
        result.add_finding(Finding {
            check: "freeze-stamp-valid".to_string(),
            severity: Severity::Error,
            message: format!(
                "Freeze stamp stage mismatch: expected '{}', got '{}'",
                stage, stamp.stage
            ),
            location: Some(stamp_path.display().to_string()),
            suggestion: Some("Regenerate freeze stamp with correct stage".to_string()),
            seam_id: None,
        });
    }

    // Verify register hash matches current register
    let register_path = repo_path.join("spec/seams/seam-register.json");
    if register_path.exists() {
        let register_content = fs::read_to_string(&register_path).await?;
        let current_hash = compute_hash(&register_content);

        if current_hash != stamp.register_hash {
            result.add_finding(Finding {
                check: "freeze-stamp-current".to_string(),
                severity: Severity::Error,
                message: format!(
                    "Seam register has changed since stage '{}' was frozen",
                    stage
                ),
                location: None,
                suggestion: Some(
                    "Seam changes after freeze require a new stage".to_string()
                ),
                seam_id: None,
            });
        }
    }

    info!("Freeze stamp check complete for stage: {}", stage);
    Ok(result)
}

/// Generate a comprehensive report
pub async fn generate_report(repo_path: &Path, full: bool) -> Result<CheckResult> {
    info!("Generating seam status report (full={})", full);

    // Run all checks and return the result
    run_all_checks(repo_path).await
}

/// Compute interface fingerprint for a seam
async fn compute_fingerprint(
    repo_path: &Path,
    seam: &crate::seam::Seam,
) -> Result<InterfaceFingerprint> {
    let mut files = Vec::new();
    let mut hasher = Sha256::new();

    // Hash the seam definition itself
    let seam_json = serde_json::to_string(seam)?;
    hasher.update(seam_json.as_bytes());

    // Hash conformance files
    for path in &seam.conformance_paths {
        let full_path = repo_path.join(path);
        if full_path.exists() {
            let content = fs::read_to_string(&full_path).await?;
            let file_hash = compute_hash(&content);
            hasher.update(file_hash.as_bytes());

            files.push(crate::seam::FileFingerprint {
                path: path.clone(),
                hash: file_hash,
                exported_symbols: Vec::new(), // TODO: extract symbols
            });
        }
    }

    let signature_hash = hex::encode(hasher.finalize());

    Ok(InterfaceFingerprint {
        seam_id: seam.id.clone(),
        signature_hash,
        files,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Compute SHA256 hash of content
fn compute_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Count seams in the register
async fn count_seams(repo_path: &Path) -> Result<usize> {
    let register_path = repo_path.join("spec/seams/seam-register.json");
    if !register_path.exists() {
        return Ok(0);
    }

    let content = fs::read_to_string(&register_path).await?;
    let register: SeamRegister = serde_json::from_str(&content)?;
    Ok(register.seams.len())
}

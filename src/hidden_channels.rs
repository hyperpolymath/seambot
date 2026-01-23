// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hidden channel detection for seam boundaries
//!
//! Detects undeclared coupling between seams through:
//! - Undeclared imports across seam boundaries
//! - Shared global state
//! - Filesystem coupling (shared files/directories)
//! - Database coupling (shared tables/schemas)
//! - Network calls across boundaries

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::seam::SeamRegister;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenChannel {
    pub channel_type: ChannelType,
    pub source_seam: String,
    pub target_seam: String,
    pub evidence: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    UndeclaredImport,
    GlobalState,
    FilesystemCoupling,
    DatabaseCoupling,
    NetworkCoupling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,  // Violates seam integrity
    High,      // Bypasses declared interfaces
    Medium,    // Implicit coupling
    Low,       // Potential issue
}

impl HiddenChannel {
    pub fn new(
        channel_type: ChannelType,
        source_seam: impl Into<String>,
        target_seam: impl Into<String>,
        evidence: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            channel_type,
            source_seam: source_seam.into(),
            target_seam: target_seam.into(),
            evidence: evidence.into(),
            severity,
        }
    }
}

/// Detect all hidden channels in a repository
pub fn detect_hidden_channels(
    register: &SeamRegister,
    repo_path: &Path,
) -> Result<Vec<HiddenChannel>> {
    let mut channels = Vec::new();

    // Detect undeclared imports
    channels.extend(detect_undeclared_imports(register, repo_path)?);

    // Detect shared global state
    channels.extend(detect_global_state(register, repo_path)?);

    // Detect filesystem coupling
    channels.extend(detect_filesystem_coupling(register, repo_path)?);

    // Detect database coupling
    channels.extend(detect_database_coupling(register, repo_path)?);

    // Detect network coupling
    channels.extend(detect_network_coupling(register, repo_path)?);

    Ok(channels)
}

/// Detect undeclared imports across seam boundaries
fn detect_undeclared_imports(
    register: &SeamRegister,
    repo_path: &Path,
) -> Result<Vec<HiddenChannel>> {
    let mut channels = Vec::new();

    // Build a map of file paths to seams
    let file_seam_map = build_file_seam_map(register, repo_path);

    // Scan all source files for imports
    for entry in WalkDir::new(repo_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
        .filter_map(|e| e.ok())
    {
        let entry_path = entry.path();

        if !is_source_file(entry_path) {
            continue;
        }

        if let Some(source_seam) = file_seam_map.get(entry_path) {
            if let Ok(imports) = extract_imports(entry_path) {
                for import_path in imports {
                    // Resolve import to actual file
                    if let Some(target_file) = resolve_import(&import_path, entry_path, repo_path) {
                        if let Some(target_seam) = file_seam_map.get(&target_file) {
                            // Check if import crosses seam boundary
                            if source_seam != target_seam {
                                // Check if this import is declared in the seam interface
                                if !is_declared_dependency(register, source_seam, target_seam) {
                                    channels.push(HiddenChannel::new(
                                        ChannelType::UndeclaredImport,
                                        source_seam,
                                        target_seam,
                                        format!("Import from {} to {}", entry_path.display(), target_file.display()),
                                        Severity::High,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(channels)
}

/// Detect shared global state between seams
fn detect_global_state(
    register: &SeamRegister,
    repo_path: &Path,
) -> Result<Vec<HiddenChannel>> {
    let mut channels = Vec::new();
    let file_seam_map = build_file_seam_map(register, repo_path);

    // Patterns indicating global state
    let global_patterns = [
        "static mut ",
        "lazy_static!",
        "once_cell",
        "global ",
        "GLOBAL_",
        "Arc<Mutex<",
        "Arc<RwLock<",
    ];

    let mut global_vars: HashMap<String, HashSet<String>> = HashMap::new();

    for entry in WalkDir::new(repo_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
        .filter_map(|e| e.ok())
    {
        let entry_path = entry.path();

        if !is_source_file(entry_path) {
            continue;
        }

        if let Some(seam_name) = file_seam_map.get(entry_path) {
            if let Ok(content) = std::fs::read_to_string(entry_path) {
                for pattern in &global_patterns {
                    if content.contains(pattern) {
                        // Extract variable name (simplified)
                        for line in content.lines() {
                            if line.contains(pattern) {
                                let var_name = extract_var_name(line);
                                global_vars
                                    .entry(var_name)
                                    .or_default()
                                    .insert(seam_name.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // Find globals shared across seams
    for (var_name, seams) in &global_vars {
        if seams.len() > 1 {
            let seams_vec: Vec<_> = seams.iter().cloned().collect();
            for i in 0..seams_vec.len() {
                for j in (i + 1)..seams_vec.len() {
                    channels.push(HiddenChannel::new(
                        ChannelType::GlobalState,
                        &seams_vec[i],
                        &seams_vec[j],
                        format!("Shared global variable: {}", var_name),
                        Severity::Critical,
                    ));
                }
            }
        }
    }

    Ok(channels)
}

/// Detect filesystem coupling between seams
fn detect_filesystem_coupling(
    register: &SeamRegister,
    repo_path: &Path,
) -> Result<Vec<HiddenChannel>> {
    let mut channels = Vec::new();
    let file_seam_map = build_file_seam_map(register, repo_path);

    // Patterns indicating filesystem operations
    let fs_patterns = [
        "std::fs::",
        "tokio::fs::",
        "File::open",
        "File::create",
        "read_to_string",
        "write_all",
    ];

    let mut fs_paths: HashMap<String, HashSet<String>> = HashMap::new();

    for entry in WalkDir::new(repo_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
        .filter_map(|e| e.ok())
    {
        let entry_path = entry.path();

        if !is_source_file(entry_path) {
            continue;
        }

        if let Some(seam_name) = file_seam_map.get(entry_path) {
            if let Ok(content) = std::fs::read_to_string(entry_path) {
                for pattern in &fs_patterns {
                    if content.contains(pattern) {
                        // Extract file paths (simplified - would need better parsing)
                        for line in content.lines() {
                            if line.contains(pattern) {
                                if let Some(path) = extract_path_literal(line) {
                                    fs_paths
                                        .entry(path)
                                        .or_default()
                                        .insert(seam_name.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Find filesystem paths accessed by multiple seams
    for (path, seams) in &fs_paths {
        if seams.len() > 1 {
            let seams_vec: Vec<_> = seams.iter().cloned().collect();
            for i in 0..seams_vec.len() {
                for j in (i + 1)..seams_vec.len() {
                    channels.push(HiddenChannel::new(
                        ChannelType::FilesystemCoupling,
                        &seams_vec[i],
                        &seams_vec[j],
                        format!("Shared file access: {}", path),
                        Severity::Medium,
                    ));
                }
            }
        }
    }

    Ok(channels)
}

/// Detect database coupling between seams
fn detect_database_coupling(
    _register: &SeamRegister,
    _repo_path: &Path,
) -> Result<Vec<HiddenChannel>> {
    // TODO: Detect shared database access
    // - SQL table names in queries
    // - ORM model references
    // - Migration files
    Ok(Vec::new())
}

/// Detect network coupling between seams
fn detect_network_coupling(
    _register: &SeamRegister,
    _repo_path: &Path,
) -> Result<Vec<HiddenChannel>> {
    // TODO: Detect network calls crossing seam boundaries
    // - HTTP client calls
    // - gRPC calls
    // - WebSocket connections
    Ok(Vec::new())
}

// Helper functions

fn build_file_seam_map(register: &SeamRegister, repo_path: &Path) -> HashMap<PathBuf, String> {
    let mut map = HashMap::new();

    for seam in &register.seams {
        let seam_path = repo_path.join(&seam.boundary_path);
        for entry in WalkDir::new(&seam_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().is_file() {
                map.insert(entry.path().to_path_buf(), seam.name.clone());
            }
        }
    }

    map
}

fn is_ignored(name: &str) -> bool {
    matches!(
        name,
        "target" | "node_modules" | ".git" | "dist" | "build" | ".cache"
    )
}

fn is_source_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        matches!(
            ext.to_str().unwrap_or(""),
            "rs" | "py" | "js" | "ts" | "go" | "java" | "kt" | "swift"
        )
    } else {
        false
    }
}

fn extract_imports(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let mut imports = Vec::new();

    // Rust imports
    if path.extension().and_then(|e| e.to_str()) == Some("rs") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("use ") || trimmed.starts_with("mod ") {
                if let Some(import) = extract_rust_import(trimmed) {
                    imports.push(import);
                }
            }
        }
    }

    // Python imports
    if path.extension().and_then(|e| e.to_str()) == Some("py") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                if let Some(import) = extract_python_import(trimmed) {
                    imports.push(import);
                }
            }
        }
    }

    // JavaScript/TypeScript imports
    if matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("js") | Some("ts") | Some("jsx") | Some("tsx")
    ) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") || trimmed.contains("require(") {
                if let Some(import) = extract_js_import(trimmed) {
                    imports.push(import);
                }
            }
        }
    }

    Ok(imports)
}

fn extract_rust_import(line: &str) -> Option<String> {
    // Simplified: extract module path from "use path::to::module"
    line.split_whitespace()
        .nth(1)?
        .trim_end_matches(';')
        .split("::")
        .next()
        .map(|s| s.to_string())
}

fn extract_python_import(line: &str) -> Option<String> {
    // Simplified: extract module from "import module" or "from module import"
    if line.starts_with("import ") {
        line.split_whitespace().nth(1)?.split('.').next().map(|s| s.to_string())
    } else if line.starts_with("from ") {
        line.split_whitespace().nth(1)?.split('.').next().map(|s| s.to_string())
    } else {
        None
    }
}

fn extract_js_import(line: &str) -> Option<String> {
    // Simplified: extract path from "import ... from 'path'" or "require('path')"
    if line.contains("from") {
        line.split("from").nth(1)?
            .trim()
            .trim_matches(|c| c == '\'' || c == '"' || c == ';')
            .to_string()
            .into()
    } else if line.contains("require(") {
        line.split("require(").nth(1)?
            .split(')').next()?
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_string()
            .into()
    } else {
        None
    }
}

fn resolve_import(import: &str, source_file: &Path, repo_path: &Path) -> Option<PathBuf> {
    // Simplified: try common patterns
    let source_dir = source_file.parent()?;

    // Relative import
    if import.starts_with('.') {
        let resolved = source_dir.join(import);
        if resolved.exists() {
            return Some(resolved);
        }
    }

    // Absolute from repo root
    let from_root = repo_path.join(import);
    if from_root.exists() {
        return Some(from_root);
    }

    None
}

fn is_declared_dependency(register: &SeamRegister, source: &str, target: &str) -> bool {
    // Check if target is in source's declared dependencies
    if let Some(seam) = register.seams.iter().find(|s| s.name == source) {
        seam.declared_dependencies.contains(&target.to_string())
    } else {
        false
    }
}

fn extract_var_name(line: &str) -> String {
    // Simplified: extract variable name from declaration
    line.split_whitespace()
        .last()
        .unwrap_or("unknown")
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_string()
}

fn extract_path_literal(line: &str) -> Option<String> {
    // Simplified: extract string literals that look like paths
    for word in line.split(|c| c == '"' || c == '\'') {
        if word.contains('/') || word.contains('\\') {
            return Some(word.to_string());
        }
    }
    None
}

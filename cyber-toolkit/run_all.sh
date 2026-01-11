#!/usr/bin/env bash
#
# CyberToolkit - Batch Analysis Runner
# 
# Automates web scanning and APK analysis for multiple targets.
# Results are saved to the results/ directory.
#
# Usage:
#   ./run_all.sh --targets targets.txt
#   ./run_all.sh --apks /path/to/apks
#   ./run_all.sh --targets targets.txt --apks /path/to/apks
#
# Author: Ghariani Oussema
# License: MIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${BASE_DIR}/results"
TARGETS_FILE=""
APKS_DIR=""
PARALLEL_JOBS=4
VERBOSE=false

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Show usage
show_usage() {
    cat << EOF
CyberToolkit Batch Runner

Usage: $(basename "$0") [OPTIONS]

Options:
    --targets FILE      File containing target URLs (one per line)
    --apks DIR          Directory containing APK files to analyze
    --output DIR        Output directory for results (default: ./results)
    --parallel N        Number of parallel jobs (default: 4)
    --verbose           Enable verbose output
    --help              Show this help message

Examples:
    $(basename "$0") --targets targets.txt
    $(basename "$0") --apks ~/apks --output ./scan_results
    $(basename "$0") --targets targets.txt --apks ~/apks --parallel 8

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --targets)
                TARGETS_FILE="$2"
                shift 2
                ;;
            --apks)
                APKS_DIR="$2"
                shift 2
                ;;
            --output)
                RESULTS_DIR="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi
    
    if [[ -n "$APKS_DIR" ]]; then
        if ! command -v apktool &> /dev/null; then
            log_warning "apktool not found - APK decompilation may fail"
        fi
        if ! command -v jadx &> /dev/null; then
            log_warning "jadx not found - Java decompilation may fail"
        fi
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        exit 1
    fi
}

# Sanitize filename
sanitize_filename() {
    local input="$1"
    echo "$input" | sed 's#https\?://##; s#[:/\\?*|"<> ]#_#g' | cut -c1-100
}

# Scan a single website
scan_website() {
    local target="$1"
    local safe_name
    safe_name=$(sanitize_filename "$target")
    local output_file="${RESULTS_DIR}/${safe_name}.web.json"
    local log_file="${RESULTS_DIR}/${safe_name}.web.log"
    
    log_info "Scanning: $target"
    
    if python3 "${BASE_DIR}/web-scanner/scanner.py" "$target" \
        --output "$output_file" \
        2> "$log_file"; then
        log_success "Completed: $target -> $output_file"
        return 0
    else
        log_error "Failed: $target (see $log_file)"
        return 1
    fi
}

# Analyze a single APK
analyze_apk() {
    local apk_path="$1"
    local apk_name
    apk_name=$(basename "$apk_path" .apk)
    local output_file="${RESULTS_DIR}/${apk_name}.apk.json"
    local log_file="${RESULTS_DIR}/${apk_name}.apk.log"
    
    log_info "Analyzing: $apk_path"
    
    if python3 "${BASE_DIR}/apk-analyzer/analyze.py" "$apk_path" \
        --output "$output_file" \
        --no-mobsf \
        2> "$log_file"; then
        log_success "Completed: $apk_name -> $output_file"
        return 0
    else
        log_error "Failed: $apk_name (see $log_file)"
        return 1
    fi
}

# Process targets file
process_targets() {
    local targets_file="$1"
    local count=0
    local success=0
    local failed=0
    
    if [[ ! -f "$targets_file" ]]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    log_info "Processing targets from: $targets_file"
    
    while IFS= read -r target || [[ -n "$target" ]]; do
        # Skip empty lines and comments
        target=$(echo "$target" | xargs)
        [[ -z "$target" || "$target" =~ ^# ]] && continue
        
        ((count++))
        
        if scan_website "$target"; then
            ((success++))
        else
            ((failed++))
        fi
    done < "$targets_file"
    
    log_info "Web scanning complete: $success/$count successful, $failed failed"
}

# Process APK directory
process_apks() {
    local apks_dir="$1"
    local count=0
    local success=0
    local failed=0
    
    if [[ ! -d "$apks_dir" ]]; then
        log_error "APKs directory not found: $apks_dir"
        return 1
    fi
    
    log_info "Processing APKs from: $apks_dir"
    
    for apk_file in "$apks_dir"/*.apk; do
        [[ -f "$apk_file" ]] || continue
        
        ((count++))
        
        if analyze_apk "$apk_file"; then
            ((success++))
        else
            ((failed++))
        fi
    done
    
    if [[ $count -eq 0 ]]; then
        log_warning "No APK files found in: $apks_dir"
        return 0
    fi
    
    log_info "APK analysis complete: $success/$count successful, $failed failed"
}

# Generate report
generate_report() {
    log_info "Generating HTML report..."
    
    if python3 "${BASE_DIR}/report_generator.py" \
        --dir "$RESULTS_DIR" \
        --output "${RESULTS_DIR}/report.html"; then
        log_success "Report generated: ${RESULTS_DIR}/report.html"
    else
        log_warning "Failed to generate HTML report"
    fi
}

# Main function
main() {
    parse_args "$@"
    
    # Validate inputs
    if [[ -z "$TARGETS_FILE" && -z "$APKS_DIR" ]]; then
        log_error "No targets or APKs specified"
        show_usage
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    log_info "CyberToolkit Batch Runner"
    log_info "Results directory: $RESULTS_DIR"
    echo ""
    
    # Process targets
    if [[ -n "$TARGETS_FILE" ]]; then
        process_targets "$TARGETS_FILE"
        echo ""
    fi
    
    # Process APKs
    if [[ -n "$APKS_DIR" ]]; then
        process_apks "$APKS_DIR"
        echo ""
    fi
    
    # Generate report
    generate_report
    
    echo ""
    log_success "All tasks completed. Results saved to: $RESULTS_DIR"
}

# Run main
main "$@"

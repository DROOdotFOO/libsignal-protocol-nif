#!/bin/sh

# Script to copy NIF files to all required locations
# This centralizes the NIF copying logic that was duplicated in rebar.config
# Uses sh for better portability across Alpine Linux and other environments

set -e

# Get script directory - portable way without bash-specific features
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Copying NIF files from $PROJECT_ROOT/priv/ to build directories..."

# Check if priv directory exists and has NIF files
if [ ! -d "$PROJECT_ROOT/priv" ]; then
    echo "WARNING: priv directory does not exist. NIFs may not be built yet."
    exit 0
fi

# Check if any NIF files exist - more portable approach
nif_files_found=false
for ext in so dylib dll; do
    if [ -n "$(find "$PROJECT_ROOT/priv" -name "*.$ext" 2>/dev/null)" ]; then
        nif_files_found=true
        break
    fi
done

if [ "$nif_files_found" = false ]; then
    echo "WARNING: No NIF files found in priv directory."
    
    # Check if we're in a Docker build environment (where NIFs might be built separately)
    if [ -n "$DOCKER_BUILDKIT" ] || [ -n "$BUILDX_BUILDER" ] || [ -f "/.dockerenv" ]; then
        echo "INFO: Docker environment detected. Skipping NIF build - assuming NIFs are built separately."
        exit 0
    fi
    
    echo "Building NIFs first..."
    cd "$PROJECT_ROOT/c_src"
    
    # Check if cmake and make are available
    if ! command -v cmake >/dev/null 2>&1; then
        echo "ERROR: cmake not found. Cannot build NIFs."
        exit 1
    fi
    
    if ! command -v make >/dev/null 2>&1; then
        echo "ERROR: make not found. Cannot build NIFs."
        exit 1
    fi
    
    cmake . -DCMAKE_BUILD_TYPE=Release
    make
    cd "$PROJECT_ROOT"
    
    # Check again if build succeeded
    nif_files_found=false
    for ext in so dylib dll; do
        if [ -n "$(find "$PROJECT_ROOT/priv" -name "*.$ext" 2>/dev/null)" ]; then
            nif_files_found=true
            break
        fi
    done
    
    if [ "$nif_files_found" = false ]; then
        echo "ERROR: NIF build failed. No files created in priv directory."
        exit 1
    fi
fi

# Define target directories - using simple variable instead of bash array
TARGETS="
_build/default/lib/nif/priv
_build/test/lib/nif/priv
_build/unit+test/lib/nif/priv
_build/unit+test/extras/test/priv
"

# Create directories and copy files
for target in $TARGETS; do
    mkdir -p "$PROJECT_ROOT/$target"
    
    # Copy .so files (Linux)
    if [ -n "$(find "$PROJECT_ROOT/priv" -name "*.so" 2>/dev/null)" ]; then
        find "$PROJECT_ROOT/priv" -name "*.so" -exec cp {} "$PROJECT_ROOT/$target/" \;
        echo "Copied .so files to $target"
    fi
    
    # Copy .dylib files (macOS)
    if [ -n "$(find "$PROJECT_ROOT/priv" -name "*.dylib" 2>/dev/null)" ]; then
        find "$PROJECT_ROOT/priv" -name "*.dylib" -exec cp {} "$PROJECT_ROOT/$target/" \;
        echo "Copied .dylib files to $target"
    fi
    
    # Copy .dll files (Windows)
    if [ -n "$(find "$PROJECT_ROOT/priv" -name "*.dll" 2>/dev/null)" ]; then
        find "$PROJECT_ROOT/priv" -name "*.dll" -exec cp {} "$PROJECT_ROOT/$target/" \;
        echo "Copied .dll files to $target"
    fi
done

echo "NIF files copied successfully to all target directories." 
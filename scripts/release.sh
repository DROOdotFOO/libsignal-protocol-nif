#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VERSION_FILE="VERSION"
CHANGELOG_FILE="CHANGELOG.md"
DOCKER_IMAGE="libsignal-protocol-nif"
DOCKER_TAG="latest"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    log_error "Not in a git repository"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    log_error "Working directory is not clean. Please commit or stash changes."
    exit 1
fi

# Read current version
CURRENT_VERSION=$(cat "$VERSION_FILE")
log_info "Current version: $CURRENT_VERSION"

# Determine release type
RELEASE_TYPE=${1:-patch}
case $RELEASE_TYPE in
    major|minor|patch)
        ;;
    *)
        log_error "Invalid release type. Use: major, minor, or patch"
        exit 1
        ;;
esac

# Calculate new version
NEW_VERSION=$(echo "$CURRENT_VERSION" | awk -F. -v type="$RELEASE_TYPE" '
    BEGIN { OFS="." }
    {
        if (type == "major") {
            $1 = $1 + 1
            $2 = 0
            $3 = 0
        } else if (type == "minor") {
            $2 = $2 + 1
            $3 = 0
        } else if (type == "patch") {
            $3 = $3 + 1
        }
        print $1, $2, $3
    }
')

log_info "New version: $NEW_VERSION"

# Update version file
echo "$NEW_VERSION" > "$VERSION_FILE"

# Update the NIF application's version (also used by the Hex publisher).
sed -i.bak "s/{vsn, \".*\"}/{vsn, \"$NEW_VERSION\"}/" src/libsignal_protocol_nif.app.src
rm src/libsignal_protocol_nif.app.src.bak

# Update version in Elixir wrapper
sed -i.bak "s/version: \".*\"/version: \"$NEW_VERSION\"/" wrappers/elixir/mix.exs
rm wrappers/elixir/mix.exs.bak

# Update version in Gleam wrapper
sed -i.bak "s/version = \".*\"/version = \"$NEW_VERSION\"/" wrappers/gleam/gleam.toml
rm wrappers/gleam/gleam.toml.bak

# Build and test
log_info "Building and testing..."
make clean
make build
make test

# Run performance tests
log_info "Running performance tests..."
make perf-test

# Build Docker images
log_info "Building Docker images..."
docker build --target erlang-build -t "$DOCKER_IMAGE:erlang-$NEW_VERSION" -f docker/Dockerfile .
docker build --target elixir-build -t "$DOCKER_IMAGE:elixir-$NEW_VERSION" -f docker/Dockerfile .
docker build --target gleam-build -t "$DOCKER_IMAGE:gleam-$NEW_VERSION" -f docker/Dockerfile .
docker build --target production -t "$DOCKER_IMAGE:$NEW_VERSION" -f docker/Dockerfile .
docker tag "$DOCKER_IMAGE:$NEW_VERSION" "$DOCKER_IMAGE:$DOCKER_TAG"

# Update changelog
log_info "Updating changelog..."
{
    echo "# Changelog"
    echo ""
    echo "## [$NEW_VERSION] - $(date +%Y-%m-%d)"
    echo ""
    echo "### Added"
    echo "- Docker support for consistent builds"
    echo "- Performance optimizations with caching"
    echo "- Memory usage monitoring"
    echo "- Connection pooling"
    echo "- Release automation"
    echo ""
    echo "### Changed"
    echo "- Improved CMake configuration"
    echo "- Enhanced error handling"
    echo "- Better documentation"
    echo ""
    echo "### Fixed"
    echo "- Platform-specific build issues"
    echo "- Memory leaks in NIF code"
    echo "- Test output directory organization"
    echo ""
    echo "---"
    echo ""
    if [ -f "$CHANGELOG_FILE" ]; then
        tail -n +3 "$CHANGELOG_FILE"
    fi
} > "$CHANGELOG_FILE.tmp" && mv "$CHANGELOG_FILE.tmp" "$CHANGELOG_FILE"

# Commit changes
git add .
git commit -m "Release version $NEW_VERSION

- Docker support for consistent builds
- Performance optimizations with caching
- Memory usage monitoring
- Connection pooling
- Release automation"

# Create git tag
git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"

# Push changes
log_info "Pushing changes to remote..."
git push origin main
git push origin "v$NEW_VERSION"

# Create GitHub release (if gh CLI is available)
if command -v gh &> /dev/null; then
    log_info "Creating GitHub release..."
    gh release create "v$NEW_VERSION" \
        --title "Release $NEW_VERSION" \
        --notes-file "$CHANGELOG_FILE" \
        --draft
else
    log_warn "GitHub CLI not found. Please create release manually."
fi

log_info "Release $NEW_VERSION completed successfully!"
log_info "Docker images:"
log_info "  - $DOCKER_IMAGE:$NEW_VERSION"
log_info "  - $DOCKER_IMAGE:erlang-$NEW_VERSION"
log_info "  - $DOCKER_IMAGE:elixir-$NEW_VERSION"
log_info "  - $DOCKER_IMAGE:gleam-$NEW_VERSION" 
# The actual NIF compile is driven by c_src/CMakeLists.txt (cmake finds
# libsodium, openssl, and the BEAM include paths itself). LIBRARY_PATH_ENV
# below is the only path the Makefile needs to set; it's used by the test
# targets so they can dlopen Homebrew's keg-only openssl@3 at run time.

# Build targets
.PHONY: all clean test test-unit test-clean deps install perf-test perf-quick perf-baseline docker-build docker-test release dev-setup dev-test help ci-build ci-test build-wrappers publish-wrappers hex-package

# Default target
all: build

PRIV_DIR = priv
BUILD_DIR = c_src/build

# Guard clause to check we're in the correct directory
check-project-root:
	@if [ ! -f "Makefile" ] || [ ! -f "c_src/CMakeLists.txt" ]; then \
		echo "ERROR: This command must be run from the project root directory."; \
		echo "Current directory: $$(pwd)"; \
		echo "Expected files: Makefile, c_src/CMakeLists.txt"; \
		echo "Please navigate to the project root directory and try again."; \
		exit 1; \
	fi
	@if [ -d "c_src/build/c_src" ]; then \
		echo "WARNING: Detected nested build directory structure!"; \
		echo "This indicates a previous build issue. Cleaning up..."; \
		rm -rf c_src/build; \
		echo "Cleanup complete. Please run 'make build' again."; \
		exit 1; \
	fi

build: check-project-root $(BUILD_DIR)
	@echo "Building Signal Protocol NIF..."
	# Check for required dependencies
	@which cmake > /dev/null || (echo "ERROR: cmake not found. Please install cmake." && exit 1)
	@pkg-config --exists libsodium || (echo "ERROR: libsodium not found. Please install libsodium-dev." && exit 1)
	# Build C components
	cd c_src && cmake . -DCMAKE_BUILD_TYPE=Release && make
	# Verify NIF files were created
	@ls -la priv/ || (echo "ERROR: NIF files not created in priv/ directory" && exit 1)
	# Copy NIF to all relevant test and default profile priv directories
	mkdir -p _build/default/lib/nif/priv
	mkdir -p _build/test/lib/nif/priv
	mkdir -p _build/unit+test/lib/nif/priv
	mkdir -p _build/unit+test/extras/test/priv
	# Copy .so files (Linux) and .dylib files (macOS)
	cp priv/*.so _build/default/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/default/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/unit+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/unit+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/unit+test/extras/test/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/unit+test/extras/test/priv/ 2>/dev/null || true
	@echo "Build completed successfully!"

# CI-specific build target
ci-build: check-project-root $(BUILD_DIR)
	@echo "Building for CI environment..."
	cd c_src && cmake . -DCMAKE_BUILD_TYPE=Release && make -j$(shell nproc 2>/dev/null || echo 1)
	# Copy NIF to only the correct test and default profile priv directories
	mkdir -p _build/default/lib/nif/priv
	mkdir -p _build/test/lib/nif/priv
	cp priv/signal_nif.so _build/default/lib/nif/priv/ || true
	cp priv/signal_nif.so _build/test/lib/nif/priv/ || true
	@echo "CI build completed successfully!"

# Clean build artifacts. CMake currently runs in-tree (see `build` target), so
# Cache + Makefile + CMakeFiles/ + cmake_install.cmake land in c_src/ alongside
# the sources. Wipe them too so they don't leak into `rebar3 hex build` tarballs.
# Also wipe wrappers/*/priv/*.so to prevent stale NIFs from previous builds
# masking NIF-API changes during local wrapper tests -- CI uses `cp -f` to
# overwrite, but locally there's no auto-refresh so they go stale.
clean: check-project-root
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf priv/*.so priv/*.dylib priv/*.dll
	rm -rf c_src/CMakeFiles c_src/CMakeCache.txt c_src/cmake_install.cmake c_src/Makefile
	rm -f wrappers/elixir/priv/*.so wrappers/elixir/priv/*.dylib
	rm -f wrappers/gleam/priv/*.so wrappers/gleam/priv/*.dylib
	@echo "Cleanup completed!"

# Clean test artifacts
test-clean: check-project-root
	@echo "Cleaning test artifacts..."
	rm -rf tmp/
	rm -f *.log *.html *.xml *.cover
	@echo "Test cleanup completed!"

# Create build directory
$(BUILD_DIR): check-project-root
	@echo "Creating build directory..."
	mkdir -p $(BUILD_DIR)
	@echo "Build directory created: $(BUILD_DIR)"

# Create test directories
test-dirs:
	mkdir -p tmp/ct_logs
	mkdir -p tmp/ct_logs_unit
	mkdir -p tmp/ct_logs_integration
	mkdir -p tmp/ct_logs_smoke
	mkdir -p tmp/cover
	mkdir -p tmp/doc
	mkdir -p tmp/perf

# Platform-specific library path setup
ifeq ($(shell uname),Darwin)
    # macOS - handle both Intel and Apple Silicon
    ifeq ($(shell uname -m),arm64)
        LIBRARY_PATH_ENV = DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib
    else
        LIBRARY_PATH_ENV = DYLD_LIBRARY_PATH=/usr/local/opt/openssl@3/lib
    endif
else
    # Linux/Unix - usually not needed, but set LD_LIBRARY_PATH if required
    LIBRARY_PATH_ENV = LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/usr/local/lib
endif

# Run all tests
test: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 ct

# Run unit tests only
test-unit: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 as unit ct --dir test/erl/unit

# Run tests with coverage
test-cover: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 ct --cover

# Run unit tests with coverage
test-unit-cover: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 as unit ct --dir test/erl/unit --cover

# Run performance tests
# performance_test.erl lives under test/erl/, compiled into the test profile
# via {extra_src_dirs, ["test/erl"]} in rebar.config. Run with the actual
# rebar3 output paths, not bare "ebin"/"test" which don't exist at the root.
PERF_BEAM_PATHS = -pa _build/test/lib/libsignal_protocol_nif/ebin \
                  -pa _build/test/lib/libsignal_protocol_nif/test/erl
PERF_ERL = $(LIBRARY_PATH_ENV) erl -noshell $(PERF_BEAM_PATHS)

perf-test: test-dirs build
	@echo "Running performance benchmarks (full)..."
	@rebar3 as test compile
	$(PERF_ERL) -eval "performance_test:run(), halt()."

# Quick smoke run of the full bench surface at low iteration counts (~5s).
perf-quick: test-dirs build
	@echo "Running performance benchmarks (quick smoke)..."
	@rebar3 as test compile
	$(PERF_ERL) -eval "performance_test:quick(), halt()."

# Regenerate the checked-in baseline.term. Run after intentional perf changes.
perf-baseline: test-dirs build
	@echo "Regenerating performance baseline..."
	@rebar3 as test compile
	$(PERF_ERL) -eval "performance_test:baseline(), halt()."

# Generate documentation
docs: test-dirs
	rebar3 edoc

# Install dependencies
deps:
	rebar3 get-deps
	rebar3 compile

# Build and install
install: build
	rebar3 compile
	rebar3 install

# Docker targets
docker-build:
	@echo "Building Docker images..."
	docker build --target erlang-build -t libsignal-protocol-nif:erlang -f docker/Dockerfile .
	docker build --target elixir-build -t libsignal-protocol-nif:elixir -f docker/Dockerfile .
	docker build --target gleam-build -t libsignal-protocol-nif:gleam -f docker/Dockerfile .
	docker build --target production -t libsignal-protocol-nif:latest -f docker/Dockerfile .

docker-test:
	@echo "Running tests in Docker..."
	docker-compose up --abort-on-container-exit erlang-test
	docker-compose up --abort-on-container-exit elixir-test
	docker-compose up --abort-on-container-exit gleam-test

docker-perf:
	@echo "Running performance tests in Docker..."
	docker-compose up --abort-on-container-exit perf-test

# Build wrapper packages
build-wrappers: build
	@echo "Building wrapper packages..."
	@echo "Building Elixir wrapper..."
	cd wrappers/elixir && mix deps.get && mix compile
	@echo "Building Gleam wrapper..."
	cd wrappers/gleam && gleam build
	@echo "Wrapper packages built successfully!"

# Build wrapper packages with nix-shell
build-wrappers-nix:
	@echo "Building wrapper packages with nix-shell..."
	@echo "Building Elixir wrapper..."
	nix-shell --run "cd wrappers/elixir && mix deps.get && mix compile"
	@echo "Building Gleam wrapper..."
	nix-shell --run "cd wrappers/gleam && gleam build"
	@echo "Wrapper packages built successfully!"

# Build a clean Hex tarball for the main Erlang package.
# Builds NIFs first so scripts/copy_nifs.sh's auto-build branch doesn't kick in
# (that branch runs cmake in-tree in c_src/ and leaves droppings). Then strips
# any in-tree cmake artifacts left by `make build` itself before packaging, so
# the tarball ships only sources -- not CMakeFiles/, CMakeCache.txt, etc.
hex-package: clean build
	@echo "Stripping in-tree cmake droppings before packaging..."
	rm -rf c_src/CMakeFiles c_src/CMakeCache.txt c_src/cmake_install.cmake c_src/Makefile c_src/build
	rebar3 hex build
	@echo "Tarball: $$(ls _build/default/lib/libsignal_protocol_nif/hex/*.tar)"

# Publish wrapper packages to Hex.pm
publish-wrappers: build-wrappers
	@echo "Publishing wrapper packages to Hex.pm..."
	@echo "Publishing Elixir wrapper..."
	cd wrappers/elixir && mix hex.publish
	@echo "Publishing Gleam wrapper..."
	cd wrappers/gleam && rebar3 hex publish
	@echo "Wrapper packages published successfully!"

# Release automation
release:
	@echo "Creating release..."
	./scripts/release.sh

release-patch:
	@echo "Creating patch release..."
	./scripts/release.sh patch

release-minor:
	@echo "Creating minor release..."
	./scripts/release.sh minor

release-major:
	@echo "Creating major release..."
	./scripts/release.sh major

# Development targets
dev-setup: deps build test-dirs
	@echo "Development environment setup complete"

dev-test: test-unit perf-test
	@echo "All tests completed"

# monitor-memory / monitor-cache / perf-monitor were removed: the underlying
# performance_test:benchmark_memory_usage/benchmark_cache_performance functions
# were stubs that returned `ok` without measuring anything real. Use perf-test
# (full) or perf-quick (smoke) instead -- the rebuilt suite covers the same
# ground with real benchmarks.

# CI-specific test target
ci-test: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 ct --cover --verbose

# Help target
help:
	@echo "Available targets:"
	@echo "  build              - Build all components"
	@echo "  clean              - Clean all build artifacts"
	@echo "  test-clean         - Clean all test artifacts"
	@echo "  diagnose           - Diagnose and fix directory issues"
	@echo "  test               - Run all tests"
	@echo "  test-unit          - Run unit tests only"
	@echo "  test-cover         - Run tests with coverage"
	@echo "  test-unit-cover    - Run unit tests with coverage"
	@echo "  perf-test          - Run full performance benchmarks vs baseline"
	@echo "  perf-quick         - Quick smoke run of perf benchmarks"
	@echo "  perf-baseline      - Regenerate baseline.term after intentional perf changes"
	@echo "  docs               - Generate documentation"
	@echo "  deps               - Install dependencies"
	@echo "  install            - Build and install"
	@echo "  docker-build       - Build Docker images"
	@echo "  docker-test        - Run tests in Docker"
	@echo "  docker-perf        - Run performance tests in Docker"
	@echo "  release            - Create a new release"
	@echo "  release-patch      - Create a patch release"
	@echo "  release-minor      - Create a minor release"
	@echo "  release-major      - Create a major release"
	@echo "  dev-setup          - Setup development environment"
	@echo "  dev-test           - Run all development tests"
	@echo "  ci-build           - Build for CI"
	@echo "  ci-test            - Run CI tests"
	@echo "  build-wrappers     - Build Elixir and Gleam wrapper packages"
	@echo "  publish-wrappers   - Publish wrapper packages to Hex.pm"
	@echo "  help               - Show this help message"

# Diagnose and fix directory issues
diagnose:
	@echo "=== Directory Diagnosis ==="
	@echo "Current directory: $$(pwd)"
	@echo ""
	@echo "Checking for required files:"
	@if [ -f "Makefile" ]; then echo "✓ Makefile found"; else echo "✗ Makefile missing"; fi
	@if [ -f "c_src/CMakeLists.txt" ]; then echo "✓ c_src/CMakeLists.txt found"; else echo "✗ c_src/CMakeLists.txt missing"; fi
	@echo ""
	@echo "Checking for build directory issues:"
	@if [ -d "c_src/build" ]; then \
		echo "✓ c_src/build exists"; \
		if [ -d "c_src/build/c_src" ]; then \
			echo "✗ WARNING: Nested build directory detected!"; \
			echo "  This indicates a previous build issue."; \
		else \
			echo "✓ Build directory structure looks correct"; \
		fi; \
	else \
		echo "✓ No build directory (this is normal for fresh builds)"; \
	fi
	@echo ""
	@echo "Checking for nested directories:"
	@find . -name "build" -type d 2>/dev/null | head -10
	@echo ""
	@echo "=== Recommendations ==="
	@if [ ! -f "Makefile" ] || [ ! -f "c_src/CMakeLists.txt" ]; then \
		echo "❌ You are not in the project root directory."; \
		echo "   Navigate to the directory containing Makefile and c_src/CMakeLists.txt"; \
	elif [ -d "c_src/build/c_src" ]; then \
		echo "❌ Nested build directory detected. Run: make clean"; \
	else \
		echo "✅ Directory structure looks good. You can run: make build"; \
	fi 
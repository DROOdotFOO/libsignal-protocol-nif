# Variables
ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/erl_src/include"])])' -s init stop -noshell)
ERL_INTERFACE_PATH = $(shell erl -eval 'io:format("~s", [code:lib_dir(erl_interface, include)])' -s init stop -noshell)
CFLAGS = -I$(ERLANG_PATH) -I$(ERL_INTERFACE_PATH) -Iinclude -fPIC -O3 -Wall -Wextra
LDFLAGS = -L$(shell erl -eval 'io:format("~s", [code:lib_dir(erl_interface, lib)])' -s init stop -noshell)

# Platform-specific settings
ifeq ($(shell uname),Darwin)
    # macOS - handle both Intel and Apple Silicon
    ifeq ($(shell uname -m),arm64)
        CFLAGS += -I/opt/homebrew/opt/openssl/include
        LDFLAGS += -L/opt/homebrew/opt/openssl/lib
    else
        CFLAGS += -I/usr/local/opt/openssl/include
        LDFLAGS += -L/usr/local/opt/openssl/lib
    endif
    SHARED_EXT = dylib
else ifeq ($(OS),Windows_NT)
    # Windows
    SHARED_EXT = dll
else
    # Linux
    CFLAGS += -I/usr/include/openssl
    LDFLAGS += -L/usr/lib
    SHARED_EXT = so
endif

# Build targets
.PHONY: all clean test test-unit test-integration test-smoke test-clean deps install perf-test perf-monitor docker-build docker-test release dev-setup dev-test monitor-memory monitor-cache help ci-build ci-test build-wrappers publish-wrappers

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
	mkdir -p _build/integration+test/lib/nif/priv
	mkdir -p _build/smoke+test/lib/nif/priv
	# Copy .so files (Linux) and .dylib files (macOS)
	cp priv/*.so _build/default/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/default/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/unit+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/unit+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/integration+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/integration+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.so _build/smoke+test/lib/nif/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/smoke+test/lib/nif/priv/ 2>/dev/null || true
	# Also copy to test-specific directories
	mkdir -p _build/unit+test/extras/test/priv
	mkdir -p _build/integration+test/extras/test/priv
	mkdir -p _build/smoke+test/extras/test/priv
	cp priv/*.so _build/unit+test/extras/test/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/unit+test/extras/test/priv/ 2>/dev/null || true
	cp priv/*.so _build/integration+test/extras/test/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/integration+test/extras/test/priv/ 2>/dev/null || true
	cp priv/*.so _build/smoke+test/extras/test/priv/ 2>/dev/null || true
	cp priv/*.dylib _build/smoke+test/extras/test/priv/ 2>/dev/null || true
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

# Clean build artifacts
clean: check-project-root
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf priv/*.so priv/*.dylib priv/*.dll
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

# Run integration tests only
test-integration: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 as integration ct

# Run smoke tests only
test-smoke: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 as smoke ct

# Run tests with coverage
test-cover: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 ct --cover

# Run unit tests with coverage
test-unit-cover: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 as unit ct --dir test/erl/unit --cover

# Run integration tests with coverage
test-integration-cover: test-dirs
	$(LIBRARY_PATH_ENV) rebar3 as integration ct --cover

# Run performance tests
perf-test: test-dirs build
	@echo "Running performance benchmarks..."
	$(LIBRARY_PATH_ENV) erl -noshell -pa ebin -pa test -eval "performance_test:run_benchmarks(), halt()."

# Run performance monitoring
perf-monitor: test-dirs build
	@echo "Starting performance monitoring..."
	$(LIBRARY_PATH_ENV) erl -noshell -pa ebin -pa test -eval "performance_test:run_benchmarks(), timer:sleep(5000), performance_test:run_benchmarks(), halt()."

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

dev-test: test-smoke test-unit test-integration perf-test
	@echo "All tests completed"

# Monitoring targets
monitor-memory:
	@echo "Monitoring memory usage..."
	erl -noshell -pa ebin -eval "performance_test:benchmark_memory_usage(1000), halt()."

monitor-cache:
	@echo "Monitoring cache performance..."
	erl -noshell -pa ebin -eval "performance_test:benchmark_cache_performance(1000), halt()."

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
	@echo "  test-integration   - Run integration tests only"
	@echo "  test-smoke         - Run smoke tests only"
	@echo "  test-cover         - Run tests with coverage"
	@echo "  test-unit-cover    - Run unit tests with coverage"
	@echo "  test-integration-cover - Run integration tests with coverage"
	@echo "  perf-test          - Run performance benchmarks"
	@echo "  perf-monitor       - Run performance monitoring"
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
	@echo "  monitor-memory     - Monitor memory usage"
	@echo "  monitor-cache      - Monitor cache performance"
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
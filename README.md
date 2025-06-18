# BTC Federation Test Suite

A comprehensive test framework for BTC federation nodes, providing Docker-based automated testing infrastructure for multi-node federation scenarios.

**Adapted from**: [vtcpd-test-suite](https://github.com/vTCP-Foundation/vtcpd-test-suite)  
**Modified for**: Single BTC federation node binary execution and testing

## Overview

This test suite enables automated testing of BTC federation node clusters using Docker containers. It provides a Go-based framework for orchestrating multi-node test scenarios with configurable network conditions and comprehensive test validation.

### Key Features

- **Multi-Distribution Support**: Ubuntu and Manjaro Linux distributions
- **Dockerized Testing**: Isolated container-based node execution
- **Dynamic Configuration**: Environment variable-driven node configuration
- **Network Condition Simulation**: Latency, packet loss, and other network conditions
- **Automated Cleanup**: Proper resource management and cleanup
- **Comprehensive Testing**: Unit, integration, and end-to-end test support

## Prerequisites

### System Requirements
- Docker Engine 20.0.0 or later
- Docker Compose 2.0.0 or later  
- Go 1.21 or later
- Make utility
- Git

### Platform Support
- **Ubuntu**: 22.04 LTS or later
- **Manjaro**: Latest stable release
- **macOS**: Docker Desktop with Linux containers
- **Windows**: WSL2 with Docker Desktop

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd btc-federation-test-suite
```

### 2. Configure Build Environment
```bash
# Copy the example Makefile and customize for your environment
cp Makefile.example Makefile

# Edit Makefile to set the correct path to your btc-federation binary
# Update the BTC_FEDERATION_SOURCE variable to point to your binary location
# Example: BTC_FEDERATION_SOURCE := /home/user/btc-federation/build/btc-federation
nano Makefile  # or use your preferred editor
```

### 3. Install Dependencies
```bash
# Install Go dependencies
go mod tidy

# Verify installation
go version
docker --version
make --version
```

### 4. Set Up BTC Federation Binary
```bash
# Copy the btc-federation binary to deps directory
# This will use the path specified in your Makefile
make init-deps-symlinks

# Alternative: manually copy the binary
# cp /path/to/your/btc-federation-node deps/
# chmod +x deps/btc-federation-node
```

### 5. Initial Setup
```bash
# Complete development environment setup
make dev-setup
```

## Directory Structure

```
btc-federation-test-suite/
├── deps/                          # Dependencies and binaries
│   └── btc-federation-node        # BTC federation node binary
├── pkg/                           # Go package source code
│   └── testsuite/                 # Test suite framework
│       ├── cluster.go             # Cluster management
│       └── node.go                # Node configuration
├── test/                          # Test files
│   └── common/                    # Common test cases
│       └── common_test.go         # Basic test scenarios
├── Dockerfile                     # Multi-distribution container
├── Makefile.example              # Build and test commands
├── go.mod                        # Go module configuration
├── go.sum                        # Go dependency checksums
└── README.md                     # This documentation
```

## Quick Start

### 1. Build Test Images

You can build Docker images for different Linux distributions:

```bash
# Build for Ubuntu (recommended for most users)
make docker-build-test-ubuntu

# Build for Manjaro Linux
make docker-build-test-manjaro

# Build for default distribution (Ubuntu)
make docker-build-test

# Build for all supported distributions
make docker-build-all
```

**Distribution-specific images:**
- `btc-federation-test:ubuntu` - Ubuntu 22.04 LTS based image
- `btc-federation-test:manjaro` - Manjaro Linux based image

### 2. Run Basic Tests
```bash
# Execute the basic 2-node test suite (uses Ubuntu by default)
make test

# Run tests on specific distribution
make test-ubuntu      # Test with Ubuntu image
make test-manjaro     # Test with Manjaro image

# Run tests on all distributions
make test-all-distros
```

### 3. Manual Node Testing
```bash
# Start a single node for manual testing (uses Ubuntu image)
make run-node

# View logs from running containers
make logs

# Stop the running test node
make stop-node
```

## Configuration

### Makefile Configuration

Before building and running tests, you need to configure the Makefile for your environment:

```bash
# Copy the example Makefile
cp Makefile.example Makefile
```

**Key configuration variables in Makefile:**

| Variable | Description | Example |
|----------|-------------|---------|
| `BTC_FEDERATION_SOURCE` | Path to your btc-federation binary | `/home/user/btc-federation/build/btc-federation` |
| `BTC_FEDERATION_BIN` | Target path for binary in deps/ | `deps/btc-federation-node` |
| `DEFAULT_DISTRO` | Default distribution for builds | `ubuntu` |
| `TEST_TIMEOUT` | Test execution timeout | `30s` |

**Example Makefile configuration:**
```makefile
# Configuration constants
BTC_FEDERATION_SOURCE := /home/mc/Personal/vtcp/btc-federation/build/btc-federation
BTC_FEDERATION_BIN := deps/btc-federation-node
DEFAULT_DISTRO := ubuntu
DEFAULT_PORT := 9000
TEST_TIMEOUT := 30s
```

### Environment Variables

The following environment variables control node behavior:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PRIVATE_KEY` | Node private key (base64) | Generated | Yes |
| `IP_ADDRESS` | Node IP address | 0.0.0.0 | Yes |
| `PORT` | Node port number | 9000 | Yes |
| `DOCKER_IMAGE` | Docker image override | ubuntu | No |

### Node Configuration

Nodes are configured via YAML generation with the following structure:

```yaml
node:
    private_key: ${PRIVATE_KEY}
network:
    addresses:
        - /ip4/${IP_ADDRESS}/tcp/${PORT}
peers:
    exchange_interval: 30s
    connection_timeout: 10s
logging:
    level: info
    format: json
```

## Usage Examples

### Basic 2-Node Test
```bash
# Run the foundational 2-node startup test
go test -v ./test/common/... -run TestBasicTwoNodeStartup
```

### Custom Node Configuration

The framework provides two API patterns for node management:

#### 1. vtcpd-test-suite Compatible API (Original Pattern)
```go
// Create context and cluster
ctx := context.Background()
cluster, _ := testsuite.NewCluster(nil)

// Create node configuration
nodeConfig := &testsuite.NodeConfig{
    IPAddress: "172.17.0.2",
    Port: 9001,
    LogLevel: "debug",
}

// Create node instance
node, err := testsuite.NewNode(nodeConfig)
if err != nil {
    t.Fatalf("Failed to create node: %v", err)
}

// Start node using original vtcpd-test-suite API
cluster.RunNode(ctx, t, nil, node)
```

#### 2. Convenience API (Error-returning Pattern)
```go
// Create cluster
cluster, _ := testsuite.NewCluster(nil)

// Create custom node configuration
nodeConfig := &testsuite.NodeConfig{
    IPAddress: "172.17.0.2",
    Port: 9001,
    LogLevel: "debug",
}

// Create and run node with error handling
node, err := cluster.RunNodeWithReturn(nodeConfig)
if err != nil {
    log.Fatalf("Failed to start node: %v", err)
}
```

### Network Condition Testing
```go
// Apply network latency
conditions := map[string]interface{}{
    "latency": "50ms",
    "packet_loss": "1%",
}
cluster.ConfigureNetworkConditions(conditions)

// Remove conditions
cluster.RemoveNetworkConditions()
```

### Multi-Node Scenarios
```go
// Configure multiple nodes
configs := []*testsuite.NodeConfig{
    {Port: 9000, ContainerName: "node-1"},
    {Port: 9001, ContainerName: "node-2"},
    {Port: 9002, ContainerName: "node-3"},
}

// Start all nodes
nodes, err := cluster.RunNodes(configs)
```

## Testing Framework

### Test Categories

1. **Unit Tests**: Individual component testing
   ```bash
   go test -v ./pkg/testsuite/...
   ```

2. **Integration Tests**: Multi-component interaction testing
   ```bash
   go test -v ./test/integration/...
   ```

3. **End-to-End Tests**: Complete workflow testing
   ```bash
   make test
   ```

### Test Configuration Constants

The framework uses the following test constants (following DRY principles):

```go
const (
    TestDuration = 5 * time.Second    // Basic test duration
    NodeCount = 2                     // Default node count
    BasePort = 9000                   // Starting port number
    TestTimeout = 30 * time.Second    // Overall test timeout
)
```

### Writing Custom Tests

```go
func TestCustomScenario(t *testing.T) {
    // Create cluster
    cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
        NetworkName: "custom-test-net",
        NodeCount: 3,
    })
    if err != nil {
        t.Fatalf("Failed to create cluster: %v", err)
    }
    defer cluster.Cleanup()

    // Test implementation...
}
```

## Performance Characteristics

The test framework is designed with the following performance targets:

- **Container Startup**: <10 seconds per node
- **Memory Usage**: <512MB per container  
- **Framework Initialization**: <5 seconds
- **Test Execution**: <30 seconds for basic scenarios

## Troubleshooting

### Common Issues

#### 1. Binary Not Found
```
Error: BTC federation binary not found at deps/btc-federation-node
```
**Solution**: Configure Makefile and copy binary to deps directory
```bash
# 1. Configure Makefile with correct binary path
cp Makefile.example Makefile
# Edit BTC_FEDERATION_SOURCE in Makefile to point to your binary

# 2. Copy binary using Makefile
make init-deps-symlinks

# 3. Alternative: manual copy
cp /path/to/btc-federation-node deps/
chmod +x deps/btc-federation-node

# 4. Verify binary exists and is executable
ls -la deps/btc-federation-node
```

#### 2. Docker Permission Issues
```
Error: permission denied while trying to connect to Docker daemon
```
**Solution**: Add user to docker group or run with sudo
```bash
sudo usermod -aG docker $USER
# Log out and log back in
```

#### 3. Port Conflicts
```
Error: port already in use
```
**Solution**: Clean up existing containers
```bash
make clean
```

#### 4. Network Issues
```
Error: failed to create network
```
**Solution**: Clean up Docker networks
```bash
docker network prune -f
```

### Debugging

#### View Container Logs
```bash
# All test containers
make logs

# Specific container
docker logs btc-federation-test-node
```

#### Interactive Container Access
```bash
# Access running container
docker exec -it btc-federation-test-node /bin/bash

# Check configuration in the new directory structure
docker exec btc-federation-test-node cat /btc-federation/conf.yaml

# Check binary location
docker exec btc-federation-test-node ls -la /btc-federation/
```

#### Network Debugging
```bash
# List Docker networks
docker network ls

# Inspect test network
docker network inspect btc-federation-test-net
```

## Development

### Code Formatting
```bash
# Format Go code
make go-fmt

# Run linters
go vet ./...
```

### Adding New Tests
1. Create test file in appropriate directory
2. Follow existing naming conventions
3. Use framework constants for repeated values
4. Include proper cleanup in defer statements
5. Add comprehensive error handling

### Build System

The Makefile provides comprehensive build and test targets following vtcpd-test-suite patterns:

**Setup and Configuration:**
```bash
make help                    # Show all available targets
make init-deps              # Initialize dependencies directory
make init-deps-symlinks     # Copy binary from BTC_FEDERATION_SOURCE
make setup                  # Initial development setup
make dev-setup              # Complete development environment setup
```

**Docker Image Building:**
```bash
make docker-build-test-ubuntu    # Build Ubuntu-based test image
make docker-build-test-manjaro   # Build Manjaro-based test image
make docker-build-test          # Build default distribution (Ubuntu)
make docker-build-all           # Build all distribution images
```

**Testing:**
```bash
make test                   # Run complete test suite (Ubuntu)
make test-ubuntu           # Run tests with Ubuntu image
make test-manjaro          # Run tests with Manjaro image
make test-all-distros      # Run tests on all distributions
```

**Development:**
```bash
make go-mod-tidy           # Tidy Go modules
make go-test               # Run Go tests without Docker
make go-fmt                # Format Go code
```

**Utilities:**
```bash
make run-node              # Start single test node
make stop-node             # Stop running test node
make logs                  # View container logs
make clean                 # Clean up all artifacts
make test-cleanup          # Clean up test environment
```

## Contributing

### Guidelines
1. Follow existing code patterns from vtcpd-test-suite
2. Include proper source attribution in comments
3. Use constants for repeated values (DRY principle)
4. Write comprehensive tests for new features
5. Update documentation for changes

### Code Style
- Follow Go conventions and gofmt formatting
- Include package and function documentation
- Use descriptive variable and function names
- Handle errors appropriately with context

## License

This project maintains the same license as the original vtcpd-test-suite.

## API Compatibility with vtcpd-test-suite

This project maintains API compatibility with the original [vtcpd-test-suite](https://github.com/vTCP-Foundation/vtcpd-test-suite) while providing convenience methods for easier usage.

### Original vtcpd-test-suite API
- `RunNode(ctx context.Context, t *testing.T, wg *sync.WaitGroup, node *Node)` - Direct testing integration
- `RunNodes(ctx context.Context, t *testing.T, nodes []*Node)` - Concurrent node startup with WaitGroup

### Convenience Extensions
- `RunNodeWithReturn(nodeConfig *NodeConfig) (*Node, error)` - Error-returning wrapper
- `RunNodesWithReturn(nodeConfigs []*NodeConfig) ([]*Node, error)` - Batch node startup with error handling

Both approaches are supported and can be used interchangeably depending on your testing needs.

## Acknowledgments

- Original [vtcpd-test-suite](https://github.com/vTCP-Foundation/vtcpd-test-suite) project
- Docker containerization patterns
- Go testing framework best practices

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review existing test patterns in the codebase
3. Consult the original vtcpd-test-suite documentation
4. Create detailed issue reports with reproduction steps 
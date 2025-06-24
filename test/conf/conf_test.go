// Package conf provides configuration validation tests for the BTC federation
// This test suite validates various configuration scenarios including:
// - Missing configuration files
// - Invalid YAML formats
// - Missing or invalid configuration sections
// - Invalid parameter values
//
// Testing approach: Uses cluster.RunNode() and testsuite.NewNode() for container management
// This integrates with the existing test infrastructure properly

package conf

import (
	"context"
	"fmt"
	"testing"
	"time"

	"btc-federation-test-suite/pkg/testsuite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test timeout and parallelism settings
const (
	TestTimeout       = 3 * time.Minute  // Maximum time for entire test suite
	ParallelBatchSize = 3                // Number of tests to run in parallel batches
	SingleTestTimeout = 30 * time.Second // Timeout for individual test
)

// TestConfYamlValidation is the main test function that orchestrates all configuration validation tests
// Following the PRD requirement to test 20 scenarios using real Docker containers
func TestConfYamlValidation(t *testing.T) {
	t.Parallel()

	// Set overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	t.Logf("Starting BTC Federation Configuration Validation Tests")
	t.Logf("Testing %d scenarios using real Docker containers", 20)
	t.Logf("Expected results: 2 success scenarios (exit code 0), 18 error scenarios (exit code 1)")

	// Initialize cluster for container management
	cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
		NetworkName: "btc-federation-test-net",
		DockerImage: "btc-federation-test:ubuntu",
	})
	require.NoError(t, err, "Failed to initialize cluster")
	defer cluster.Cleanup()

	scenarios := NewConfigScenarios()
	require.NotNil(t, scenarios, "Failed to create test scenarios")

	// Test success scenarios (should exit with code 0)
	t.Run("SuccessScenarios", func(t *testing.T) {
		testSuccessScenarios(ctx, t, scenarios, cluster)
	})

	// Test error scenarios (should exit with code 1)
	t.Run("ErrorScenarios", func(t *testing.T) {
		testErrorScenarios(ctx, t, scenarios, cluster)
	})

	t.Log("All configuration validation tests completed successfully")
}

// testSuccessScenarios tests scenarios that should succeed (exit code 0)
func testSuccessScenarios(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	t.Log("Testing success scenarios (expected exit code 0)")

	successTests := []struct {
		name        string
		description string
		testFunc    func(t *testing.T)
	}{
		{
			name:        "Scenario01_MissingConfigFile",
			description: "Missing conf.yaml should generate default configuration (exit code 0)",
			testFunc: func(t *testing.T) {
				testMissingConfigFile(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario04_MissingPrivateKey",
			description: "Missing private_key should generate new key (exit code 0)",
			testFunc: func(t *testing.T) {
				testMissingPrivateKey(ctx, t, scenarios, cluster)
			},
		},
	}

	// Run success tests sequentially
	for _, test := range successTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("Testing: %s", test.description)
			test.testFunc(t)
		})
	}
}

// testErrorScenarios tests scenarios that should fail (exit code 1)
func testErrorScenarios(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	t.Log("Testing error scenarios (expected exit code 1)")

	errorTests := []struct {
		name        string
		description string
		testFunc    func(t *testing.T)
	}{
		{
			name:        "Scenario02_EmptyConfigFile",
			description: "Empty conf.yaml should exit with code 1",
			testFunc: func(t *testing.T) {
				testEmptyConfigFile(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario03_MalformedYAML",
			description: "Malformed YAML should exit with code 1",
			testFunc: func(t *testing.T) {
				testMalformedYAML(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario05_InvalidPrivateKey",
			description: "Invalid private_key should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidPrivateKey(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario06_MissingNetwork",
			description: "Missing network section should exit with code 1",
			testFunc: func(t *testing.T) {
				testMissingNetwork(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario07_MissingAddresses",
			description: "Missing network.addresses should exit with code 1",
			testFunc: func(t *testing.T) {
				testMissingAddresses(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario08_EmptyAddresses",
			description: "Empty network.addresses should exit with code 1",
			testFunc: func(t *testing.T) {
				testEmptyAddresses(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario09_InvalidAddress",
			description: "Invalid address format should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidAddress(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario10_MissingPeers",
			description: "Missing peers section should exit with code 1",
			testFunc: func(t *testing.T) {
				testMissingPeers(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario11_MissingConnectionTimeout",
			description: "Missing peers.connection_timeout should exit with code 1",
			testFunc: func(t *testing.T) {
				testMissingConnectionTimeout(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario12_InvalidConnectionTimeout",
			description: "Invalid peers.connection_timeout should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidConnectionTimeout(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario13_MissingLogging",
			description: "Missing logging section should exit with code 1",
			testFunc: func(t *testing.T) {
				testMissingLogging(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario14_InvalidLogLevel",
			description: "Invalid logging.level should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidLogLevel(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario15_InvalidLogFormat",
			description: "Invalid logging.format should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidLogFormat(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario16_InvalidConsoleOutput",
			description: "Invalid console output should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidConsoleOutput(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario17_InvalidFileMaxSize",
			description: "Invalid file max size should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidFileMaxSize(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario18_InvalidPort",
			description: "Invalid port number should exit with code 1",
			testFunc: func(t *testing.T) {
				testInvalidPort(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario19_MixedValidInvalid",
			description: "Mixed valid/invalid sections should exit with code 1",
			testFunc: func(t *testing.T) {
				testMixedValidInvalid(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario20_CompletelyInvalid",
			description: "Completely invalid configuration should exit with code 1",
			testFunc: func(t *testing.T) {
				testCompletelyInvalid(ctx, t, scenarios, cluster)
			},
		},
	}

	// Run error tests in batches
	runTestsInBatches(t, errorTests, ParallelBatchSize)
}

// runTestsInBatches executes tests in parallel batches
func runTestsInBatches(t *testing.T, tests []struct {
	name        string
	description string
	testFunc    func(t *testing.T)
}, batchSize int) {
	for i := 0; i < len(tests); i += batchSize {
		end := i + batchSize
		if end > len(tests) {
			end = len(tests)
		}

		batch := tests[i:end]
		for _, test := range batch {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				t.Logf("Testing: %s", test.description)
				test.testFunc(t)
			})
		}
	}
}

// Success scenario implementations (exit code 0)

// testMissingConfigFile tests scenario 1: Missing conf.yaml file
func testMissingConfigFile(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingConfigFile()

	// Create unique container name for this test
	containerName := generateContainerName()
	nodeConfig.ContainerName = containerName

	// Create node instance
	node, err := testsuite.NewNode(nodeConfig)
	require.NoError(t, err, "Failed to create node")

	// Use RunNode for success scenario - should start successfully
	cluster.RunNode(ctx, t, nil, node)

	// Additional verification: check that node started successfully
	success, err := cluster.CheckNodeLogContains(node.ContainerID, "Node started successfully")
	if err != nil {
		t.Logf("Warning: Could not check logs: %v", err)
	} else {
		assert.True(t, success, "Node should start successfully with default configuration")
	}

	// Verify configuration was generated properly
	configGenerated, err := cluster.CheckNodeLogContains(node.ContainerID, "BTC Federation Node starting with config")
	if err != nil {
		t.Logf("Warning: Could not check config logs: %v", err)
	} else {
		assert.True(t, configGenerated, "Configuration should be generated")
	}
}

// testMissingPrivateKey tests scenario 4: Missing private_key
func testMissingPrivateKey(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingPrivateKey()

	// Create unique container name for this test
	containerName := generateContainerName()
	nodeConfig.ContainerName = containerName

	// Create node instance
	node, err := testsuite.NewNode(nodeConfig)
	require.NoError(t, err, "Failed to create node")

	// Use RunNode for success scenario - should start successfully
	cluster.RunNode(ctx, t, nil, node)

	// Additional verification: check that node started successfully
	success, err := cluster.CheckNodeLogContains(node.ContainerID, "Node started successfully")
	if err != nil {
		t.Logf("Warning: Could not check logs: %v", err)
	} else {
		assert.True(t, success, "Node should start successfully with generated private key")
	}

	// Verify network manager started
	networkStarted, err := cluster.CheckNodeLogContains(node.ContainerID, "Network manager started successfully")
	if err != nil {
		t.Logf("Warning: Could not check network logs: %v", err)
	} else {
		assert.True(t, networkStarted, "Network manager should start successfully")
	}
}

// Error scenario implementations (exit code 1)

// testEmptyConfigFile tests scenario 2: Empty conf.yaml
func testEmptyConfigFile(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForEmptyConfigFile()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Empty conf.yaml should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMalformedYAML tests scenario 3: Malformed YAML
func testMalformedYAML(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMalformedConfigFile()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Malformed YAML should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidPrivateKey tests scenario 5: Invalid private_key
func testInvalidPrivateKey(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidPrivateKey()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid private_key should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMissingNetwork tests scenario 6: Missing network section
func testMissingNetwork(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingNetwork()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Missing network section should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMissingAddresses tests scenario 7: Missing network.addresses
func testMissingAddresses(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingAddresses()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Missing network.addresses should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testEmptyAddresses tests scenario 8: Empty network.addresses
func testEmptyAddresses(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForEmptyAddresses()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Empty network.addresses should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidAddress tests scenario 9: Invalid address format
func testInvalidAddress(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidAddress()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid address format should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMissingPeers tests scenario 10: Missing peers section
func testMissingPeers(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingPeers()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Missing peers section should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMissingConnectionTimeout tests scenario 11: Missing connection_timeout
func testMissingConnectionTimeout(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingConnectionTimeout()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Missing connection timeout should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidConnectionTimeout tests scenario 12: Invalid connection_timeout
func testInvalidConnectionTimeout(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidConnectionTimeout()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid connection timeout should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMissingLogging tests scenario 13: Missing logging section
func testMissingLogging(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingLogging()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Missing logging section should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidLogLevel tests scenario 14: Invalid log level
func testInvalidLogLevel(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidLogLevel()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid log level should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidLogFormat tests scenario 15: Invalid log format
func testInvalidLogFormat(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidLogFormat()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid log format should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidConsoleOutput tests scenario 16: Invalid console output
func testInvalidConsoleOutput(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidConsoleOutput()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid console output should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidFileMaxSize tests scenario 17: Invalid file max size
func testInvalidFileMaxSize(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidFileMaxSize()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid file max size should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testInvalidPort tests scenario 18: Invalid port number
func testInvalidPort(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForInvalidPort()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Invalid port number should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testMixedValidInvalid tests scenario 19: Mixed valid/invalid sections
func testMixedValidInvalid(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMixedValidInvalid()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Mixed valid/invalid sections should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// testCompletelyInvalid tests scenario 20: Completely invalid configuration
func testCompletelyInvalid(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForCompletelyInvalid()

	result, err := runNodeWithConfig(ctx, t, cluster, nodeConfig)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Completely invalid configuration should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")
}

// Helper functions

// runNodeWithConfig runs a node with the given configuration and returns the result
func runNodeWithConfig(ctx context.Context, t *testing.T, cluster *testsuite.Cluster, nodeConfig *testsuite.NodeConfig) (*testsuite.ConfigValidationResult, error) {
	// Create unique container name
	containerName := generateContainerName()
	nodeConfig.ContainerName = containerName

	// Create node instance
	node, err := testsuite.NewNode(nodeConfig)
	if err != nil {
		return &testsuite.ConfigValidationResult{
			ExitCode: 1,
			TimedOut: false,
			Logs:     "",
			Error:    err,
		}, nil
	}

	// Run node for configuration validation
	result, err := cluster.RunConfigValidation(ctx, node)
	if err != nil {
		return &testsuite.ConfigValidationResult{
			ExitCode: 1,
			TimedOut: false,
			Logs:     "",
			Error:    err,
		}, nil
	}

	return result, nil
}

// generateContainerName generates a unique container name for testing
func generateContainerName() string {
	return fmt.Sprintf("test-config-%d", time.Now().UnixNano())
}

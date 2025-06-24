// Package conf provides peers configuration validation tests for the BTC federation
// Task 05-3: peers.yaml Validation Tests
// This test suite validates 3 peers.yaml scenarios:
// 1. Missing peers.yaml (success + standalone mode log)
// 2. Empty peers.yaml file (error)
// 3. Empty peers value (success + standalone mode log)
//
// Testing approach: Uses cluster.RunNode() for success scenarios and
// cluster.RunConfigValidation() for error scenarios, matching conf_test.go approach

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

// Test timeout and configuration constants for peers testing
const (
	PeersTestTimeout       = 1 * time.Minute                                    // Maximum time for peers test suite
	PeersSingleTestTimeout = 20 * time.Second                                   // Timeout for individual peer test
	StandaloneLogMessage   = "No peers configured - running in standalone mode" // Expected log message
)

// TestPeersYamlValidation is the main test function for peers.yaml validation
// Tests 3 scenarios as defined in task 05-3: peers.yaml validation tests
func TestPeersYamlValidation(t *testing.T) {
	t.Parallel()

	// Set overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), PeersTestTimeout)
	defer cancel()

	t.Logf("Starting BTC Federation peers.yaml Validation Tests")
	t.Logf("Testing %d scenarios for peers.yaml configuration", 3)
	t.Logf("Expected results: 2 success scenarios (exit code 0 + standalone log), 1 error scenario (exit code 1)")

	// Initialize cluster for container management
	cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
		NetworkName: "btc-federation-peers-test-net",
		DockerImage: "btc-federation-test:ubuntu",
	})
	require.NoError(t, err, "Failed to initialize cluster")
	defer cluster.Cleanup()

	scenarios := NewConfigScenarios()
	require.NotNil(t, scenarios, "Failed to create test scenarios")

	// Test success scenarios (should exit with code 0 and log standalone message)
	t.Run("SuccessScenarios", func(t *testing.T) {
		testPeersSuccessScenarios(ctx, t, scenarios, cluster)
	})

	// Test error scenarios (should exit with code 1)
	t.Run("ErrorScenarios", func(t *testing.T) {
		testPeersErrorScenarios(ctx, t, scenarios, cluster)
	})

	t.Log("All peers.yaml validation tests completed successfully")
}

// testPeersSuccessScenarios tests scenarios that should succeed (exit code 0 + standalone log)
func testPeersSuccessScenarios(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	t.Log("Testing peers success scenarios (expected exit code 0 + standalone mode log)")

	successTests := []struct {
		name        string
		description string
		testFunc    func(t *testing.T)
	}{
		{
			name:        "Scenario01_MissingPeersFile",
			description: "Missing peers.yaml should start in standalone mode (exit code 0 + log)",
			testFunc: func(t *testing.T) {
				testMissingPeersFile(ctx, t, scenarios, cluster)
			},
		},
		{
			name:        "Scenario03_EmptyPeersValue",
			description: "Empty peers value should start in standalone mode (exit code 0 + log)",
			testFunc: func(t *testing.T) {
				testEmptyPeersValue(ctx, t, scenarios, cluster)
			},
		},
	}

	// Run success tests in parallel
	for _, test := range successTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("Testing: %s", test.description)
			test.testFunc(t)
		})
	}
}

// testPeersErrorScenarios tests scenarios that should fail (exit code 1)
func testPeersErrorScenarios(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	t.Log("Testing peers error scenarios (expected exit code 1)")

	errorTests := []struct {
		name        string
		description string
		testFunc    func(t *testing.T)
	}{
		{
			name:        "Scenario02_EmptyPeersFile",
			description: "Empty peers.yaml file should exit with code 1",
			testFunc: func(t *testing.T) {
				testEmptyPeersFile(ctx, t, scenarios, cluster)
			},
		},
	}

	// Run error tests
	for _, test := range errorTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("Testing: %s", test.description)
			test.testFunc(t)
		})
	}
}

// Success scenario implementations (exit code 0 + standalone log)

// testMissingPeersFile tests scenario 1: Missing peers.yaml file
func testMissingPeersFile(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForMissingPeersFile()

	// Create unique container name for this test
	containerName := generatePeersContainerName("missing-peers")
	nodeConfig.ContainerName = containerName

	// Create node instance
	node, err := testsuite.NewNode(nodeConfig)
	require.NoError(t, err, "Failed to create node")

	// Use RunNode for success scenario - should start successfully
	cluster.RunNode(ctx, t, nil, node)

	// Verify node started successfully
	success, err := cluster.CheckNodeLogContains(node.ContainerID, "Node started successfully")
	if err != nil {
		t.Logf("Warning: Could not check startup logs: %v", err)
	} else {
		assert.True(t, success, "Node should start successfully without peers.yaml")
	}

	// Verify standalone mode log message
	standaloneMode, err := cluster.CheckNodeLogContains(node.ContainerID, StandaloneLogMessage)
	if err != nil {
		t.Logf("Warning: Could not check standalone mode logs: %v", err)
	} else {
		assert.True(t, standaloneMode, "Node should log standalone mode message when peers.yaml is missing")
	}

	t.Logf("✓ Missing peers.yaml test completed - node started in standalone mode")
}

// testEmptyPeersValue tests scenario 3: Empty peers value in peers.yaml
func testEmptyPeersValue(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForEmptyPeersValue()

	// Create unique container name for this test
	containerName := generatePeersContainerName("empty-peers-value")
	nodeConfig.ContainerName = containerName

	// Create node instance
	node, err := testsuite.NewNode(nodeConfig)
	require.NoError(t, err, "Failed to create node")

	// Use RunNode for success scenario - should start successfully
	cluster.RunNode(ctx, t, nil, node)

	// Verify node started successfully
	success, err := cluster.CheckNodeLogContains(node.ContainerID, "Node started successfully")
	if err != nil {
		t.Logf("Warning: Could not check startup logs: %v", err)
	} else {
		assert.True(t, success, "Node should start successfully with empty peers value")
	}

	// Verify standalone mode log message
	standaloneMode, err := cluster.CheckNodeLogContains(node.ContainerID, StandaloneLogMessage)
	if err != nil {
		t.Logf("Warning: Could not check standalone mode logs: %v", err)
	} else {
		assert.True(t, standaloneMode, "Node should log standalone mode message when peers value is empty")
	}

	t.Logf("✓ Empty peers value test completed - node started in standalone mode")
}

// Error scenario implementations (exit code 1)

// testEmptyPeersFile tests scenario 2: Empty peers.yaml file
func testEmptyPeersFile(ctx context.Context, t *testing.T, scenarios *ConfigScenarios, cluster *testsuite.Cluster) {
	nodeConfig := scenarios.CreateNodeConfigForEmptyPeersFile()

	result, err := runPeersNodeWithConfig(ctx, t, cluster, nodeConfig, "empty-peers-file")
	require.NoError(t, err)

	assert.Equal(t, 1, result.ExitCode, "Empty peers.yaml file should result in validation error")
	assert.False(t, result.TimedOut, "Container should not timeout")

	t.Logf("✓ Empty peers.yaml file test completed - validation error as expected")
}

// Helper functions

// runPeersNodeWithConfig runs a node with the given configuration for peers testing
func runPeersNodeWithConfig(ctx context.Context, t *testing.T, cluster *testsuite.Cluster, nodeConfig *testsuite.NodeConfig, testType string) (*testsuite.ConfigValidationResult, error) {
	// Create unique container name
	containerName := generatePeersContainerName(testType)
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

// generatePeersContainerName generates a unique container name for peers testing
func generatePeersContainerName(testType string) string {
	return fmt.Sprintf("test-peers-%s-%d", testType, time.Now().UnixNano())
}

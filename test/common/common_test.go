// Package common provides common tests for BTC federation test suite
// Adapted from vtcpd-test-suite test patterns for BTC federation testing

package common

import (
	"context"
	"testing"
	"time"

	"btc-federation-test-suite/pkg/testsuite"
)

// Test constants following policy requirements for repeated values
const (
	// TestDuration is the duration for the basic 2-node test
	TestDuration = 5 * time.Second
	// NodeCount is the number of nodes for the basic test
	NodeCount = 2
	// BasePort is the starting port for test nodes
	BasePort = 9000
	// TestTimeout is the overall test timeout
	TestTimeout = 30 * time.Second
)

// TestBasicTwoNodeStartup tests starting 2 BTC federation nodes for 5 seconds
// This is the foundational test case as specified in the task requirements
// Based on vtcpd-test-suite test patterns
func TestBasicTwoNodeStartup(t *testing.T) {
	t.Log("Starting BTC Federation basic 2-node startup test")
	t.Logf("Test configuration: %d nodes, %v duration", NodeCount, TestDuration)

	// Create context with timeout for the test
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Create cluster instance
	cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
		NetworkName: "btc-federation-test-net",
		DockerImage: "btc-federation-test:ubuntu",
		NodeCount:   NodeCount,
		BasePort:    BasePort,
	})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	if cluster == nil {
		t.Fatal("Cluster should not be nil")
	}

	// Predefined private keys for test nodes
	// First node gets the first key, second node gets the second key
	testPrivateKeys := []string{
		"IbBr3HGYxpu+M3/h8xNcWtnnlN5WEwJCdlau3ExYPPM0t32Unu8fFTbd6AzVXy6kswCWLEG/bd/T1zbhbQXJPw==",
		"31WAxpr4/90ITOQ3qYYh+sVN1LktUaUV/rlZxxYGQ4gzLVH0C/b1piO+mqqdt/OICchoklnDPDAleO+EttbAmg==",
	}

	// Prepare nodes for 2-node test (following vtcpd-test-suite pattern)
	nodes := make([]*testsuite.Node, NodeCount)
	for i := 0; i < NodeCount; i++ {
		// Use predefined private key for this node
		privateKey := ""
		if i < len(testPrivateKeys) {
			privateKey = testPrivateKeys[i]
		}

		nodeConfig := &testsuite.NodeConfig{
			PrivateKey:    privateKey, // Set specific private key
			IPAddress:     "0.0.0.0",
			Port:          BasePort + i,
			ContainerName: nodeNameForIndex(i),
			NetworkName:   "btc-federation-test-net",
			DockerImage:   "btc-federation-test:ubuntu",
		}

		// Create node instances using vtcpd-test-suite pattern
		node, err := testsuite.NewNode(nodeConfig)
		if err != nil {
			t.Fatalf("Failed to create node %d: %v", i, err)
		}
		nodes[i] = node
	}

	// Start the nodes using vtcpd-test-suite API
	t.Log("Starting BTC federation nodes...")
	startTime := time.Now()

	// Use the original vtcpd-test-suite RunNodes signature
	cluster.RunNodes(ctx, t, nodes)

	startupDuration := time.Since(startTime)
	t.Logf("✓ %d nodes started successfully in %v", len(nodes), startupDuration)

	// Verify all nodes are running
	runningNodes := cluster.GetRunningNodes()
	if len(runningNodes) != NodeCount {
		t.Errorf("Expected %d running nodes, got %d", NodeCount, len(runningNodes))
	}

	// Log node details
	for i, node := range nodes {
		if !node.IsRunning {
			t.Errorf("Node %d should be running", i)
		}
		t.Logf("  Node %d: %s", i+1, node.String())
	}

	// Run for exactly 5 seconds as specified in requirements
	t.Logf("Running test for %v...", TestDuration)
	testTimer := time.NewTimer(TestDuration)

	// Monitor nodes during test execution
	healthCheckTicker := time.NewTicker(1 * time.Second)
	defer healthCheckTicker.Stop()

	testStart := time.Now()

	select {
	case <-testTimer.C:
		// Test completed successfully after 5 seconds
		actualDuration := time.Since(testStart)
		t.Logf("✓ Test completed after %v", actualDuration)

		// Verify duration is approximately 5 seconds (allow small variance)
		if actualDuration < TestDuration-500*time.Millisecond || actualDuration > TestDuration+500*time.Millisecond {
			t.Errorf("Test duration should be approximately %v, got %v", TestDuration, actualDuration)
		}

	case <-healthCheckTicker.C:
		// Periodic health check during test execution
		runningNodes := cluster.GetRunningNodes()
		if len(runningNodes) != NodeCount {
			t.Errorf("Expected %d running nodes, got %d", NodeCount, len(runningNodes))
			return
		}
	}

	// Final verification that all nodes are still running
	finalRunningNodes := cluster.GetRunningNodes()
	if len(finalRunningNodes) != NodeCount {
		t.Errorf("All %d nodes should still be running at test end, got %d", NodeCount, len(finalRunningNodes))
	}

	t.Log("✓ Basic 2-node startup test completed successfully")
}

// TestNodeConfiguration tests individual node configuration
// Following vtcpd-test-suite test patterns for configuration validation
func TestNodeConfiguration(t *testing.T) {
	t.Log("Testing BTC federation node configuration")

	// Test node creation with default configuration
	node, err := testsuite.NewNode(&testsuite.NodeConfig{})
	if err != nil {
		t.Fatalf("Failed to create node with default config: %v", err)
	}
	if node == nil {
		t.Fatal("Node should not be nil")
	}

	// Verify default values are set correctly
	if node.Config.Port != testsuite.DefaultPort {
		t.Errorf("Expected default port %d, got %d", testsuite.DefaultPort, node.Config.Port)
	}
	if node.Config.IPAddress != "0.0.0.0" {
		t.Errorf("Expected default IP '0.0.0.0', got '%s'", node.Config.IPAddress)
	}
	if node.Config.PrivateKey == "" {
		t.Error("Private key should be generated")
	}
	if node.Config.LogLevel != testsuite.DefaultLogLevel {
		t.Errorf("Expected default log level '%s', got '%s'", testsuite.DefaultLogLevel, node.Config.LogLevel)
	}
	if node.Config.LogFormat != testsuite.DefaultLogFormat {
		t.Errorf("Expected default log format '%s', got '%s'", testsuite.DefaultLogFormat, node.Config.LogFormat)
	}

	t.Logf("✓ Node configuration test passed: %s", node.String())
}

// TestClusterCreation tests cluster creation and basic operations
// Based on vtcpd-test-suite cluster testing patterns
func TestClusterCreation(t *testing.T) {
	t.Log("Testing BTC federation cluster creation")

	cluster, err := testsuite.NewCluster(nil) // Test with nil config
	if err != nil {
		t.Fatalf("Failed to create cluster with nil config: %v", err)
	}
	if cluster == nil {
		t.Fatal("Cluster should not be nil")
	}

	defer func() {
		if cleanupErr := cluster.Cleanup(); cleanupErr != nil {
			t.Errorf("Failed to cleanup cluster: %v", cleanupErr)
		}
	}()

	// Verify cluster state
	nodes := cluster.GetNodes()
	if len(nodes) != 0 {
		t.Errorf("New cluster should have no nodes, got %d", len(nodes))
	}

	runningNodes := cluster.GetRunningNodes()
	if len(runningNodes) != 0 {
		t.Errorf("New cluster should have no running nodes, got %d", len(runningNodes))
	}

	t.Log("✓ Cluster creation test completed successfully")
}

// TestNetworkConditions tests network condition configuration
// Adapted from vtcpd-test-suite network testing patterns
func TestNetworkConditions(t *testing.T) {
	t.Log("Testing network conditions configuration")

	cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
		NetworkName: "btc-federation-test-conditions",
	})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}

	defer func() {
		if cleanupErr := cluster.Cleanup(); cleanupErr != nil {
			t.Errorf("Failed to cleanup cluster: %v", cleanupErr)
		}
	}()

	// Test network conditions with empty cluster (should not error)
	err = cluster.ConfigureNetworkConditions(map[string]interface{}{
		"latency": "10ms",
	})
	if err != nil {
		t.Errorf("Configuring network conditions on empty cluster should not error: %v", err)
	}

	// Test removing network conditions
	err = cluster.RemoveNetworkConditions()
	if err != nil {
		t.Errorf("Removing network conditions should not error: %v", err)
	}

	t.Log("✓ Network conditions test completed successfully")
}

// TestRunNodeVtcpdPattern demonstrates the vtcpd-test-suite RunNode API usage
// Following the original vtcpd-test-suite pattern with context, testing.T, and WaitGroup
func TestRunNodeVtcpdPattern(t *testing.T) {
	t.Log("Testing RunNode with vtcpd-test-suite API pattern")

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
		NetworkName: "btc-federation-vtcpd-pattern-test",
	})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}

	defer func() {
		if cleanupErr := cluster.Cleanup(); cleanupErr != nil {
			t.Errorf("Failed to cleanup cluster: %v", cleanupErr)
		}
	}()

	// Create a single node following vtcpd-test-suite pattern
	nodeConfig := &testsuite.NodeConfig{
		IPAddress:     "0.0.0.0",
		Port:          BasePort + 100, // Use different port to avoid conflicts
		ContainerName: "btc-federation-vtcpd-pattern-node",
		NetworkName:   "btc-federation-vtcpd-pattern-test",
		DockerImage:   "btc-federation-test:ubuntu",
	}

	node, err := testsuite.NewNode(nodeConfig)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Test the original vtcpd-test-suite RunNode API
	cluster.RunNode(ctx, t, nil, node) // nil WaitGroup for single node test

	// Verify node is running
	if !node.IsRunning {
		t.Error("Node should be running after RunNode call")
	}

	runningNodes := cluster.GetRunningNodes()
	if len(runningNodes) != 1 {
		t.Errorf("Expected 1 running node, got %d", len(runningNodes))
	}

	t.Log("✓ vtcpd-test-suite RunNode API pattern test completed successfully")
}

// nodeNameForIndex generates a consistent node name for the given index
// Following DRY principle for repeated node naming logic
func nodeNameForIndex(index int) string {
	return "btc-federation-test-node-" + string(rune('0'+index))
}

// Helper function for test setup verification
func verifyTestEnvironment(t *testing.T) {
	t.Helper()

	// Verify required constants are properly defined
	if TestDuration != 5*time.Second {
		t.Errorf("Test duration should be 5 seconds, got %v", TestDuration)
	}
	if NodeCount != 2 {
		t.Errorf("Node count should be 2, got %d", NodeCount)
	}
	if BasePort != 9000 {
		t.Errorf("Base port should be 9000, got %d", BasePort)
	}

	t.Log("✓ Test environment verification completed")
}

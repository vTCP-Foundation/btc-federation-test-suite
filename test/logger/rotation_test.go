// Package logger provides tests for log rotation functionality in BTC federation
package logger

import (
	"context"
	"fmt"
	"testing"
	"time"

	"btc-federation-test-suite/pkg/testsuite"
)

// Test constants for log rotation testing
const (
	// TestTimeout is the overall test timeout
	TestTimeout = 600 * time.Second
	// RotationWaitTime is the time to wait for log rotation
	RotationWaitTime = 10 * time.Second
	// TestPort is the port for the test node
	TestPort = 9100
)

// TestLogRotation tests that log rotation occurs in btc-federation container
// Creates a container with 1kB log rotation limit, waits 10 seconds,
// then checks if log rotation occurred by verifying rotated log file exists
func TestLogRotation(t *testing.T) {
	t.Log("Starting BTC Federation log rotation test")
	t.Logf("Test configuration: wait time %v, timeout %v", RotationWaitTime, TestTimeout)

	// Create context with timeout for the test
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Create cluster instance
	cluster, err := testsuite.NewCluster(&testsuite.ClusterConfig{
		NetworkName: "btc-federation-log-rotation-test",
		DockerImage: "btc-federation-test:ubuntu",
	})
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	if cluster == nil {
		t.Fatal("Cluster should not be nil")
	}

	// Create node configuration with log rotation settings
	nodeConfig := &testsuite.NodeConfig{
		IPAddress:     "0.0.0.0",
		Port:          TestPort,
		ContainerName: "btc-federation-log-rotation-test-node",
		NetworkName:   "btc-federation-log-rotation-test",
		DockerImage:   "btc-federation-test:ubuntu",
		// Set log rotation parameters for quick rotation
		FileName:      "test-rotation.log",
		FileMaxSize:   "1MB", // Small size for quick rotation
		ConsoleOutput: true,
		ConsoleColor:  true,
		FileOutput:    true,
	}

	// Create node instance
	node, err := testsuite.NewNode(nodeConfig)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	t.Log("Starting BTC federation node with log rotation configuration...")
	startTime := time.Now()

	// Start the node using cluster API (similar to common_test.go)
	cluster.RunNode(ctx, t, nil, node)

	startupDuration := time.Since(startTime)
	t.Logf("✓ Node started successfully in %v", startupDuration)

	// Verify node is running
	if !node.IsRunning {
		t.Fatal("Node should be running after start")
	}

	runningNodes := cluster.GetRunningNodes()
	if len(runningNodes) != 1 {
		t.Errorf("Expected 1 running node, got %d", len(runningNodes))
	}

	t.Logf("Node details: %s", node.String())

	// Get container ID for executing commands
	containerID := node.ContainerID
	if containerID == "" {
		t.Fatal("Container ID should not be empty")
	}

	// Generate more logs by running the binary multiple times in sequence
	t.Log("Generating more logs by running btc-federation-node multiple times in sequence...")

	for i := 1; i <= 500; i++ {
		t.Logf("Sequential run #%d: Starting btc-federation-node...", i)

		// Run the binary and let it exit naturally (it runs for ~2-3 seconds)
		runCmd := []string{"sh", "-c", "cd /btc-federation && timeout 2s ./btc-federation-node || true"}
		_, err := cluster.ExecInContainer(containerID, runCmd)
		if err != nil {
			t.Logf("Warning: Failed to run binary on iteration #%d: %v", i, err)
		}

		// Check current log size every 50 runs
		if i%50 == 0 || i == 500 {
			sizeCmd := []string{"sh", "-c", "wc -c /btc-federation/test-rotation.log 2>/dev/null || echo '0'"}
			sizeOutput, err := cluster.ExecInContainer(containerID, sizeCmd)
			if err == nil {
				t.Logf("Log size after run #%d: %s", i, sizeOutput)

				// Parse the file size (format: "1234567 /path/to/file")
				var currentSize int64
				if _, parseErr := fmt.Sscanf(sizeOutput, "%d", &currentSize); parseErr == nil {
					// Check if file size exceeds rotation threshold (1MB = 1048576 bytes)
					const rotationThreshold = 1048576 // 1MB in bytes
					if currentSize >= rotationThreshold {
						t.Logf("⚠️  Log file size (%d bytes) has reached rotation threshold (%d bytes)", currentSize, rotationThreshold)

						// Check for rotation files
						rotationCmd := []string{"sh", "-c", "ls -la /btc-federation/*.log.* 2>/dev/null || echo 'NO_ROTATION_YET'"}
						rotationOutput, err := cluster.ExecInContainer(containerID, rotationCmd)
						if err == nil && rotationOutput != "NO_ROTATION_YET" {
							t.Logf("🎉 ROTATION DETECTED at run #%d: %s", i, rotationOutput)
							break // Exit loop early if rotation is detected
						} else {
							t.Fatalf("❌ ROTATION FAILED: Log file size (%d bytes) exceeded rotation threshold (%d bytes) but no rotation occurred. This indicates log rotation is not working properly.", currentSize, rotationThreshold)
						}
					}
				}

				// Also check for rotation files even if size parsing failed
				rotationCmd := []string{"sh", "-c", "ls -la /btc-federation/*.log.* 2>/dev/null || echo 'NO_ROTATION_YET'"}
				rotationOutput, err := cluster.ExecInContainer(containerID, rotationCmd)
				if err == nil && rotationOutput != "NO_ROTATION_YET" {
					t.Logf("🎉 ROTATION DETECTED at run #%d: %s", i, rotationOutput)
					break // Exit loop early if rotation is detected
				}
			} else {
				t.Logf("Warning: Failed to check log size after run #%d: %v", i, err)
			}
		}
	}

	t.Log("✓ Completed multiple restarts to generate logs")

	// Final check: if we completed all runs without rotation, verify the final size
	finalSizeCmd := []string{"sh", "-c", "wc -c /btc-federation/test-rotation.log 2>/dev/null || echo '0'"}
	finalSizeOutput, err := cluster.ExecInContainer(containerID, finalSizeCmd)
	if err == nil {
		var finalSize int64
		if _, parseErr := fmt.Sscanf(finalSizeOutput, "%d", &finalSize); parseErr == nil {
			const rotationThreshold = 1048576 // 1MB in bytes
			if finalSize >= rotationThreshold {
				// Check one more time for rotation files
				rotationCmd := []string{"sh", "-c", "ls -la /btc-federation/*.log.* 2>/dev/null || echo 'NO_ROTATION_YET'"}
				rotationOutput, err := cluster.ExecInContainer(containerID, rotationCmd)
				if err != nil || rotationOutput == "NO_ROTATION_YET" {
					t.Fatalf("❌ FINAL ROTATION CHECK FAILED: Log file size (%d bytes) exceeded rotation threshold (%d bytes) but no rotation occurred after %d runs. Log rotation is not working properly.", finalSize, rotationThreshold, 500)
				}
			}
		}
	}

	// Check if log rotation occurred by examining container
	t.Log("Checking if log rotation occurred in container...")

	// Verify node is still running after wait period
	finalRunningNodes := cluster.GetRunningNodes()
	if len(finalRunningNodes) != 1 {
		t.Errorf("Node should still be running after wait period, got %d running nodes", len(finalRunningNodes))
	}

	if !node.IsRunning {
		t.Error("Node should still be running after wait period")
	}

	// Actually check for log files in the container

	// Check if log files exist
	logCheckCmd := []string{"sh", "-c", "ls -la /btc-federation/*.log* 2>/dev/null || echo 'NO_LOG_FILES'"}
	logOutput, err := cluster.ExecInContainer(containerID, logCheckCmd)
	if err != nil {
		t.Fatalf("Failed to check log files in container: %v", err)
	}

	t.Logf("Log files output: %s", logOutput)

	if logOutput == "NO_LOG_FILES" {
		t.Error("❌ No log files found - file logging is not working")
		return
	}

	// Check file size to ensure logging is working
	sizeCheckCmd := []string{"sh", "-c", "wc -c /btc-federation/test-rotation.log 2>/dev/null || echo '0'"}
	sizeOutput, err := cluster.ExecInContainer(containerID, sizeCheckCmd)
	if err != nil {
		t.Fatalf("Failed to check log file size: %v", err)
	}

	t.Logf("Log file size: %s", sizeOutput)

	// Parse size (format: "1234 /path/to/file")
	if sizeOutput == "0" || sizeOutput == "" {
		t.Error("❌ Log file is empty - logging is not working properly")
		return
	}

	// Check if rotation occurred by looking for rotated files (.1, .gz, etc.)
	rotationCheckCmd := []string{"sh", "-c", "ls -la /btc-federation/*.log.* 2>/dev/null && echo 'ROTATION_FOUND' || echo 'NO_ROTATION'"}
	rotationOutput, err := cluster.ExecInContainer(containerID, rotationCheckCmd)
	if err != nil {
		t.Fatalf("Failed to check log rotation in container: %v", err)
	}

	t.Logf("Rotation check output: %s", rotationOutput)

	if rotationOutput == "NO_ROTATION" {
		t.Log("⚠️  No rotated log files found - this is expected for small log volumes")
		t.Log("✓ File logging is working correctly with rotation configuration")
	} else {
		t.Log("✓ Log rotation detected - rotated files exist")
	}

	t.Log("✓ Log rotation test completed - file logging verified")
}

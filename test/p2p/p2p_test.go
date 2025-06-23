package p2p

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"btc-federation-test-suite/pkg/testsuite"
)

const (
	// Test timeouts and configuration
	TestTimeout        = 60 * time.Second
	ConnectionTimeout  = 30 * time.Second
	NodeStartupTimeout = 15 * time.Second
	RetryInterval      = 2 * time.Second

	// Node configuration
	NodeAPort = 9000
	NodeBPort = 9001
	NodeAIP   = "192.168.1.100"
	NodeBIP   = "192.168.1.101"

	// Container names
	NodeAContainer = "btc-federation-node-a"
	NodeBContainer = "btc-federation-node-b"

	// Expected connection patterns in logs
	ConnectionPattern1 = "Connection established with peer"
	ConnectionPattern2 = "Successfully established connection"
	ConnectionPattern3 = "Successfully connected to peer"

	// Cryptographic keys generated using Ed25519 (btc-federation format)
	// Node A key pair - Node A uses private key, Node B uses public key in peers.yaml
	NodeAPrivateKey = "Q2c9Bsj7rjUrORIJJJ4KYxtwoCFeMyqZzM43SumBNjUWAO9P3kgA9VF5Ctq3SB3qqyC1NCUPrJc3Q3w+MqNMaQ=="
	NodeAPublicKey  = "FgDvT95IAPVReQrat0gd6qsgtTQlD6yXN0N8PjKjTGk="

	// Node B key pair - Node B uses private key, Node A uses public key in peers.yaml
	NodeBPrivateKey = "2Qyti0ZkhNAoZXe4NOC7MX7j/+vPEXpMAzx2QMjad95fY8bpC0CQo+Q88KgALPIdHQ/nXmEQJ7K7UL9WnCCePg=="
	NodeBPublicKey  = "X2PG6QtAkKPkPPCoACzyHR0P515hECeyu1C/Vpwgnj4="

	NodeAStaticIP = "172.30.0.10"
	NodeBStaticIP = "172.30.0.11"
)

// TestP2PConnection tests end-to-end P2P connectivity between two btc-federation nodes
// This test integrates all enhancements from tasks 03-1, 03-2, 03-3, and 03-4
//
// Key Distribution:
// - Node A private key (NodeAPrivateKey) → Node A's conf.yaml
// - Node A public key (NodeAPublicKey) → Node B's peers.yaml
// - Node B private key (NodeBPrivateKey) → Node B's conf.yaml
// - Node B public key (NodeBPublicKey) → Node A's peers.yaml
//
// This allows each node to identify itself with its private key and connect to
// the other node using the other node's public key for authentication.
func TestP2PConnectionSingle(t *testing.T) {
	ctx := context.Background()

	// Create cluster
	clusterConfig := &testsuite.ClusterConfig{
		NetworkName: "btc-federation-test-network",
		DockerImage: "btc-federation-test:latest",
	}
	cluster, err := testsuite.NewCluster(clusterConfig)
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster.Cleanup()

	// Configure Node A
	nodeAConfig := &testsuite.NodeConfig{
		ContainerName: "btc-federation-node-a",
		DockerImage:   "btc-federation-test:ubuntu",
		IPAddress:     NodeAStaticIP,
		Port:          9000,
		PrivateKey:    NodeAPrivateKey,
		NetworkName:   "btc-federation-test-network",
		FileName:      "node-a.log",
		FileMaxSize:   "5MB",
		Peers: []testsuite.PeerConfig{
			{
				PublicKey: NodeBPublicKey,
				Addresses: []string{
					fmt.Sprintf("/ip4/%s/tcp/9001", NodeBStaticIP),
				},
			},
		},
	}

	nodeA, err := testsuite.NewNode(nodeAConfig)
	if err != nil {
		t.Fatalf("Failed to create Node A: %v", err)
	}

	// Configure Node B
	nodeBConfig := &testsuite.NodeConfig{
		ContainerName: "btc-federation-node-b",
		DockerImage:   "btc-federation-test:ubuntu",
		IPAddress:     NodeBStaticIP,
		Port:          9001,
		PrivateKey:    NodeBPrivateKey,
		NetworkName:   "btc-federation-test-network",
		FileName:      "node-b.log",
		FileMaxSize:   "5MB",
		Peers: []testsuite.PeerConfig{
			{
				PublicKey: NodeAPublicKey,
				Addresses: []string{
					fmt.Sprintf("/ip4/%s/tcp/9000", NodeAStaticIP),
				},
			},
		},
	}

	nodeB, err := testsuite.NewNode(nodeBConfig)
	if err != nil {
		t.Fatalf("Failed to create Node B: %v", err)
	}

	// Start both nodes
	t.Log("Starting Node A and Node B...")
	nodes := []*testsuite.Node{nodeA, nodeB}

	var wg sync.WaitGroup
	wg.Add(len(nodes))

	for _, node := range nodes {
		go cluster.RunNode(ctx, t, &wg, node)
	}

	wg.Wait()
	t.Log("Both nodes started successfully")

	// Wait for nodes to fully initialize
	t.Log("Waiting for nodes to initialize...")
	time.Sleep(15 * time.Second)

	// ========================================
	// METHOD 1: 🔍 System Process Analysis
	// ========================================
	t.Log("=== METHOD 1: 🔍 System Process Analysis (lsof) ===")

	// Check Node A process connections
	processConnsA, err := cluster.CheckProcessConnections(nodeA.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Warning: Failed to get Node A process connections: %v", err)
	} else {
		t.Logf("Node A process connections (%d):", len(processConnsA))
		for i, conn := range processConnsA {
			t.Logf("  Process Conn %d: %s (PID:%s) %s -> %s (%s)", i+1, conn.Command, conn.PID, conn.LocalAddr, conn.RemoteAddr, conn.State)
		}
	}

	// Check Node B process connections
	processConnsB, err := cluster.CheckProcessConnections(nodeB.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Warning: Failed to get Node B process connections: %v", err)
	} else {
		t.Logf("Node B process connections (%d):", len(processConnsB))
		for i, conn := range processConnsB {
			t.Logf("  Process Conn %d: %s (PID:%s) %s -> %s (%s)", i+1, conn.Command, conn.PID, conn.LocalAddr, conn.RemoteAddr, conn.State)
		}
	}

	// ========================================
	// METHOD 2: 🌐 Network Namespace Analysis
	// ========================================
	t.Log("=== METHOD 2: 🌐 Network Namespace Analysis (ss/netstat) ===")

	// Check Node A network namespace
	nsConnsA, err := cluster.CheckNetworkNamespaceConnections(nodeA.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node A network connections: %v", err)
	} else {
		t.Logf("Node A network namespace connections (%d):", len(nsConnsA))
		for i, conn := range nsConnsA {
			t.Logf("  NS Conn %d: %s %s -> %s (Recv:%s Send:%s) %s", i+1, conn.State, conn.LocalAddr, conn.PeerAddr, conn.RecvQ, conn.SendQ, conn.Process)
		}
	}

	// Check Node B network namespace
	nsConnsB, err := cluster.CheckNetworkNamespaceConnections(nodeB.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node B network connections: %v", err)
	} else {
		t.Logf("Node B network namespace connections (%d):", len(nsConnsB))
		for i, conn := range nsConnsB {
			t.Logf("  NS Conn %d: %s %s -> %s (Recv:%s Send:%s) %s", i+1, conn.State, conn.LocalAddr, conn.PeerAddr, conn.RecvQ, conn.SendQ, conn.Process)
		}
	}

	// Check LibP2P specific connections via netstat
	libp2pA, err := cluster.CheckLibP2PConnections(nodeA.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node A libp2p connections: %v", err)
	} else {
		t.Logf("Node A libp2p connections (%d):", len(libp2pA))
		for i, conn := range libp2pA {
			t.Logf("  LibP2P %d: %s %s -> %s (%s)", i+1, conn.Protocol, conn.LocalAddr, conn.RemoteAddr, conn.State)
		}
	}

	libp2pB, err := cluster.CheckLibP2PConnections(nodeB.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node B libp2p connections: %v", err)
	} else {
		t.Logf("Node B libp2p connections (%d):", len(libp2pB))
		for i, conn := range libp2pB {
			t.Logf("  LibP2P %d: %s %s -> %s (%s)", i+1, conn.Protocol, conn.LocalAddr, conn.RemoteAddr, conn.State)
		}
	}

	// ========================================
	// METHOD 3: 📋 Log and Pattern Analysis
	// ========================================
	t.Log("=== METHOD 3: 📋 Log and Pattern Analysis ===")

	// Comprehensive LibP2P Analysis with log patterns
	analysisA, err := cluster.AnalyzeLibP2PBehavior(nodeA.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to analyze Node A: %v", err)
	} else {
		t.Logf("Node A LibP2P Analysis:")
		t.Logf("  TCP Connections: %d", len(analysisA.TCPConnections))
		t.Logf("  LibP2P Connections: %d", len(analysisA.LibP2PConnections))
		t.Logf("  Process Connections: %d", len(analysisA.ProcessConnections))
		t.Logf("  Network Connections: %d", len(analysisA.NetworkConnections))
		t.Logf("  Log Matches: %v", analysisA.LogMatches)
		if len(analysisA.Errors) > 0 {
			t.Logf("  Errors: %v", analysisA.Errors)
		}
	}

	analysisB, err := cluster.AnalyzeLibP2PBehavior(nodeB.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to analyze Node B: %v", err)
	} else {
		t.Logf("Node B LibP2P Analysis:")
		t.Logf("  TCP Connections: %d", len(analysisB.TCPConnections))
		t.Logf("  LibP2P Connections: %d", len(analysisB.LibP2PConnections))
		t.Logf("  Process Connections: %d", len(analysisB.ProcessConnections))
		t.Logf("  Network Connections: %d", len(analysisB.NetworkConnections))
		t.Logf("  Log Matches: %v", analysisB.LogMatches)
		if len(analysisB.Errors) > 0 {
			t.Logf("  Errors: %v", analysisB.Errors)
		}
	}

	// Check for specific libp2p protocol patterns
	protocolAnalysisA, err := cluster.CheckLibP2PProtocolHandshake(nodeA.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to analyze Node A protocol: %v", err)
	} else {
		t.Logf("Node A Protocol Analysis:")
		t.Logf("  Has Network Traffic: %t", protocolAnalysisA.HasTraffic)
		t.Logf("  MultiAddr Matches: %v", protocolAnalysisA.MultiAddrMatches)
		if len(protocolAnalysisA.Errors) > 0 {
			t.Logf("  Protocol Errors: %v", protocolAnalysisA.Errors)
		}
	}

	protocolAnalysisB, err := cluster.CheckLibP2PProtocolHandshake(nodeB.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to analyze Node B protocol: %v", err)
	} else {
		t.Logf("Node B Protocol Analysis:")
		t.Logf("  Has Network Traffic: %t", protocolAnalysisB.HasTraffic)
		t.Logf("  MultiAddr Matches: %v", protocolAnalysisB.MultiAddrMatches)
		if len(protocolAnalysisB.Errors) > 0 {
			t.Logf("  Protocol Errors: %v", protocolAnalysisB.Errors)
		}
	}

	// ========================================
	// METHOD 4: 🐳 Docker Network Analysis
	// ========================================
	t.Log("=== METHOD 4: 🐳 Docker Network Analysis ===")

	// Docker network connectivity analysis
	dockerNetworkAnalysis, err := cluster.CheckDockerNetworkConnectivity(nodeA.ContainerID, nodeB.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to analyze Docker network: %v", err)
	} else {
		t.Logf("Docker Network Analysis:")
		t.Logf("  Container A: %s (%s) on network %s", dockerNetworkAnalysis.ContainerAInfo.ContainerName, dockerNetworkAnalysis.ContainerAInfo.IPAddress, dockerNetworkAnalysis.ContainerAInfo.NetworkName)
		t.Logf("  Container B: %s (%s) on network %s", dockerNetworkAnalysis.ContainerBInfo.ContainerName, dockerNetworkAnalysis.ContainerBInfo.IPAddress, dockerNetworkAnalysis.ContainerBInfo.NetworkName)
		t.Logf("  Same Network: %t", dockerNetworkAnalysis.SameNetwork)
		t.Logf("  Ping A->B: %t", dockerNetworkAnalysis.PingAB)
		t.Logf("  Ping B->A: %t", dockerNetworkAnalysis.PingBA)
		if len(dockerNetworkAnalysis.Errors) > 0 {
			t.Logf("  Network Errors: %v", dockerNetworkAnalysis.Errors)
		}
	}

	// ========================================
	// ADDITIONAL: 🔌 Reachability Testing
	// ========================================
	t.Log("=== ADDITIONAL: 🔌 Reachability Testing (netcat) ===")

	// Check if Node A can reach Node B
	reachableAB, err := cluster.CheckPeerReachability(nodeA.ContainerID, NodeBStaticIP, 9001)
	if err != nil {
		t.Logf("Warning: Failed to check reachability A->B: %v", err)
	} else {
		t.Logf("Node A can reach Node B: %t", reachableAB)
	}

	// Check if Node B can reach Node A
	reachableBA, err := cluster.CheckPeerReachability(nodeB.ContainerID, NodeAStaticIP, 9000)
	if err != nil {
		t.Logf("Warning: Failed to check reachability B->A: %v", err)
	} else {
		t.Logf("Node B can reach Node A: %t", reachableBA)
	}

	// ========================================
	// 🎯 FINAL RESULTS ANALYSIS
	// ========================================
	t.Log("=== 🎯 FINAL RESULTS ANALYSIS ===")

	var successfulMethods []string
	var indicators []string
	var detailedResults []string

	// 1. Process analysis (METHOD 1)
	if len(processConnsA) > 0 || len(processConnsB) > 0 {
		establishedConns := 0
		for _, conn := range processConnsA {
			if conn.State == "ESTABLISHED" {
				establishedConns++
			}
		}
		for _, conn := range processConnsB {
			if conn.State == "ESTABLISHED" {
				establishedConns++
			}
		}
		if establishedConns > 0 {
			successfulMethods = append(successfulMethods, "🔍 System Process Analysis")
			indicators = append(indicators, fmt.Sprintf("Found %d established process connections", establishedConns))
			detailedResults = append(detailedResults, fmt.Sprintf("METHOD 1 ✅: %d ESTABLISHED connections via lsof", establishedConns))
		}
	}

	// 2. Network namespace analysis (METHOD 2)
	establishedNSConns := 0
	for _, conn := range nsConnsA {
		if conn.State == "ESTAB" {
			establishedNSConns++
		}
	}
	for _, conn := range nsConnsB {
		if conn.State == "ESTAB" {
			establishedNSConns++
		}
	}
	if establishedNSConns > 0 {
		successfulMethods = append(successfulMethods, "🌐 Network Namespace Analysis")
		indicators = append(indicators, fmt.Sprintf("Found %d established network connections", establishedNSConns))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 2 ✅: %d ESTAB connections via ss", establishedNSConns))
	}

	// Check libp2p connections
	if len(libp2pA) > 0 || len(libp2pB) > 0 {
		successfulMethods = append(successfulMethods, "🌐 LibP2P Connections")
		indicators = append(indicators, fmt.Sprintf("Node A: %d libp2p, Node B: %d libp2p", len(libp2pA), len(libp2pB)))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 2 ✅: Found libp2p connections via netstat"))
	}

	// 3. Log and pattern analysis (METHOD 3)
	logMatches := 0
	if analysisA != nil {
		for pattern, found := range analysisA.LogMatches {
			if found {
				logMatches++
				t.Logf("Node A log match: %s", pattern)
			}
		}
	}
	if analysisB != nil {
		for pattern, found := range analysisB.LogMatches {
			if found {
				logMatches++
				t.Logf("Node B log match: %s", pattern)
			}
		}
	}

	protocolMatches := 0
	if protocolAnalysisA != nil {
		for _, found := range protocolAnalysisA.MultiAddrMatches {
			if found {
				protocolMatches++
			}
		}
	}
	if protocolAnalysisB != nil {
		for _, found := range protocolAnalysisB.MultiAddrMatches {
			if found {
				protocolMatches++
			}
		}
	}

	if logMatches > 0 || protocolMatches > 0 {
		successfulMethods = append(successfulMethods, "📋 Log and Pattern Analysis")
		indicators = append(indicators, fmt.Sprintf("Found %d log matches, %d protocol patterns", logMatches, protocolMatches))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 3 ✅: %d log + %d protocol matches", logMatches, protocolMatches))
	}

	// 4. Docker network analysis (METHOD 4)
	if dockerNetworkAnalysis != nil {
		dockerSuccess := dockerNetworkAnalysis.SameNetwork && (dockerNetworkAnalysis.PingAB || dockerNetworkAnalysis.PingBA)
		if dockerSuccess {
			successfulMethods = append(successfulMethods, "🐳 Docker Network Analysis")
			indicators = append(indicators, fmt.Sprintf("Containers on same network, ping: A->B=%t, B->A=%t", dockerNetworkAnalysis.PingAB, dockerNetworkAnalysis.PingBA))
			detailedResults = append(detailedResults, "METHOD 4 ✅: Docker network connectivity confirmed")
		}
	}

	// 5. Reachability testing
	if reachableAB && reachableBA {
		successfulMethods = append(successfulMethods, "🔌 Reachability Testing")
		indicators = append(indicators, "Both nodes can reach each other")
		detailedResults = append(detailedResults, "ADDITIONAL ✅: netcat reachability successful")
	}

	// Output results
	t.Logf("🎯 VERIFICATION RESULTS:")
	t.Logf("Successful verification methods (%d): %v", len(successfulMethods), successfulMethods)
	t.Logf("Found connection indicators:")
	for _, indicator := range indicators {
		t.Logf("  ✅ %s", indicator)
	}

	t.Logf("Detailed results:")
	for _, result := range detailedResults {
		t.Logf("  %s", result)
	}

	// Final test decision - Updated requirements: need at least 3 methods for full success
	if len(successfulMethods) >= 3 {
		t.Log("🎉 P2P Connection Test PASSED: Nodes successfully connected!")
		t.Logf("✅ Confirmed by %d methods: %v", len(successfulMethods), successfulMethods)
		t.Log("🔗 P2P network is functioning correctly")
	} else if len(successfulMethods) == 2 {
		t.Error("⚠️  P2P Connection Test FAILED: Insufficient verification methods")
		t.Errorf("❌ Only %d methods confirmed connection, need at least 3 for reliable verification", len(successfulMethods))
		t.Logf("🔍 Working methods: %v", successfulMethods)
		t.Error("🚫 Stricter validation requires majority of methods to pass")
	} else if len(successfulMethods) == 1 {
		t.Error("⚠️  P2P Connection Test FAILED: Single method verification insufficient")
		t.Errorf("❌ Only 1 method confirmed connection: %v", successfulMethods)
		t.Error("🔍 Need at least 3 methods for reliable P2P connection verification")
	} else {
		t.Error("❌ P2P Connection Test FAILED: No connection indicators found")
		t.Error("🚫 None of the verification methods showed successful P2P connections")

		// Detailed diagnostics
		t.Log("=== 🔍 DIAGNOSTIC INFORMATION ===")
		if analysisA != nil && len(analysisA.Errors) > 0 {
			t.Logf("Node A errors: %v", analysisA.Errors)
		}
		if analysisB != nil && len(analysisB.Errors) > 0 {
			t.Logf("Node B errors: %v", analysisB.Errors)
		}
		if dockerNetworkAnalysis != nil && len(dockerNetworkAnalysis.Errors) > 0 {
			t.Logf("Docker network errors: %v", dockerNetworkAnalysis.Errors)
		}
	}
}

// TestP2PConnectionReliability tests P2P connection reliability over multiple iterations
func TestP2PConnectionReliability(t *testing.T) {
	const iterations = 3
	const successThreshold = 0.95 // 95% success rate

	successCount := 0

	for i := 0; i < iterations; i++ {
		t.Logf("=== Reliability Test Iteration %d/%d ===", i+1, iterations)

		success := t.Run(fmt.Sprintf("Iteration_%d", i+1), func(t *testing.T) {
			TestP2PConnectionSingle(t)
		})

		if success {
			successCount++
		}

		// Small delay between iterations
		if i < iterations-1 {
			time.Sleep(5 * time.Second)
		}
	}

	successRate := float64(successCount) / float64(iterations)
	t.Logf("Reliability test results: %d/%d successful (%.2f%%)", successCount, iterations, successRate*100)

	if successRate < successThreshold {
		t.Errorf("P2P connection reliability below threshold: %.2f%% < %.2f%%", successRate*100, successThreshold*100)
	}
}

// TestP2PConnectionTiming validates that the P2P connection test completes within time limits
func TestP2PConnectionTiming(t *testing.T) {
	const maxTestDuration = 60 * time.Second

	start := time.Now()
	TestP2PConnectionSingle(t)
	duration := time.Since(start)

	t.Logf("P2P connection test completed in: %v", duration)

	if duration > maxTestDuration {
		t.Errorf("P2P connection test took too long: %v > %v", duration, maxTestDuration)
	}
}

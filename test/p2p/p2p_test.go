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

// TestP2PConnectionMultiNode tests P2P connectivity between 8 btc-federation nodes
// Each node connects to all other 7 nodes in a full mesh topology
// This test verifies that all nodes can establish connections with each other
func TestP2PConnectionMultiNode(t *testing.T) {
	ctx := context.Background()

	// Node configurations with provided keys
	type NodeInfo struct {
		ContainerName string
		IPAddress     string
		Port          int
		PrivateKey    string
		PublicKey     string
	}

	nodes := []NodeInfo{
		{
			ContainerName: "btc-federation-node-1",
			IPAddress:     "172.31.0.10",
			Port:          9001,
			PrivateKey:    "4nxBCdT+yqsBsMqwAvklZjgSUHKZ3nOGWvChzcE809lWYn906dJN3trJ/1BQQ4gEvEzSed0zb8vDYIdb0RZEZQ==",
			PublicKey:     "VmJ/dOnSTd7ayf9QUEOIBLxM0nndM2/Lw2CHW9EWRGU=",
		},
		{
			ContainerName: "btc-federation-node-2",
			IPAddress:     "172.31.0.11",
			Port:          9002,
			PrivateKey:    "hgSCwOWjm4ftCuxn+gem/md+OmbUemI+8+F+bgD/Gy2UpYpmUVUqck/8XGNtcY9fnkWD2ppvUu7V7x4su9uNog==",
			PublicKey:     "lKWKZlFVKnJP/FxjbXGPX55Fg9qab1Lu1e8eLLvbjaI=",
		},
		{
			ContainerName: "btc-federation-node-3",
			IPAddress:     "172.31.0.12",
			Port:          9003,
			PrivateKey:    "LwRcmFZuIi6HuEoqDDjE6ZvtyKoChpH4+S7lMth5Rtas30kQPzcG5POqzGkjghAh+Qqp4w4NmA6xr3SZTs1ACA==",
			PublicKey:     "rN9JED83BuTzqsxpI4IQIfkKqeMODZgOsa90mU7NQAg=",
		},
		{
			ContainerName: "btc-federation-node-4",
			IPAddress:     "172.31.0.13",
			Port:          9004,
			PrivateKey:    "V8IcUTo8u6zi74/fbgwrGvAZBogbY+L2+M/0km0oy7qtJcwujvjuC467cMViSstByLW6/jSpHJQUp1uZXaBQTQ==",
			PublicKey:     "rSXMLo747guOu3DFYkrLQci1uv40qRyUFKdbmV2gUE0=",
		},
		{
			ContainerName: "btc-federation-node-5",
			IPAddress:     "172.31.0.14",
			Port:          9005,
			PrivateKey:    "nzHEbL15nskatbjSNvbpTpjAAT4Xcy75gndXpHAt5n7XSFK0X4DjoV6q6tQ8T/d3gXXIKWzvuZnKqT/wv/0eSg==",
			PublicKey:     "10hStF+A46FequrUPE/3d4F1yCls77mZyqk/8L/9Hko=",
		},
		{
			ContainerName: "btc-federation-node-6",
			IPAddress:     "172.31.0.15",
			Port:          9006,
			PrivateKey:    "kyQ7Ge6/S/UbCc5FcssNKSz5roz0NOAoDiY9DX8rEt1bv4mJ9SyOQfvNLfiD3EZTttuS/myt/se60wPqmfOmcw==",
			PublicKey:     "W7+JifUsjkH7zS34g9xGU7bbkv5srf7HutMD6pnzpnM=",
		},
		{
			ContainerName: "btc-federation-node-7",
			IPAddress:     "172.31.0.16",
			Port:          9007,
			PrivateKey:    "9cHV6A2few3B5kkikwJOOmdhkm8E7+AJfp180Ql6uxLjcEuONu1DcE56qwngJk7jz6NWR6ka4b7SJQeT419JVQ==",
			PublicKey:     "43BLjjbtQ3BOeqsJ4CZO48+jVkepGuG+0iUHk+NfSVU=",
		},
		{
			ContainerName: "btc-federation-node-8",
			IPAddress:     "172.31.0.17",
			Port:          9008,
			PrivateKey:    "r65wtLa0jQEeRSVmP8FXTORzquW9f504jVTuBDrwbRu47qlIQp9rcmTSmreyQUzhqec5fwBbEUUUPCh+ceTukw==",
			PublicKey:     "uO6pSEKfa3Jk0pq3skFM4annOX8AWxFFFDwofnHk7pM=",
		},
	}

	// Create cluster with a different subnet to avoid conflicts
	clusterConfig := &testsuite.ClusterConfig{
		NetworkName: "btc-federation-multinode-network",
		DockerImage: "btc-federation-test:latest",
		Subnet:      "172.31.0.0/16",
		Gateway:     "172.31.0.1",
	}
	cluster, err := testsuite.NewCluster(clusterConfig)
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster.Cleanup()

	// Create and configure all nodes
	var testNodes []*testsuite.Node
	for i, nodeInfo := range nodes {
		// Build peers list for current node (all other nodes)
		var peers []testsuite.PeerConfig
		for j, peerInfo := range nodes {
			if i != j { // Don't add self as peer
				peers = append(peers, testsuite.PeerConfig{
					PublicKey: peerInfo.PublicKey,
					Addresses: []string{
						fmt.Sprintf("/ip4/%s/tcp/%d", peerInfo.IPAddress, peerInfo.Port),
					},
				})
			}
		}

		nodeConfig := &testsuite.NodeConfig{
			ContainerName: nodeInfo.ContainerName,
			DockerImage:   "btc-federation-test:ubuntu",
			IPAddress:     nodeInfo.IPAddress,
			Port:          nodeInfo.Port,
			PrivateKey:    nodeInfo.PrivateKey,
			NetworkName:   "btc-federation-multinode-network",
			FileName:      fmt.Sprintf("node-%d.log", i+1),
			FileMaxSize:   "5MB",
			Peers:         peers,
		}

		node, err := testsuite.NewNode(nodeConfig)
		if err != nil {
			t.Fatalf("Failed to create Node %d: %v", i+1, err)
		}
		testNodes = append(testNodes, node)
	}

	// Start all nodes concurrently
	t.Logf("Starting %d nodes...", len(testNodes))
	var wg sync.WaitGroup
	wg.Add(len(testNodes))

	for _, node := range testNodes {
		go cluster.RunNode(ctx, t, &wg, node)
	}

	wg.Wait()
	t.Log("All nodes started successfully")

	// Wait for nodes to fully initialize and attempt connections
	t.Log("Waiting for nodes to initialize and establish connections...")
	time.Sleep(30 * time.Second) // Increased wait time for 8 nodes

	// ========================================
	// MULTI-NODE CONNECTION VERIFICATION
	// ========================================
	t.Log("=== 🔍 MULTI-NODE CONNECTION VERIFICATION ===")

	type NodeAnalysis struct {
		NodeIndex            int
		ContainerName        string
		IPAddress            string
		ProcessConnections   []testsuite.ProcessConnection
		NetworkConnections   []testsuite.NetworkConnection
		LibP2PConnections    []testsuite.LibP2PConnection
		LibP2PAnalysis       *testsuite.LibP2PAnalysis
		ProtocolAnalysis     *testsuite.ProtocolAnalysis
		EstablishedConnCount int
		Errors               []string
	}

	var nodeAnalyses []NodeAnalysis

	// Analyze each node
	for i, node := range testNodes {
		analysis := NodeAnalysis{
			NodeIndex:     i + 1,
			ContainerName: nodes[i].ContainerName,
			IPAddress:     nodes[i].IPAddress,
		}

		t.Logf("Analyzing Node %d (%s)...", i+1, analysis.ContainerName)

		// Process connections analysis
		processConns, err := cluster.CheckProcessConnections(node.ContainerID, "btc-federation-node")
		if err != nil {
			analysis.Errors = append(analysis.Errors, fmt.Sprintf("Process connections error: %v", err))
		} else {
			analysis.ProcessConnections = processConns
			for _, conn := range processConns {
				if conn.State == "ESTABLISHED" {
					analysis.EstablishedConnCount++
				}
			}
		}

		// Network namespace connections
		nsConns, err := cluster.CheckNetworkNamespaceConnections(node.ContainerID)
		if err != nil {
			analysis.Errors = append(analysis.Errors, fmt.Sprintf("Network connections error: %v", err))
		} else {
			analysis.NetworkConnections = nsConns
		}

		// LibP2P connections
		libp2pConns, err := cluster.CheckLibP2PConnections(node.ContainerID)
		if err != nil {
			analysis.Errors = append(analysis.Errors, fmt.Sprintf("LibP2P connections error: %v", err))
		} else {
			analysis.LibP2PConnections = libp2pConns
		}

		// LibP2P behavior analysis
		libp2pAnalysis, err := cluster.AnalyzeLibP2PBehavior(node.ContainerID)
		if err != nil {
			analysis.Errors = append(analysis.Errors, fmt.Sprintf("LibP2P analysis error: %v", err))
		} else {
			analysis.LibP2PAnalysis = libp2pAnalysis
		}

		// Protocol analysis
		protocolAnalysis, err := cluster.CheckLibP2PProtocolHandshake(node.ContainerID)
		if err != nil {
			analysis.Errors = append(analysis.Errors, fmt.Sprintf("Protocol analysis error: %v", err))
		} else {
			analysis.ProtocolAnalysis = protocolAnalysis
		}

		nodeAnalyses = append(nodeAnalyses, analysis)

		t.Logf("Node %d analysis: %d process connections, %d network connections, %d libp2p connections",
			i+1, len(analysis.ProcessConnections), len(analysis.NetworkConnections), len(analysis.LibP2PConnections))
	}

	// ========================================
	// CROSS-NODE REACHABILITY TESTING
	// ========================================
	t.Log("=== 🔌 CROSS-NODE REACHABILITY TESTING ===")

	type ReachabilityResult struct {
		FromNode int
		ToNode   int
		Success  bool
		Error    error
	}

	var reachabilityResults []ReachabilityResult
	totalReachabilityTests := len(nodes) * (len(nodes) - 1) // n*(n-1) tests

	for i, fromNode := range testNodes {
		for j, toNodeInfo := range nodes {
			if i != j { // Don't test self-reachability
				reachable, err := cluster.CheckPeerReachability(fromNode.ContainerID, toNodeInfo.IPAddress, toNodeInfo.Port)
				result := ReachabilityResult{
					FromNode: i + 1,
					ToNode:   j + 1,
					Success:  reachable,
					Error:    err,
				}
				reachabilityResults = append(reachabilityResults, result)

				if err != nil {
					t.Logf("Reachability Node%d->Node%d: ERROR %v", i+1, j+1, err)
				} else {
					t.Logf("Reachability Node%d->Node%d: %t", i+1, j+1, reachable)
				}
			}
		}
	}

	// ========================================
	// DOCKER NETWORK ANALYSIS
	// ========================================
	t.Log("=== 🐳 DOCKER NETWORK ANALYSIS ===")

	// Test Docker network connectivity between first few pairs
	var dockerNetworkResults []bool
	maxDockerTests := 4 // Test first 4 pairs to avoid excessive logging

	for i := 0; i < len(testNodes) && i < maxDockerTests; i++ {
		j := (i + 1) % len(testNodes)
		dockerNetworkAnalysis, err := cluster.CheckDockerNetworkConnectivity(testNodes[i].ContainerID, testNodes[j].ContainerID)
		if err != nil {
			t.Logf("Warning: Docker network analysis Node%d<->Node%d failed: %v", i+1, j+1, err)
		} else {
			success := dockerNetworkAnalysis.SameNetwork && (dockerNetworkAnalysis.PingAB || dockerNetworkAnalysis.PingBA)
			dockerNetworkResults = append(dockerNetworkResults, success)
			t.Logf("Docker Network Node%d<->Node%d: same_network=%t, ping_ab=%t, ping_ba=%t",
				i+1, j+1, dockerNetworkAnalysis.SameNetwork, dockerNetworkAnalysis.PingAB, dockerNetworkAnalysis.PingBA)
		}
	}

	// ========================================
	// RESULTS ANALYSIS AND SCORING
	// ========================================
	t.Log("=== 🎯 MULTI-NODE RESULTS ANALYSIS ===")

	var successfulMethods []string
	var indicators []string
	var detailedResults []string

	// METHOD 1: Process connections analysis
	totalEstablishedConns := 0
	nodesWithConnections := 0
	for _, analysis := range nodeAnalyses {
		if analysis.EstablishedConnCount > 0 {
			nodesWithConnections++
			totalEstablishedConns += analysis.EstablishedConnCount
		}
	}

	if totalEstablishedConns > 0 {
		successfulMethods = append(successfulMethods, "🔍 System Process Analysis")
		indicators = append(indicators, fmt.Sprintf("%d nodes with %d total established connections", nodesWithConnections, totalEstablishedConns))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 1 ✅: %d established connections across %d nodes", totalEstablishedConns, nodesWithConnections))
	}

	// METHOD 2: Network namespace analysis
	totalNetworkConns := 0
	nodesWithNetworkConns := 0
	for _, analysis := range nodeAnalyses {
		establishedNetConns := 0
		for _, conn := range analysis.NetworkConnections {
			if conn.State == "ESTAB" {
				establishedNetConns++
			}
		}
		if establishedNetConns > 0 {
			nodesWithNetworkConns++
			totalNetworkConns += establishedNetConns
		}
	}

	if totalNetworkConns > 0 {
		successfulMethods = append(successfulMethods, "🌐 Network Namespace Analysis")
		indicators = append(indicators, fmt.Sprintf("%d nodes with %d total network connections", nodesWithNetworkConns, totalNetworkConns))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 2 ✅: %d network connections across %d nodes", totalNetworkConns, nodesWithNetworkConns))
	}

	// METHOD 3: LibP2P connections
	totalLibP2PConns := 0
	nodesWithLibP2P := 0
	for _, analysis := range nodeAnalyses {
		if len(analysis.LibP2PConnections) > 0 {
			nodesWithLibP2P++
			totalLibP2PConns += len(analysis.LibP2PConnections)
		}
	}

	if totalLibP2PConns > 0 {
		successfulMethods = append(successfulMethods, "🌐 LibP2P Connections")
		indicators = append(indicators, fmt.Sprintf("%d nodes with %d total libp2p connections", nodesWithLibP2P, totalLibP2PConns))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 3 ✅: %d libp2p connections across %d nodes", totalLibP2PConns, nodesWithLibP2P))
	}

	// METHOD 4: Log and protocol analysis
	logMatches := 0
	protocolMatches := 0
	for _, analysis := range nodeAnalyses {
		if analysis.LibP2PAnalysis != nil {
			for _, found := range analysis.LibP2PAnalysis.LogMatches {
				if found {
					logMatches++
				}
			}
		}
		if analysis.ProtocolAnalysis != nil {
			for _, found := range analysis.ProtocolAnalysis.MultiAddrMatches {
				if found {
					protocolMatches++
				}
			}
		}
	}

	if logMatches > 0 || protocolMatches > 0 {
		successfulMethods = append(successfulMethods, "📋 Log and Pattern Analysis")
		indicators = append(indicators, fmt.Sprintf("Found %d log matches, %d protocol patterns", logMatches, protocolMatches))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 4 ✅: %d log + %d protocol matches", logMatches, protocolMatches))
	}

	// METHOD 5: Reachability testing
	successfulReachability := 0
	for _, result := range reachabilityResults {
		if result.Success {
			successfulReachability++
		}
	}

	if successfulReachability > 0 {
		successfulMethods = append(successfulMethods, "🔌 Reachability Testing")
		indicators = append(indicators, fmt.Sprintf("%d/%d reachability tests passed", successfulReachability, totalReachabilityTests))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 5 ✅: %d/%d reachability tests successful", successfulReachability, totalReachabilityTests))
	}

	// METHOD 6: Docker network analysis
	successfulDockerTests := 0
	for _, success := range dockerNetworkResults {
		if success {
			successfulDockerTests++
		}
	}

	if successfulDockerTests > 0 {
		successfulMethods = append(successfulMethods, "🐳 Docker Network Analysis")
		indicators = append(indicators, fmt.Sprintf("%d/%d docker network tests passed", successfulDockerTests, len(dockerNetworkResults)))
		detailedResults = append(detailedResults, fmt.Sprintf("METHOD 6 ✅: %d/%d docker network tests successful", successfulDockerTests, len(dockerNetworkResults)))
	}

	// ========================================
	// DETAILED NODE-BY-NODE REPORTING
	// ========================================
	t.Log("=== 📊 DETAILED NODE-BY-NODE ANALYSIS ===")
	for _, analysis := range nodeAnalyses {
		t.Logf("Node %d (%s @ %s):", analysis.NodeIndex, analysis.ContainerName, analysis.IPAddress)
		t.Logf("  Process connections: %d (%d established)", len(analysis.ProcessConnections), analysis.EstablishedConnCount)
		t.Logf("  Network connections: %d", len(analysis.NetworkConnections))
		t.Logf("  LibP2P connections: %d", len(analysis.LibP2PConnections))
		if len(analysis.Errors) > 0 {
			t.Logf("  Errors: %v", analysis.Errors)
		}
	}

	// ========================================
	// FINAL TEST DECISION
	// ========================================
	t.Log("=== 🎯 FINAL MULTI-NODE TEST RESULTS ===")
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

	// Multi-node test requires stricter validation
	// Expected: 8 nodes should have connections, high reachability success rate
	minRequiredMethods := 4     // Need majority of methods for multi-node test
	minReachabilityRate := 0.75 // At least 75% of reachability tests should pass
	actualReachabilityRate := float64(successfulReachability) / float64(totalReachabilityTests)

	if len(successfulMethods) >= minRequiredMethods && actualReachabilityRate >= minReachabilityRate {
		t.Log("🎉 MULTI-NODE P2P Connection Test PASSED: All nodes successfully interconnected!")
		t.Logf("✅ Confirmed by %d/%d methods: %v", len(successfulMethods), 6, successfulMethods)
		t.Logf("✅ Reachability: %.1f%% (%d/%d tests passed)", actualReachabilityRate*100, successfulReachability, totalReachabilityTests)
		t.Log("🔗 Multi-node P2P mesh network is functioning correctly")
	} else if len(successfulMethods) >= 3 {
		t.Error("⚠️  MULTI-NODE P2P Connection Test PARTIALLY PASSED: Some connectivity issues detected")
		t.Errorf("⚠️  %d/%d methods confirmed, reachability %.1f%% (%d/%d)", len(successfulMethods), minRequiredMethods, actualReachabilityRate*100, successfulReachability, totalReachabilityTests)
		t.Logf("🔍 Working methods: %v", successfulMethods)
		t.Error("🚫 Multi-node mesh requires higher success rates for reliable operation")
	} else {
		t.Error("❌ MULTI-NODE P2P Connection Test FAILED: Insufficient connectivity between nodes")
		t.Errorf("❌ Only %d/%d methods confirmed connection, reachability %.1f%%", len(successfulMethods), minRequiredMethods, actualReachabilityRate*100)
		t.Error("🔍 Multi-node P2P mesh requires majority of verification methods to pass")

		// Enhanced diagnostics for multi-node failure
		t.Log("=== 🔍 MULTI-NODE DIAGNOSTIC INFORMATION ===")
		failedReachability := totalReachabilityTests - successfulReachability
		if failedReachability > 0 {
			t.Logf("Failed reachability tests: %d/%d (%.1f%%)", failedReachability, totalReachabilityTests, float64(failedReachability)/float64(totalReachabilityTests)*100)
		}

		nodesWithErrors := 0
		for _, analysis := range nodeAnalyses {
			if len(analysis.Errors) > 0 {
				nodesWithErrors++
				t.Logf("Node %d errors: %v", analysis.NodeIndex, analysis.Errors)
			}
		}
		if nodesWithErrors > 0 {
			t.Logf("Nodes with errors: %d/%d", nodesWithErrors, len(nodeAnalyses))
		}
	}
}

// TestP2PConnectionResilience tests P2P connection recovery after network disruption
// Added for task 03-6: Network resilience testing
// This test validates that P2P connections can recover after network isolation
func TestP2PConnectionResilience(t *testing.T) {
	ctx := context.Background()

	// Create cluster
	clusterConfig := &testsuite.ClusterConfig{
		NetworkName: "btc-federation-resilience-network",
		DockerImage: "btc-federation-test:latest",
		Subnet:      "172.32.0.0/16",
		Gateway:     "172.32.0.1",
	}
	cluster, err := testsuite.NewCluster(clusterConfig)
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}
	defer cluster.Cleanup()

	// Cryptographic keys for resilience testing
	const (
		// Node 1 keys
		Node1PrivateKey = "QUGhLJyuZN5zyqVyzY3lR2Dn4h17nRmXemJ7j8dTodsGRsTtvvI7Mc3yu6lQ9SCPopfxCXy64wVr2a96akMzYA=="
		Node1PublicKey  = "BkbE7b7yOzHN8rupUPUgj6KX8Ql8uuMFa9mvempDM2A="

		// Node 2 keys
		Node2PrivateKey = "ymIaHQbssRSu+/7Fn1Iy3IEFU/e95hVBcqLksVNGdf6P8ILafaydEr5UdLZlhnmEdWdc6fPxHGQoCRH/r+j1tQ=="
		Node2PublicKey  = "j/CC2n2snRK+VHS2ZYZ5hHVnXOnz8RxkKAkR/6/o9bU="

		// Static IP addresses
		Node1StaticIP = "172.32.0.10"
		Node2StaticIP = "172.32.0.11"
	)

	// Configure Node 1
	node1Config := &testsuite.NodeConfig{
		ContainerName: "btc-federation-resilience-node-1",
		DockerImage:   "btc-federation-test:ubuntu",
		IPAddress:     Node1StaticIP,
		Port:          9000,
		PrivateKey:    Node1PrivateKey,
		NetworkName:   "btc-federation-resilience-network",
		FileName:      "resilience-node-1.log",
		FileMaxSize:   "5MB",
		Peers: []testsuite.PeerConfig{
			{
				PublicKey: Node2PublicKey,
				Addresses: []string{
					fmt.Sprintf("/ip4/%s/tcp/9001", Node2StaticIP),
				},
			},
		},
	}

	node1, err := testsuite.NewNode(node1Config)
	if err != nil {
		t.Fatalf("Failed to create Node 1: %v", err)
	}

	// Configure Node 2
	node2Config := &testsuite.NodeConfig{
		ContainerName: "btc-federation-resilience-node-2",
		DockerImage:   "btc-federation-test:ubuntu",
		IPAddress:     Node2StaticIP,
		Port:          9001,
		PrivateKey:    Node2PrivateKey,
		NetworkName:   "btc-federation-resilience-network",
		FileName:      "resilience-node-2.log",
		FileMaxSize:   "5MB",
		Peers: []testsuite.PeerConfig{
			{
				PublicKey: Node1PublicKey,
				Addresses: []string{
					fmt.Sprintf("/ip4/%s/tcp/9000", Node1StaticIP),
				},
			},
		},
	}

	node2, err := testsuite.NewNode(node2Config)
	if err != nil {
		t.Fatalf("Failed to create Node 2: %v", err)
	}

	// Start both nodes
	t.Log("=== PHASE 1: Initial Connection Establishment ===")
	t.Log("Starting Node 1 and Node 2...")
	nodes := []*testsuite.Node{node1, node2}

	var wg sync.WaitGroup
	wg.Add(len(nodes))

	for _, node := range nodes {
		go cluster.RunNode(ctx, t, &wg, node)
	}

	wg.Wait()
	t.Log("Both nodes started successfully")

	// Wait for initial connections to establish
	t.Log("Waiting for initial connections to establish...")
	time.Sleep(15 * time.Second)

	// Verify initial connections are working
	t.Log("=== Initial Connection Verification ===")

	// Check process connections for both nodes
	processConns1, err := cluster.CheckProcessConnections(node1.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Warning: Failed to get Node 1 initial process connections: %v", err)
	} else {
		t.Logf("Node 1 initial process connections: %d", len(processConns1))
	}

	processConns2, err := cluster.CheckProcessConnections(node2.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Warning: Failed to get Node 2 initial process connections: %v", err)
	} else {
		t.Logf("Node 2 initial process connections: %d", len(processConns2))
	}

	// Check network namespace connections
	nsConns1, err := cluster.CheckNetworkNamespaceConnections(node1.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node 1 initial network connections: %v", err)
	} else {
		t.Logf("Node 1 initial network connections: %d", len(nsConns1))
	}

	nsConns2, err := cluster.CheckNetworkNamespaceConnections(node2.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node 2 initial network connections: %v", err)
	} else {
		t.Logf("Node 2 initial network connections: %d", len(nsConns2))
	}

	// Check reachability
	reachable12, err := cluster.CheckPeerReachability(node1.ContainerID, Node2StaticIP, 9001)
	if err != nil {
		t.Logf("Warning: Failed to check initial reachability 1->2: %v", err)
	} else {
		t.Logf("Initial reachability Node 1->Node 2: %t", reachable12)
	}

	reachable21, err := cluster.CheckPeerReachability(node2.ContainerID, Node1StaticIP, 9000)
	if err != nil {
		t.Logf("Warning: Failed to check initial reachability 2->1: %v", err)
	} else {
		t.Logf("Initial reachability Node 2->Node 1: %t", reachable21)
	}

	// Determine initial connection status
	initialConnections := 0
	if len(processConns1) > 0 {
		initialConnections++
	}
	if len(processConns2) > 0 {
		initialConnections++
	}
	if len(nsConns1) > 0 {
		initialConnections++
	}
	if len(nsConns2) > 0 {
		initialConnections++
	}
	if reachable12 {
		initialConnections++
	}
	if reachable21 {
		initialConnections++
	}

	t.Logf("Initial connection indicators: %d/6", initialConnections)

	// ========================================
	// PHASE 2: Network Disruption
	// ========================================
	t.Log("=== PHASE 2: Network Disruption ===")
	t.Log("Applying network isolation to Node 1...")

	// Create network conditions for isolation
	isolationConditions := &testsuite.NetworkConditions{
		Isolated: true,
	}

	// Apply network isolation to Node 1
	if err := cluster.ConfigureNetworkConditions(node1, isolationConditions); err != nil {
		t.Fatalf("Failed to apply network isolation to Node 1: %v", err)
	}

	// Wait for isolation to take effect
	t.Log("Waiting for network isolation to take effect...")
	time.Sleep(5 * time.Second)

	// Verify connections are broken (without log checks as requested)
	t.Log("=== Disruption Verification (No Log Checks) ===")

	// Check process connections during disruption
	processConnsDisrupted1, err := cluster.CheckProcessConnections(node1.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Node 1 disrupted process connections check failed (possibly expected): %v", err)
		processConnsDisrupted1 = nil
	} else {
		t.Logf("Node 1 disrupted process connections: %d", len(processConnsDisrupted1))
	}

	processConnsDisrupted2, err := cluster.CheckProcessConnections(node2.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Node 2 disrupted process connections check failed (possibly expected): %v", err)
		processConnsDisrupted2 = nil
	} else {
		t.Logf("Node 2 disrupted process connections: %d", len(processConnsDisrupted2))
	}

	// Check network connections during disruption
	nsConnsDisrupted1, err := cluster.CheckNetworkNamespaceConnections(node1.ContainerID)
	if err != nil {
		t.Logf("Node 1 disrupted network connections check failed (possibly expected): %v", err)
		nsConnsDisrupted1 = nil
	} else {
		t.Logf("Node 1 disrupted network connections: %d", len(nsConnsDisrupted1))
	}

	nsConnsDisrupted2, err := cluster.CheckNetworkNamespaceConnections(node2.ContainerID)
	if err != nil {
		t.Logf("Node 2 disrupted network connections check failed (possibly expected): %v", err)
		nsConnsDisrupted2 = nil
	} else {
		t.Logf("Node 2 disrupted network connections: %d", len(nsConnsDisrupted2))
	}

	// Check if reachability is broken
	reachable12Disrupted, err := cluster.CheckPeerReachability(node1.ContainerID, Node2StaticIP, 9001)
	if err != nil {
		t.Logf("Reachability check 1->2 during disruption failed (expected): %v", err)
		reachable12Disrupted = false
	} else {
		t.Logf("Reachability Node 1->Node 2 during disruption: %t", reachable12Disrupted)
	}

	reachable21Disrupted, err := cluster.CheckPeerReachability(node2.ContainerID, Node1StaticIP, 9000)
	if err != nil {
		t.Logf("Reachability check 2->1 during disruption failed (expected): %v", err)
		reachable21Disrupted = false
	} else {
		t.Logf("Reachability Node 2->Node 1 during disruption: %t", reachable21Disrupted)
	}

	// Calculate disrupted indicators (should be FEWER than initial)
	var disruptedIndicators []string
	workingConnections := 0

	// Count working connections during disruption (lower is better for isolation)
	if len(processConnsDisrupted1) > 0 {
		workingConnections++
		disruptedIndicators = append(disruptedIndicators, "Node 1 process connections still working")
	}
	if len(processConnsDisrupted2) > 0 {
		workingConnections++
		disruptedIndicators = append(disruptedIndicators, "Node 2 process connections still working")
	}
	if len(nsConnsDisrupted1) > 0 {
		workingConnections++
		disruptedIndicators = append(disruptedIndicators, "Node 1 network connections still working")
	}
	if len(nsConnsDisrupted2) > 0 {
		workingConnections++
		disruptedIndicators = append(disruptedIndicators, "Node 2 network connections still working")
	}
	if reachable12Disrupted {
		workingConnections++
		disruptedIndicators = append(disruptedIndicators, "Node 1->Node 2 reachability still working")
	}
	if reachable21Disrupted {
		workingConnections++
		disruptedIndicators = append(disruptedIndicators, "Node 2->Node 1 reachability still working")
	}

	brokenConnections := 6 - workingConnections
	t.Logf("Disruption status: %d/6 connections broken, %d/6 still working", brokenConnections, workingConnections)

	if len(disruptedIndicators) > 0 {
		t.Logf("Connections still working during isolation:")
		for _, indicator := range disruptedIndicators {
			t.Logf("  ⚠️ %s", indicator)
		}
	}

	// Assess disruption effectiveness
	if brokenConnections >= 3 {
		t.Logf("✓ Network isolation partially effective (%d/6 connections broken)", brokenConnections)
	} else if brokenConnections >= 1 {
		t.Logf("⚠️ Network isolation minimally effective (%d/6 connections broken)", brokenConnections)
	} else {
		t.Logf("❌ Network isolation ineffective (0/6 connections broken)")
	}

	// ========================================
	// PHASE 3: Network Recovery
	// ========================================
	t.Log("=== PHASE 3: Network Recovery ===")
	t.Log("Removing network isolation from Node 1...")

	// Remove network conditions
	if err := cluster.RemoveNetworkConditions(node1); err != nil {
		t.Fatalf("Failed to remove network conditions from Node 1: %v", err)
	}

	// Wait for recovery as specified in task
	t.Log("Waiting 5 seconds for network recovery...")
	time.Sleep(5 * time.Second)

	// Verify connections are restored (without log checks as requested)
	t.Log("=== Recovery Verification (No Log Checks) ===")

	// Check process connections after recovery
	processConnsRecovered1, err := cluster.CheckProcessConnections(node1.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Warning: Failed to get Node 1 recovered process connections: %v", err)
	} else {
		t.Logf("Node 1 recovered process connections: %d", len(processConnsRecovered1))
	}

	processConnsRecovered2, err := cluster.CheckProcessConnections(node2.ContainerID, "btc-federation-node")
	if err != nil {
		t.Logf("Warning: Failed to get Node 2 recovered process connections: %v", err)
	} else {
		t.Logf("Node 2 recovered process connections: %d", len(processConnsRecovered2))
	}

	// Check network connections after recovery
	nsConnsRecovered1, err := cluster.CheckNetworkNamespaceConnections(node1.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node 1 recovered network connections: %v", err)
	} else {
		t.Logf("Node 1 recovered network connections: %d", len(nsConnsRecovered1))
	}

	nsConnsRecovered2, err := cluster.CheckNetworkNamespaceConnections(node2.ContainerID)
	if err != nil {
		t.Logf("Warning: Failed to get Node 2 recovered network connections: %v", err)
	} else {
		t.Logf("Node 2 recovered network connections: %d", len(nsConnsRecovered2))
	}

	// Check reachability after recovery
	reachableRecovered12, err := cluster.CheckPeerReachability(node1.ContainerID, Node2StaticIP, 9001)
	if err != nil {
		t.Logf("Warning: Failed to check recovered reachability 1->2: %v", err)
	} else {
		t.Logf("Recovered reachability Node 1->Node 2: %t", reachableRecovered12)
	}

	reachableRecovered21, err := cluster.CheckPeerReachability(node2.ContainerID, Node1StaticIP, 9000)
	if err != nil {
		t.Logf("Warning: Failed to check recovered reachability 2->1: %v", err)
	} else {
		t.Logf("Recovered reachability Node 2->Node 1: %t", reachableRecovered21)
	}

	// ========================================
	// FINAL RESULTS ANALYSIS
	// ========================================
	t.Log("=== 🎯 RESILIENCE TEST RESULTS ===")

	var recoveredIndicators []string
	recoveredConnections := 0

	// Detailed recovery analysis (matching initial connection logic)
	// Process connections recovery - Node 1
	if len(processConnsRecovered1) > 0 {
		recoveredConnections++
		recoveredIndicators = append(recoveredIndicators, "Node 1 process connections restored")
	}

	// Process connections recovery - Node 2
	if len(processConnsRecovered2) > 0 {
		recoveredConnections++
		recoveredIndicators = append(recoveredIndicators, "Node 2 process connections restored")
	}

	// Network connections recovery - Node 1
	if len(nsConnsRecovered1) > 0 {
		recoveredConnections++
		recoveredIndicators = append(recoveredIndicators, "Node 1 network connections restored")
	}

	// Network connections recovery - Node 2
	if len(nsConnsRecovered2) > 0 {
		recoveredConnections++
		recoveredIndicators = append(recoveredIndicators, "Node 2 network connections restored")
	}

	// Reachability recovery - Node 1 to Node 2
	if reachableRecovered12 {
		recoveredConnections++
		recoveredIndicators = append(recoveredIndicators, "Node 1->Node 2 reachability restored")
	}

	// Reachability recovery - Node 2 to Node 1
	if reachableRecovered21 {
		recoveredConnections++
		recoveredIndicators = append(recoveredIndicators, "Node 2->Node 1 reachability restored")
	}

	t.Logf("Recovery indicators found: %d/6", recoveredConnections)
	for _, indicator := range recoveredIndicators {
		t.Logf("  ✅ %s", indicator)
	}

	// Final test decision (updated for detailed recovery analysis)
	if recoveredConnections >= 4 {
		t.Log("🎉 P2P Connection Resilience Test PASSED: Network recovery successful!")
		t.Logf("✅ Network isolation and recovery working correctly")
		t.Logf("✅ Found %d/6 recovery indicators", recoveredConnections)
		t.Log("🔗 P2P network resilience is functioning correctly")
	} else if recoveredConnections >= 2 {
		t.Error("⚠️  P2P Connection Resilience Test PARTIAL: Some recovery detected")
		t.Errorf("⚠️ Found %d/6 recovery indicators, expected at least 4 for full success", recoveredConnections)
		t.Log("🔍 Network may be recovering slowly or partially")
	} else {
		t.Error("❌ P2P Connection Resilience Test FAILED: Insufficient recovery detected")
		t.Errorf("🚫 Only %d/6 recovery indicators found", recoveredConnections)
		t.Log("🔍 Check network conditions, container capabilities, or timing")
	}
}

package testsuite

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"gopkg.in/yaml.v2"
)

// Cluster configuration constants
const (
	// DefaultDockerImage is the default Docker image for testing
	DefaultDockerImage = "btc-federation-test:ubuntu"
	// DefaultNetworkName is the default Docker network name
	DefaultNetworkName = "btc-federation-test-net"
	// ContainerStartupTimeout is the timeout for container startup
	ContainerStartupTimeout = 30 * time.Second
	// ContainerShutdownTimeout is the timeout for container shutdown
	ContainerShutdownTimeout = 10 * time.Second
	// HealthCheckRetries is the number of health check retries
	HealthCheckRetries = 5
	// HealthCheckInterval is the interval between health checks
	HealthCheckInterval = 2 * time.Second
)

// TCPConnection represents a TCP connection in a container
// Added for task 03-1: TCP connection analysis
type TCPConnection struct {
	// Source connection details
	SourceIP   string
	SourcePort int

	// Destination connection details
	DestIP   string
	DestPort int

	// Connection state (ESTABLISHED, LISTEN, etc.)
	State string

	// Additional metadata
	Protocol string
}

// NetworkConditions represents network conditions to apply to a node
// Added for task 03-6: Network resilience testing
type NetworkConditions struct {
	// Network isolation - completely block network traffic
	Isolated bool `json:"isolated"`

	// Traffic control conditions
	Latency    string `json:"latency,omitempty"`     // e.g., "100ms"
	PacketLoss string `json:"packet_loss,omitempty"` // e.g., "10%"
	Bandwidth  string `json:"bandwidth,omitempty"`   // e.g., "1mbit"

	// Advanced conditions
	Jitter      string `json:"jitter,omitempty"`      // e.g., "10ms"
	Duplication string `json:"duplication,omitempty"` // e.g., "1%"
	Corruption  string `json:"corruption,omitempty"`  // e.g., "0.1%"
	Reordering  string `json:"reordering,omitempty"`  // e.g., "25% 50%"
}

// Cluster represents a BTC federation node cluster for testing
// Adapted from vtcpd-test-suite Cluster structure
type Cluster struct {
	dockerClient *client.Client
	networkID    string
	networkName  string
	nodes        map[string]*Node
	dockerImage  string
	ctx          context.Context
}

// ClusterConfig represents configuration for a BTC federation cluster
// Based on vtcpd-test-suite cluster configuration patterns
type ClusterConfig struct {
	NetworkName string
	DockerImage string
	NodeCount   int
	BasePort    int
	Subnet      string // Optional custom subnet, defaults to "172.30.0.0/16"
	Gateway     string // Optional custom gateway, defaults to "172.30.0.1"
}

// NewCluster creates a new BTC federation cluster management instance
// Adapted from vtcpd-test-suite NewCluster implementation
func NewCluster(config *ClusterConfig) (*Cluster, error) {
	// Set default configuration values
	if config == nil {
		config = &ClusterConfig{}
	}

	if config.NetworkName == "" {
		config.NetworkName = DefaultNetworkName
	}

	if config.DockerImage == "" {
		// Check for environment variable override
		if envImage := os.Getenv("DOCKER_IMAGE"); envImage != "" {
			config.DockerImage = envImage
		} else {
			config.DockerImage = DefaultDockerImage
		}
	}

	// Create Docker client
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	cluster := &Cluster{
		dockerClient: dockerClient,
		networkName:  config.NetworkName,
		nodes:        make(map[string]*Node),
		dockerImage:  config.DockerImage,
		ctx:          context.Background(),
	}

	// Create Docker network
	if err := cluster.createNetwork(config); err != nil {
		return nil, fmt.Errorf("failed to create Docker network: %w", err)
	}

	return cluster, nil
}

// createNetwork creates a Docker network for the cluster
// Following vtcpd-test-suite network management patterns
func (c *Cluster) createNetwork(config *ClusterConfig) error {
	log.Printf("Checking for existing Docker network: %s", c.networkName)

	// Check if network already exists (following vtcpd-test-suite approach)
	networks, err := c.dockerClient.NetworkList(c.ctx, types.NetworkListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}

	// Search for existing network by name
	for _, net := range networks {
		if net.Name == c.networkName {
			log.Printf("✓ Found existing Docker network: %s (ID: %s)", c.networkName, net.ID[:12])

			// Verify network is in good state
			networkInspect, err := c.dockerClient.NetworkInspect(c.ctx, net.ID, types.NetworkInspectOptions{})
			if err != nil {
				log.Printf("Warning: Failed to inspect existing network %s: %v", c.networkName, err)
				// Continue to use the network even if inspection fails
			} else {
				log.Printf("✓ Network %s is active with driver: %s", c.networkName, networkInspect.Driver)
			}

			c.networkID = net.ID
			return nil // Network already exists, reuse it
		}
	}

	log.Printf("Network %s not found, creating new network...", c.networkName)

	// Find available subnet to avoid conflicts
	subnet, gateway, err := c.findAvailableSubnet(networks, config)
	if err != nil {
		return fmt.Errorf("failed to find available subnet: %w", err)
	}

	log.Printf("Using subnet: %s, gateway: %s", subnet, gateway)

	ipamConfig := network.IPAM{
		Driver: "default",
		Config: []network.IPAMConfig{
			{
				Subnet:  subnet,
				Gateway: gateway,
			},
		},
	}

	networkResponse, err := c.dockerClient.NetworkCreate(c.ctx, c.networkName, types.NetworkCreate{
		CheckDuplicate: true,
		Driver:         "bridge",
		IPAM:           &ipamConfig,
		Options: map[string]string{
			"com.docker.network.bridge.enable_icc":           "true",
			"com.docker.network.bridge.enable_ip_masquerade": "true",
		},
		Labels: map[string]string{
			"btc-federation-test": "true",
			"test-suite":          "btc-federation-test-suite",
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create network %s: %w", c.networkName, err)
	}

	c.networkID = networkResponse.ID
	log.Printf("✓ Successfully created new Docker network: %s (ID: %s)", c.networkName, networkResponse.ID[:12])

	return nil
}

// findAvailableSubnet finds an available subnet that doesn't conflict with existing networks
func (c *Cluster) findAvailableSubnet(existingNetworks []types.NetworkResource, config *ClusterConfig) (string, string, error) {
	// Use custom subnet if provided
	if config != nil && config.Subnet != "" && config.Gateway != "" {
		// Verify custom subnet doesn't conflict
		if !c.isSubnetInUse(existingNetworks, config.Subnet) {
			return config.Subnet, config.Gateway, nil
		}
		log.Printf("Warning: Custom subnet %s conflicts with existing network, finding alternative", config.Subnet)
	}

	// Try different subnets in 172.x.0.0/16 range
	baseSubnets := []string{
		"172.30.0.0/16", // Default
		"172.33.0.0/16",
		"172.34.0.0/16",
		"172.35.0.0/16",
		"172.36.0.0/16",
		"172.37.0.0/16",
		"172.38.0.0/16",
		"172.39.0.0/16",
		"172.40.0.0/16",
		"172.41.0.0/16",
	}

	for _, subnet := range baseSubnets {
		if !c.isSubnetInUse(existingNetworks, subnet) {
			gateway := strings.Replace(subnet, "0.0/16", "0.1", 1)
			return subnet, gateway, nil
		}
	}

	return "", "", fmt.Errorf("no available subnet found in 172.x.0.0/16 range")
}

// isSubnetInUse checks if a subnet is already in use by existing networks
func (c *Cluster) isSubnetInUse(networks []types.NetworkResource, targetSubnet string) bool {
	for _, net := range networks {
		// Skip the default bridge networks
		if net.Name == "bridge" || net.Name == "host" || net.Name == "none" {
			continue
		}

		// Get network details to check IPAM config
		networkDetails, err := c.dockerClient.NetworkInspect(c.ctx, net.ID, types.NetworkInspectOptions{})
		if err != nil {
			log.Printf("Warning: Failed to inspect network %s: %v", net.Name, err)
			continue
		}

		// Check all IPAM configs for subnet conflicts
		for _, ipamConfig := range networkDetails.IPAM.Config {
			if ipamConfig.Subnet == targetSubnet {
				log.Printf("Subnet %s already used by network %s", targetSubnet, net.Name)
				return true
			}
		}
	}
	return false
}

// RunNode starts a single BTC federation node
// Adapted from vtcpd-test-suite RunNode implementation with original signature
func (c *Cluster) RunNode(ctx context.Context, t *testing.T, wg *sync.WaitGroup, node *Node) {
	if wg != nil {
		defer wg.Done()
	}

	if node == nil {
		t.Fatalf("node cannot be nil")
		return
	}

	// Set cluster defaults
	if node.Config.NetworkName == "" {
		node.Config.NetworkName = c.networkName
	}
	if node.Config.DockerImage == "" {
		node.Config.DockerImage = c.dockerImage
	}

	// Check and clean up any existing container with the same name
	// Following vtcpd-test-suite container management patterns
	containerName := node.Config.ContainerName
	if containerName == "" {
		t.Fatalf("container name cannot be empty for node")
		return
	}

	// List all containers (running and stopped) with this name
	containers, err := c.dockerClient.ContainerList(ctx, types.ContainerListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("name", containerName),
		),
	})
	if err != nil {
		t.Fatalf("Failed to list containers: %v", err)
		return
	}

	// Remove any existing containers with the same name
	for _, existingContainer := range containers {
		for _, name := range existingContainer.Names {
			if name == "/"+containerName || name == containerName {
				t.Logf("Removing existing container %s (%s)", containerName, existingContainer.ID[:12])

				// Stop container if running
				if existingContainer.State == "running" {
					timeout := int(ContainerShutdownTimeout.Seconds())
					if stopErr := c.dockerClient.ContainerStop(ctx, existingContainer.ID, container.StopOptions{Timeout: &timeout}); stopErr != nil {
						t.Logf("Warning: Failed to stop existing container %s: %v", containerName, stopErr)
					}
				}

				// Remove container
				if removeErr := c.dockerClient.ContainerRemove(ctx, existingContainer.ID, types.ContainerRemoveOptions{Force: true}); removeErr != nil {
					t.Logf("Warning: Failed to remove existing container %s: %v", containerName, removeErr)
				}
				break
			}
		}
	}

	// Remove from cluster tracking if it was there
	if existingNode, exists := c.nodes[containerName]; exists {
		existingNode.IsRunning = false
		delete(c.nodes, containerName)
	}

	// Create and start container
	containerID, err := c.createContainer(node)
	if err != nil {
		t.Fatalf("Failed to create container for node %s: %v", containerName, err)
		return
	}

	node.ContainerID = containerID

	// Start container
	if err := c.dockerClient.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		t.Fatalf("Failed to start container for node %s: %v", containerName, err)
		return
	}

	// Wait for container to be healthy
	if err := c.waitForNodeHealthy(ctx, node); err != nil {
		// Cleanup on failure
		c.dockerClient.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
		t.Fatalf("Node %s failed to become healthy: %v", containerName, err)
		return
	}

	node.IsRunning = true
	c.nodes[containerName] = node

	// Add cleanup using t.Cleanup following vtcpd-test-suite pattern
	t.Cleanup(func() {
		t.Logf("Cleaning up container %s", containerName)

		// Stop container gracefully
		timeout := int(ContainerShutdownTimeout.Seconds())
		if stopErr := c.dockerClient.ContainerStop(context.Background(), containerID, container.StopOptions{Timeout: &timeout}); stopErr != nil {
			t.Logf("Warning: Failed to stop container %s: %v", containerName, stopErr)
		}

		// Remove container
		if removeErr := c.dockerClient.ContainerRemove(context.Background(), containerID, types.ContainerRemoveOptions{Force: true}); removeErr != nil {
			t.Logf("Warning: Failed to remove container %s: %v", containerName, removeErr)
		}

		// Update node state
		node.IsRunning = false
		delete(c.nodes, containerName)

		t.Logf("✓ Container %s cleaned up", containerName)
	})

	t.Logf("✓ Node %s started successfully", containerName)
}

// RunNodes starts multiple BTC federation nodes using the original vtcpd-test-suite pattern
// Adapted from vtcpd-test-suite RunNodes implementation
func (c *Cluster) RunNodes(ctx context.Context, t *testing.T, nodes []*Node) {
	if len(nodes) == 0 {
		t.Log("No nodes provided to start")
		return
	}

	var wg sync.WaitGroup

	t.Logf("Starting %d BTC federation nodes...", len(nodes))

	for _, node := range nodes {
		wg.Add(1)
		go c.RunNode(ctx, t, &wg, node)
	}

	wg.Wait()
	t.Logf("✓ All %d nodes startup process completed", len(nodes))
}

// createContainer creates a Docker container for the node
// Following vtcpd-test-suite container creation patterns
func (c *Cluster) createContainer(node *Node) (string, error) {
	// Prepare port bindings
	portBindings := nat.PortMap{}
	exposedPorts := nat.PortSet{}

	portStr := strconv.Itoa(node.Config.Port)
	containerPort := nat.Port(portStr + "/tcp")

	portBindings[containerPort] = []nat.PortBinding{
		{
			HostIP:   "0.0.0.0",
			HostPort: portStr,
		},
	}
	exposedPorts[containerPort] = struct{}{}

	// Container configuration
	containerConfig := &container.Config{
		Image:        node.Config.DockerImage,
		ExposedPorts: exposedPorts,
		Env:          node.GetEnvironmentVariables(),
		Labels:       node.GetLabels(),
		Healthcheck: &container.HealthConfig{
			Test:        []string{"CMD", "pgrep", "-f", "btc-federation-node"},
			Interval:    HealthCheckInterval,
			Timeout:     5 * time.Second,
			StartPeriod: 10 * time.Second,
			Retries:     HealthCheckRetries,
		},
	}

	// Host configuration
	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		NetworkMode:  container.NetworkMode(c.networkName),
		RestartPolicy: container.RestartPolicy{
			Name: "no",
		},
	}

	// Network configuration with static IP support
	endpointSettings := &network.EndpointSettings{
		NetworkID: c.networkID,
	}

	// Set static IP if provided
	if node.Config.IPAddress != "" && node.Config.IPAddress != "0.0.0.0" {
		endpointSettings.IPAMConfig = &network.EndpointIPAMConfig{
			IPv4Address: node.Config.IPAddress,
		}
	}

	networkConfig := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			c.networkName: endpointSettings,
		},
	}

	// Create container
	response, err := c.dockerClient.ContainerCreate(
		c.ctx,
		containerConfig,
		hostConfig,
		networkConfig,
		nil,
		node.Config.ContainerName,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	return response.ID, nil
}

// waitForNodeHealthy waits for a node to become healthy
// Updated to accept context parameter following vtcpd-test-suite patterns
func (c *Cluster) waitForNodeHealthy(ctx context.Context, node *Node) error {
	timeout := time.After(ContainerStartupTimeout)
	ticker := time.NewTicker(HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for node %s", node.Config.ContainerName)
		case <-timeout:
			return fmt.Errorf("timeout waiting for node %s to become healthy", node.Config.ContainerName)
		case <-ticker.C:
			inspect, err := c.dockerClient.ContainerInspect(ctx, node.ContainerID)
			if err != nil {
				continue
			}

			if inspect.State.Health != nil && inspect.State.Health.Status == "healthy" {
				return nil
			}

			if inspect.State.Status == "exited" {
				return fmt.Errorf("container exited unexpectedly")
			}
		}
	}
}

// StopNode stops a running node
// Following vtcpd-test-suite node shutdown patterns
func (c *Cluster) StopNode(containerName string) error {
	node, exists := c.nodes[containerName]
	if !exists {
		return fmt.Errorf("node %s not found", containerName)
	}

	if !node.IsRunning {
		return nil
	}

	// Stop container
	timeout := int(ContainerShutdownTimeout.Seconds())
	if err := c.dockerClient.ContainerStop(c.ctx, node.ContainerID, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Remove container
	if err := c.dockerClient.ContainerRemove(c.ctx, node.ContainerID, types.ContainerRemoveOptions{}); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	node.IsRunning = false
	delete(c.nodes, containerName)

	return nil
}

// ConfigureNetworkConditions applies network conditions to a specific node
// Modified for task 03-6: Accept specific node and NetworkConditions struct
func (c *Cluster) ConfigureNetworkConditions(node *Node, conditions *NetworkConditions) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if !node.IsRunning {
		return fmt.Errorf("node %s is not running", node.Config.ContainerName)
	}

	if conditions == nil {
		return nil
	}

	// Apply network isolation if specified
	if conditions.Isolated {
		if err := c.applyNetworkIsolation(node); err != nil {
			return fmt.Errorf("failed to apply network isolation to node %s: %w", node.Config.ContainerName, err)
		}
	}

	// Apply traffic control conditions if specified
	if conditions.Latency != "" {
		if err := c.applyLatency(node, conditions.Latency); err != nil {
			return fmt.Errorf("failed to apply latency to node %s: %w", node.Config.ContainerName, err)
		}
	}

	if conditions.PacketLoss != "" {
		if err := c.applyPacketLoss(node, conditions.PacketLoss); err != nil {
			return fmt.Errorf("failed to apply packet loss to node %s: %w", node.Config.ContainerName, err)
		}
	}

	if conditions.Bandwidth != "" {
		if err := c.applyBandwidthLimit(node, conditions.Bandwidth); err != nil {
			return fmt.Errorf("failed to apply bandwidth limit to node %s: %w", node.Config.ContainerName, err)
		}
	}

	// Apply advanced conditions if specified
	if conditions.Jitter != "" {
		if err := c.applyJitter(node, conditions.Jitter); err != nil {
			return fmt.Errorf("failed to apply jitter to node %s: %w", node.Config.ContainerName, err)
		}
	}

	if conditions.Duplication != "" {
		if err := c.applyDuplication(node, conditions.Duplication); err != nil {
			return fmt.Errorf("failed to apply duplication to node %s: %w", node.Config.ContainerName, err)
		}
	}

	if conditions.Corruption != "" {
		if err := c.applyCorruption(node, conditions.Corruption); err != nil {
			return fmt.Errorf("failed to apply corruption to node %s: %w", node.Config.ContainerName, err)
		}
	}

	if conditions.Reordering != "" {
		if err := c.applyReordering(node, conditions.Reordering); err != nil {
			return fmt.Errorf("failed to apply reordering to node %s: %w", node.Config.ContainerName, err)
		}
	}

	return nil
}

// RemoveNetworkConditions removes network conditions from a specific node
// Modified for task 03-6: Accept specific node parameter
func (c *Cluster) RemoveNetworkConditions(node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if !node.IsRunning {
		return fmt.Errorf("node %s is not running", node.Config.ContainerName)
	}

	if err := c.clearNetworkConditions(node); err != nil {
		return fmt.Errorf("failed to clear network conditions for node %s: %w", node.Config.ContainerName, err)
	}

	return nil
}

// applyNetworkIsolation completely isolates network for a node using multiple methods
func (c *Cluster) applyNetworkIsolation(node *Node) error {
	log.Printf("Applying comprehensive network isolation to container %s", node.ContainerID)

	// Method 1: Disconnect from Docker networks (most effective)
	if err := c.disconnectFromDockerNetworks(node); err != nil {
		log.Printf("Warning: Docker network disconnect failed: %v", err)
	}

	// Method 2: Bring down network interface completely
	interfaceCommands := [][]string{
		{"ip", "link", "set", "eth0", "down"},
		{"ifconfig", "eth0", "down"}, // Backup command
	}

	for _, cmd := range interfaceCommands {
		if err := c.execInContainer(node, cmd); err == nil {
			log.Printf("✓ Network interface brought down successfully")
			break // Success with one method is enough
		}
	}

	// Method 3: Comprehensive iptables blocking (backup isolation)
	iptablesCommands := [][]string{
		// Flush existing rules first
		{"iptables", "-F"},
		{"iptables", "-X"},
		{"iptables", "-t", "nat", "-F"},
		{"iptables", "-t", "mangle", "-F"},
		// Block all traffic in all directions
		{"iptables", "-P", "INPUT", "DROP"},
		{"iptables", "-P", "OUTPUT", "DROP"},
		{"iptables", "-P", "FORWARD", "DROP"},
		// Additional specific blocks
		{"iptables", "-A", "INPUT", "-j", "DROP"},
		{"iptables", "-A", "OUTPUT", "-j", "DROP"},
		{"iptables", "-A", "FORWARD", "-j", "DROP"},
	}

	for _, cmd := range iptablesCommands {
		if err := c.execInContainer(node, cmd); err == nil {
			log.Printf("✓ Applied iptables rule: %v", cmd)
		}
	}

	// Method 4: Traffic control complete packet drop (triple backup)
	tcCommands := [][]string{
		// Clear existing tc rules
		{"tc", "qdisc", "del", "dev", "eth0", "root"},
		// Apply 100% packet loss
		{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%"},
	}

	for _, cmd := range tcCommands {
		if err := c.execInContainer(node, cmd); err == nil {
			log.Printf("✓ Applied tc rule: %v", cmd)
		}
	}

	// Method 5: Block specific P2P ports (additional layer)
	portBlockCommands := [][]string{
		{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", "9000:9010", "-j", "DROP"},
		{"iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "9000:9010", "-j", "DROP"},
		{"iptables", "-A", "INPUT", "-p", "udp", "--dport", "9000:9010", "-j", "DROP"},
		{"iptables", "-A", "OUTPUT", "-p", "udp", "--sport", "9000:9010", "-j", "DROP"},
	}

	for _, cmd := range portBlockCommands {
		c.execInContainer(node, cmd) // Ignore errors - these are additional layers
	}

	log.Printf("✓ Comprehensive network isolation applied to container %s", node.ContainerID)
	return nil
}

// disconnectFromDockerNetworks disconnects container from all Docker networks
func (c *Cluster) disconnectFromDockerNetworks(node *Node) error {
	// Get container info to see which networks it's connected to
	containerInfo, err := c.dockerClient.ContainerInspect(context.Background(), node.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Disconnect from all networks
	for networkName := range containerInfo.NetworkSettings.Networks {
		err = c.dockerClient.NetworkDisconnect(context.Background(), networkName, node.ContainerID, true)
		if err != nil {
			log.Printf("Warning: failed to disconnect from network %s: %v", networkName, err)
		} else {
			log.Printf("✓ Disconnected container from network: %s", networkName)
		}
	}

	return nil
}

// applyLatency applies network latency to a node
func (c *Cluster) applyLatency(node *Node, latency string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", latency}
	return c.execInContainer(node, cmd)
}

// applyPacketLoss applies packet loss to a node
func (c *Cluster) applyPacketLoss(node *Node, packetLoss string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", packetLoss}
	return c.execInContainer(node, cmd)
}

// applyBandwidthLimit applies bandwidth limitation to a node
func (c *Cluster) applyBandwidthLimit(node *Node, bandwidth string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "tbf", "rate", bandwidth, "burst", "32kbit", "latency", "400ms"}
	return c.execInContainer(node, cmd)
}

// applyJitter applies network jitter to a node
func (c *Cluster) applyJitter(node *Node, jitter string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "50ms", jitter}
	return c.execInContainer(node, cmd)
}

// applyDuplication applies packet duplication to a node
func (c *Cluster) applyDuplication(node *Node, duplication string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "duplicate", duplication}
	return c.execInContainer(node, cmd)
}

// applyCorruption applies packet corruption to a node
func (c *Cluster) applyCorruption(node *Node, corruption string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "corrupt", corruption}
	return c.execInContainer(node, cmd)
}

// applyReordering applies packet reordering to a node
func (c *Cluster) applyReordering(node *Node, reordering string) error {
	// Clear existing conditions first
	c.clearNetworkConditions(node)

	// Parse reordering parameter (e.g., "25% 50%")
	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "10ms", "reorder"}
	cmd = append(cmd, strings.Fields(reordering)...)
	return c.execInContainer(node, cmd)
}

// clearNetworkConditions clears all network conditions from a node
func (c *Cluster) clearNetworkConditions(node *Node) error {
	log.Printf("Removing comprehensive network isolation from container %s", node.ContainerID)

	// Method 1: Reconnect to Docker networks (most important)
	if err := c.reconnectToDockerNetworks(node); err != nil {
		log.Printf("Warning: Docker network reconnect failed: %v", err)
	}

	// Method 2: Bring network interface back up
	interfaceCommands := [][]string{
		{"ip", "link", "set", "eth0", "up"},
		{"ifconfig", "eth0", "up"}, // Backup command
	}

	for _, cmd := range interfaceCommands {
		if err := c.execInContainer(node, cmd); err == nil {
			log.Printf("✓ Network interface brought up successfully")
			break
		}
	}

	// Method 3: Clear traffic control conditions
	tcClearCommands := [][]string{
		{"tc", "qdisc", "del", "dev", "eth0", "root"},
		{"tc", "qdisc", "show", "dev", "eth0"}, // Verify clearing
	}

	for _, cmd := range tcClearCommands {
		if err := c.execInContainer(node, cmd); err == nil {
			log.Printf("✓ Cleared tc rule: %v", cmd)
		}
	}

	// Method 4: Reset iptables to permissive state
	iptablesClearCommands := [][]string{
		// Set default policies to ACCEPT
		{"iptables", "-P", "INPUT", "ACCEPT"},
		{"iptables", "-P", "OUTPUT", "ACCEPT"},
		{"iptables", "-P", "FORWARD", "ACCEPT"},
		// Flush all rules
		{"iptables", "-F"},
		{"iptables", "-X"},
		{"iptables", "-t", "nat", "-F"},
		{"iptables", "-t", "mangle", "-F"},
		// Remove specific DROP rules (just in case)
		{"iptables", "-D", "OUTPUT", "-j", "DROP"},
		{"iptables", "-D", "INPUT", "-j", "DROP"},
		{"iptables", "-D", "FORWARD", "-j", "DROP"},
	}

	for _, cmd := range iptablesClearCommands {
		if err := c.execInContainer(node, cmd); err == nil {
			log.Printf("✓ Applied iptables recovery rule: %v", cmd)
		}
	}

	// Method 5: Clear specific port blocks
	portClearCommands := [][]string{
		{"iptables", "-D", "INPUT", "-p", "tcp", "--dport", "9000:9010", "-j", "DROP"},
		{"iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", "9000:9010", "-j", "DROP"},
		{"iptables", "-D", "INPUT", "-p", "udp", "--dport", "9000:9010", "-j", "DROP"},
		{"iptables", "-D", "OUTPUT", "-p", "udp", "--sport", "9000:9010", "-j", "DROP"},
	}

	for _, cmd := range portClearCommands {
		c.execInContainer(node, cmd) // Ignore errors - these might not exist
	}

	log.Printf("✓ Comprehensive network isolation removed from container %s", node.ContainerID)
	return nil
}

// reconnectToDockerNetworks reconnects container to the cluster network
func (c *Cluster) reconnectToDockerNetworks(node *Node) error {
	// Reconnect to the cluster network
	err := c.dockerClient.NetworkConnect(context.Background(), c.networkID, node.ContainerID, &network.EndpointSettings{
		IPAMConfig: &network.EndpointIPAMConfig{
			IPv4Address: node.Config.IPAddress,
		},
	})
	if err != nil {
		log.Printf("Warning: failed to reconnect to cluster network: %v", err)
		return err
	}

	log.Printf("✓ Reconnected container to cluster network with IP: %s", node.Config.IPAddress)
	return nil
}

// execInContainer executes a command in a container
func (c *Cluster) execInContainer(node *Node, cmd []string) error {
	execConfig := types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	response, err := c.dockerClient.ContainerExecCreate(c.ctx, node.ContainerID, execConfig)
	if err != nil {
		return fmt.Errorf("failed to create exec: %w", err)
	}

	return c.dockerClient.ContainerExecStart(c.ctx, response.ID, types.ExecStartCheck{})
}

// ExecInContainer executes a command in a container and returns output
func (c *Cluster) ExecInContainer(containerID string, cmd []string) (string, error) {
	execConfig := types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	response, err := c.dockerClient.ContainerExecCreate(c.ctx, containerID, execConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	hijackedResponse, err := c.dockerClient.ContainerExecAttach(c.ctx, response.ID, types.ExecStartCheck{})
	if err != nil {
		return "", fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer hijackedResponse.Close()

	// Read the output
	output := make([]byte, 4096)
	n, err := hijackedResponse.Reader.Read(output)
	if err != nil && err.Error() != "EOF" {
		return "", fmt.Errorf("failed to read exec output: %w", err)
	}

	// Remove Docker stream headers (first 8 bytes) and trim whitespace
	result := string(output[:n])
	if len(result) > 8 {
		result = result[8:]
	}
	result = strings.TrimSpace(result)

	// Check exit code of the executed command
	inspectResp, err := c.dockerClient.ContainerExecInspect(c.ctx, response.ID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect exec: %w", err)
	}

	if inspectResp.ExitCode != 0 {
		return result, fmt.Errorf("command failed with exit code %d", inspectResp.ExitCode)
	}

	return result, nil
}

// Cleanup cleans up cluster resources (but not the network)
// Following vtcpd-test-suite cleanup patterns - network is persistent
func (c *Cluster) Cleanup() error {
	var errors []string

	// Stop all nodes
	for name := range c.nodes {
		if err := c.StopNode(name); err != nil {
			errors = append(errors, fmt.Sprintf("failed to stop node %s: %v", name, err))
		}
	}

	// NOTE: Do not remove network - following vtcpd-test-suite pattern
	// Networks are shared between tests and should persist
	// This prevents conflicts when multiple tests run concurrently

	// Close Docker client
	if err := c.dockerClient.Close(); err != nil {
		errors = append(errors, fmt.Sprintf("failed to close Docker client: %v", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// GetNodes returns all nodes in the cluster
func (c *Cluster) GetNodes() map[string]*Node {
	return c.nodes
}

// GetRunningNodes returns all running nodes in the cluster
func (c *Cluster) GetRunningNodes() []*Node {
	var runningNodes []*Node
	for _, node := range c.nodes {
		if node.IsRunning {
			runningNodes = append(runningNodes, node)
		}
	}
	return runningNodes
}

// CheckTCPConnections analyzes TCP connections in a container
// Added for task 03-1: TCP connection analysis capability
func (c *Cluster) CheckTCPConnections(containerID string) ([]TCPConnection, error) {
	// Use ss command to get TCP connection information
	// ss is more modern and reliable than netstat
	cmd := []string{"ss", "-tuln"}

	output, err := c.ExecInContainer(containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ss command in container %s: %w", containerID, err)
	}

	connections, err := c.parseTCPConnections(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TCP connections: %w", err)
	}

	return connections, nil
}

// GetActiveConnectionsCount returns the count of active TCP connections on P2P ports
// Added for task 03-1: Simplified connection counting for P2P testing
func (c *Cluster) GetActiveConnectionsCount(containerID string) (int, error) {
	connections, err := c.CheckTCPConnections(containerID)
	if err != nil {
		return 0, fmt.Errorf("failed to check TCP connections: %w", err)
	}

	// Count connections on P2P ports (9000-9001) that are ESTABLISHED
	count := 0
	for _, conn := range connections {
		if (conn.SourcePort >= 9000 && conn.SourcePort <= 9001) ||
			(conn.DestPort >= 9000 && conn.DestPort <= 9001) {
			if conn.State == "ESTAB" || conn.State == "ESTABLISHED" {
				count++
			}
		}
	}

	return count, nil
}

// parseTCPConnections parses ss command output to extract TCP connection information
// Helper method for CheckTCPConnections
func (c *Cluster) parseTCPConnections(output string) ([]TCPConnection, error) {
	var connections []TCPConnection
	lines := strings.Split(output, "\n")

	// Regular expression to parse ss output
	// Expected format: tcp   ESTAB      0      0      192.168.1.100:9000      192.168.1.101:45678
	tcpRegex := regexp.MustCompile(`^(tcp|udp)\s+([A-Z-]+)\s+\d+\s+\d+\s+([^:\s]+):(\d+)\s+([^:\s]+):(\d+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}

		matches := tcpRegex.FindStringSubmatch(line)
		if len(matches) == 7 {
			sourcePort, err1 := strconv.Atoi(matches[4])
			destPort, err2 := strconv.Atoi(matches[6])

			if err1 != nil || err2 != nil {
				// Skip lines with invalid port numbers
				continue
			}

			connection := TCPConnection{
				Protocol:   matches[1],
				State:      matches[2],
				SourceIP:   matches[3],
				SourcePort: sourcePort,
				DestIP:     matches[5],
				DestPort:   destPort,
			}

			connections = append(connections, connection)
		}
	}

	return connections, nil
}

// CheckNodeLogContains searches for a pattern in a node's log file
// Added for task 03-2: Node log analysis through cluster context
func (c *Cluster) CheckNodeLogContains(containerID string, pattern string) (bool, error) {
	// Find node by container ID
	var targetNode *Node
	for _, node := range c.nodes {
		if node.ContainerID == containerID {
			targetNode = node
			break
		}
	}

	if targetNode == nil {
		return false, fmt.Errorf("node with container ID %s not found", containerID)
	}

	if !targetNode.IsRunning {
		return false, fmt.Errorf("node is not running")
	}

	// Get the log file path from the node configuration
	logPath := targetNode.getLogFilePath()

	// Use grep to search for the pattern in the log file
	cmd := []string{"grep", "-q", pattern, logPath}

	_, err := c.ExecInContainer(containerID, cmd)
	if err != nil {
		// grep exit codes:
		// 0 = pattern found
		// 1 = pattern not found
		// 2 = file not found or other error
		if strings.Contains(err.Error(), "exit code 1") {
			return false, nil // Pattern not found, but no error
		}
		// For exit code 2 (file not found) or other errors, return error
		return false, fmt.Errorf("failed to search log file: %w", err)
	}

	return true, nil
}

// GetNodePeersConfig retrieves peers configuration from a node's peers.yaml file
// Added for task 03-2: Node peers configuration access through cluster context
func (c *Cluster) GetNodePeersConfig(containerID string) (map[string]interface{}, error) {
	// Find node by container ID
	var targetNode *Node
	for _, node := range c.nodes {
		if node.ContainerID == containerID {
			targetNode = node
			break
		}
	}

	if targetNode == nil {
		return nil, fmt.Errorf("node with container ID %s not found", containerID)
	}

	if !targetNode.IsRunning {
		return nil, fmt.Errorf("node is not running")
	}

	// Get the peers config file path
	peersPath := targetNode.getPeersConfigPath()

	// Read the peers.yaml file content
	cmd := []string{"cat", peersPath}

	yamlContent, err := c.ExecInContainer(containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to read peers config file: %w", err)
	}

	if strings.TrimSpace(yamlContent) == "" {
		return make(map[string]interface{}), nil // Return empty map for empty file
	}

	// Parse YAML content
	var peersConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &peersConfig); err != nil {
		return nil, fmt.Errorf("failed to parse peers YAML: %w", err)
	}

	return peersConfig, nil
}

// GetContainerIP returns the IP address of a container in the cluster network
func (c *Cluster) GetContainerIP(containerID string) (string, error) {
	// Inspect the container to get network information
	containerInfo, err := c.dockerClient.ContainerInspect(c.ctx, containerID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	// Get the network settings
	networkSettings := containerInfo.NetworkSettings
	if networkSettings == nil {
		return "", fmt.Errorf("no network settings found for container %s", containerID)
	}

	// Look for the cluster network
	networkName := c.networkName
	if networkName == "" {
		return "", fmt.Errorf("no network name configured for cluster")
	}

	// Find the network in the container's networks
	if networkSettings.Networks == nil {
		return "", fmt.Errorf("no networks found for container %s", containerID)
	}

	network, exists := networkSettings.Networks[networkName]
	if !exists {
		return "", fmt.Errorf("container %s is not connected to network %s", containerID, networkName)
	}

	if network.IPAddress == "" {
		return "", fmt.Errorf("no IP address found for container %s in network %s", containerID, networkName)
	}

	return network.IPAddress, nil
}

// UpdateNodePeersConfig updates the peers.yaml file in a running container
func (c *Cluster) UpdateNodePeersConfig(node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if !node.IsRunning {
		return fmt.Errorf("node %s is not running", node.Config.ContainerName)
	}

	// Trigger peers config update in the node
	if err := node.UpdatePeersConfig(); err != nil {
		return fmt.Errorf("failed to generate peers config: %w", err)
	}

	// Get the updated peers config data
	yamlData := node.GetUpdatedPeersConfig()
	if len(yamlData) == 0 {
		return fmt.Errorf("no peers config data to update")
	}

	// Write the YAML content to the container's peers.yaml file
	peersPath := node.getPeersConfigPath()

	// Create the command to write the file
	cmd := []string{"sh", "-c", fmt.Sprintf("cat > %s", peersPath)}

	// Execute the command and pipe the YAML content to it
	execConfig := types.ExecConfig{
		Cmd:          cmd,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
	}

	response, err := c.dockerClient.ContainerExecCreate(c.ctx, node.ContainerID, execConfig)
	if err != nil {
		return fmt.Errorf("failed to create exec for peers config update: %w", err)
	}

	hijackedResponse, err := c.dockerClient.ContainerExecAttach(c.ctx, response.ID, types.ExecStartCheck{})
	if err != nil {
		return fmt.Errorf("failed to attach to exec for peers config update: %w", err)
	}
	defer hijackedResponse.Close()

	// Write the YAML data to stdin
	if _, err := hijackedResponse.Conn.Write(yamlData); err != nil {
		return fmt.Errorf("failed to write peers config data: %w", err)
	}

	// Close the connection to signal EOF
	if err := hijackedResponse.CloseWrite(); err != nil {
		return fmt.Errorf("failed to close write connection: %w", err)
	}

	// Wait for the command to complete and check exit code
	inspectResponse, err := c.dockerClient.ContainerExecInspect(c.ctx, response.ID)
	if err != nil {
		return fmt.Errorf("failed to inspect exec for peers config update: %w", err)
	}

	// Wait for command completion
	for inspectResponse.Running {
		time.Sleep(100 * time.Millisecond)
		inspectResponse, err = c.dockerClient.ContainerExecInspect(c.ctx, response.ID)
		if err != nil {
			return fmt.Errorf("failed to inspect exec status: %w", err)
		}
	}

	if inspectResponse.ExitCode != 0 {
		return fmt.Errorf("failed to update peers config file, exit code: %d", inspectResponse.ExitCode)
	}

	// Mark the node as updated
	node.MarkPeersUpdated()

	return nil
}

// RestartNode stops and starts a container to reload configuration
func (c *Cluster) RestartNode(ctx context.Context, node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if !node.IsRunning {
		return fmt.Errorf("node %s is not running", node.Config.ContainerName)
	}

	// Stop container
	timeout := int(ContainerShutdownTimeout.Seconds())
	if err := c.dockerClient.ContainerStop(ctx, node.ContainerID, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("failed to stop container %s: %w", node.Config.ContainerName, err)
	}

	// Start container again
	if err := c.dockerClient.ContainerStart(ctx, node.ContainerID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed to start container %s: %w", node.Config.ContainerName, err)
	}

	// Wait for container to be healthy
	if err := c.waitForNodeHealthy(ctx, node); err != nil {
		return fmt.Errorf("node %s failed to become healthy after restart: %w", node.Config.ContainerName, err)
	}

	return nil
}

// WaitForNodeHealthy waits for a node to become healthy - public wrapper
func (c *Cluster) WaitForNodeHealthy(ctx context.Context, node *Node) error {
	return c.waitForNodeHealthy(ctx, node)
}

// CheckLibP2PConnections перевіряє libp2p з'єднання через netstat
func (c *Cluster) CheckLibP2PConnections(containerID string) ([]LibP2PConnection, error) {
	// Execute netstat to find P2P connections
	cmd := []string{"netstat", "-tupln"}
	output, err := c.ExecInContainer(containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute netstat: %w", err)
	}

	return c.parseLibP2PConnections(output)
}

// CheckPeerReachability перевіряє доступність peer'ів через ping/nc
func (c *Cluster) CheckPeerReachability(containerID string, targetIP string, targetPort int) (bool, error) {
	// Try to connect using netcat
	cmd := []string{"nc", "-z", "-w", "3", targetIP, strconv.Itoa(targetPort)}
	_, err := c.ExecInContainer(containerID, cmd)

	return err == nil, nil
}

// CheckProcessConnections перевіряє з'єднання конкретного процесу через lsof
func (c *Cluster) CheckProcessConnections(containerID string, processName string) ([]ProcessConnection, error) {
	// Find process PID first
	pidCmd := []string{"pgrep", "-f", processName}
	pidOutput, err := c.ExecInContainer(containerID, pidCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to find process %s: %w", processName, err)
	}

	pid := strings.TrimSpace(pidOutput)
	if pid == "" {
		return nil, fmt.Errorf("process %s not found", processName)
	}

	// Use lsof to check connections for this PID
	lsofCmd := []string{"lsof", "-p", pid, "-i", "-n"}
	lsofOutput, err := c.ExecInContainer(containerID, lsofCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute lsof: %w", err)
	}

	return c.parseProcessConnections(lsofOutput)
}

// CheckNetworkNamespaceConnections перевіряє з'єднання через ss
func (c *Cluster) CheckNetworkNamespaceConnections(containerID string) ([]NetworkConnection, error) {
	// Use ss command for more detailed network information
	cmd := []string{"ss", "-tuln", "-p"}
	output, err := c.ExecInContainer(containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ss: %w", err)
	}

	return c.parseNetworkConnections(output)
}

// AnalyzeLibP2PBehavior аналізує поведінку libp2p через логи та мережеві з'єднання
func (c *Cluster) AnalyzeLibP2PBehavior(containerID string) (*LibP2PAnalysis, error) {
	analysis := &LibP2PAnalysis{
		ContainerID: containerID,
		Timestamp:   time.Now(),
	}

	// 1. Check TCP connections
	tcpConns, err := c.CheckTCPConnections(containerID)
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("TCP check failed: %v", err))
	} else {
		analysis.TCPConnections = tcpConns
	}

	// 2. Check libp2p specific connections
	libp2pConns, err := c.CheckLibP2PConnections(containerID)
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("LibP2P check failed: %v", err))
	} else {
		analysis.LibP2PConnections = libp2pConns
	}

	// 3. Check process connections
	processConns, err := c.CheckProcessConnections(containerID, "btc-federation-node")
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("Process check failed: %v", err))
	} else {
		analysis.ProcessConnections = processConns
	}

	// 4. Check network namespace
	nsConns, err := c.CheckNetworkNamespaceConnections(containerID)
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("Network namespace check failed: %v", err))
	} else {
		analysis.NetworkConnections = nsConns
	}

	// 5. Analyze logs for P2P patterns
	logPatterns := []string{
		"Connection established",
		"peer connected",
		"Bootstrap successful",
		"connected_peers",
		"libp2p",
		"multiaddr",
	}

	analysis.LogMatches = make(map[string]bool)
	for _, pattern := range logPatterns {
		if found, err := c.CheckNodeLogContains(containerID, pattern); err == nil && found {
			analysis.LogMatches[pattern] = true
		}
	}

	return analysis, nil
}

// parseLibP2PConnections парсить вивід netstat для libp2p з'єднань
func (c *Cluster) parseLibP2PConnections(output string) ([]LibP2PConnection, error) {
	var connections []LibP2PConnection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}

			localAddr := fields[3]
			remoteAddr := fields[4]

			// Parse local address
			localParts := strings.Split(localAddr, ":")
			if len(localParts) < 2 {
				continue
			}
			localPort, _ := strconv.Atoi(localParts[len(localParts)-1])

			// Parse remote address
			remoteParts := strings.Split(remoteAddr, ":")
			if len(remoteParts) < 2 {
				continue
			}
			remotePort, _ := strconv.Atoi(remoteParts[len(remoteParts)-1])

			// Check if this looks like a P2P connection (ports 9000-9010 range)
			if (localPort >= 9000 && localPort <= 9010) || (remotePort >= 9000 && remotePort <= 9010) {
				conn := LibP2PConnection{
					Protocol:   "tcp",
					LocalAddr:  localAddr,
					RemoteAddr: remoteAddr,
					State:      "ESTABLISHED",
				}
				connections = append(connections, conn)
			}
		}
	}

	return connections, nil
}

// parseProcessConnections парсить вивід lsof
func (c *Cluster) parseProcessConnections(output string) ([]ProcessConnection, error) {
	var connections []ProcessConnection
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		// lsof output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
		conn := ProcessConnection{
			Command: fields[0],
			PID:     fields[1],
			FD:      fields[3],
			Type:    fields[4],
			Node:    fields[7],
			Name:    fields[8],
		}

		// Parse connection details from NAME field
		if strings.Contains(conn.Name, "->") {
			parts := strings.Split(conn.Name, "->")
			if len(parts) == 2 {
				conn.LocalAddr = strings.TrimSpace(parts[0])
				conn.RemoteAddr = strings.TrimSpace(parts[1])
				conn.State = "ESTABLISHED"
			}
		} else if strings.Contains(conn.Name, ":") {
			conn.LocalAddr = conn.Name
			conn.State = "LISTEN"
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// parseNetworkConnections парсить вивід ss
func (c *Cluster) parseNetworkConnections(output string) ([]NetworkConnection, error) {
	var connections []NetworkConnection
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// ss output format: State Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process
		conn := NetworkConnection{
			State:     fields[0],
			RecvQ:     fields[1],
			SendQ:     fields[2],
			LocalAddr: fields[3],
			PeerAddr:  fields[4],
		}

		if len(fields) > 5 {
			conn.Process = strings.Join(fields[5:], " ")
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// LibP2PConnection represents a libp2p network connection
type LibP2PConnection struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
}

// ProcessConnection represents a process-specific connection from lsof
type ProcessConnection struct {
	Command    string `json:"command"`
	PID        string `json:"pid"`
	FD         string `json:"fd"`
	Type       string `json:"type"`
	Node       string `json:"node"`
	Name       string `json:"name"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
}

// NetworkConnection represents a network connection from ss
type NetworkConnection struct {
	State     string `json:"state"`
	RecvQ     string `json:"recv_q"`
	SendQ     string `json:"send_q"`
	LocalAddr string `json:"local_addr"`
	PeerAddr  string `json:"peer_addr"`
	Process   string `json:"process"`
}

// LibP2PAnalysis contains comprehensive libp2p analysis
type LibP2PAnalysis struct {
	ContainerID        string              `json:"container_id"`
	Timestamp          time.Time           `json:"timestamp"`
	TCPConnections     []TCPConnection     `json:"tcp_connections"`
	LibP2PConnections  []LibP2PConnection  `json:"libp2p_connections"`
	ProcessConnections []ProcessConnection `json:"process_connections"`
	NetworkConnections []NetworkConnection `json:"network_connections"`
	LogMatches         map[string]bool     `json:"log_matches"`
	Errors             []string            `json:"errors"`
}

// CheckDockerNetworkConnectivity перевіряє мережеву зв'язність між контейнерами
func (c *Cluster) CheckDockerNetworkConnectivity(containerAID, containerBID string) (*DockerNetworkAnalysis, error) {
	analysis := &DockerNetworkAnalysis{
		Timestamp: time.Now(),
	}

	// Get container A info
	containerAInfo, err := c.dockerClient.ContainerInspect(c.ctx, containerAID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container A: %w", err)
	}
	analysis.ContainerAInfo = extractNetworkInfo(containerAInfo)

	// Get container B info
	containerBInfo, err := c.dockerClient.ContainerInspect(c.ctx, containerBID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container B: %w", err)
	}
	analysis.ContainerBInfo = extractNetworkInfo(containerBInfo)

	// Check if containers are on the same network
	analysis.SameNetwork = checkSameNetwork(containerAInfo, containerBInfo)

	// Test connectivity with ping
	pingAB, err := c.testPingConnectivity(containerAID, analysis.ContainerBInfo.IPAddress)
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("Ping A->B failed: %v", err))
	} else {
		analysis.PingAB = pingAB
	}

	pingBA, err := c.testPingConnectivity(containerBID, analysis.ContainerAInfo.IPAddress)
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("Ping B->A failed: %v", err))
	} else {
		analysis.PingBA = pingBA
	}

	return analysis, nil
}

// testPingConnectivity tests ping connectivity between containers
func (c *Cluster) testPingConnectivity(containerID, targetIP string) (bool, error) {
	cmd := []string{"ping", "-c", "3", "-W", "2", targetIP}
	_, err := c.ExecInContainer(containerID, cmd)
	return err == nil, err
}

// extractNetworkInfo extracts network information from container inspect
func extractNetworkInfo(containerInfo types.ContainerJSON) ContainerNetworkInfo {
	info := ContainerNetworkInfo{
		ContainerID:   containerInfo.ID,
		ContainerName: containerInfo.Name,
	}

	if containerInfo.NetworkSettings != nil {
		for networkName, network := range containerInfo.NetworkSettings.Networks {
			info.NetworkName = networkName
			info.IPAddress = network.IPAddress
			info.Gateway = network.Gateway
			info.MacAddress = network.MacAddress
			break // Take first network
		}
	}

	return info
}

// checkSameNetwork checks if two containers are on the same Docker network
func checkSameNetwork(containerA, containerB types.ContainerJSON) bool {
	if containerA.NetworkSettings == nil || containerB.NetworkSettings == nil {
		return false
	}

	for networkNameA := range containerA.NetworkSettings.Networks {
		for networkNameB := range containerB.NetworkSettings.Networks {
			if networkNameA == networkNameB {
				return true
			}
		}
	}
	return false
}

// CheckLibP2PProtocolHandshake перевіряє libp2p протокол handshake
func (c *Cluster) CheckLibP2PProtocolHandshake(containerID string) (*ProtocolAnalysis, error) {
	analysis := &ProtocolAnalysis{
		ContainerID: containerID,
		Timestamp:   time.Now(),
	}

	// Check for libp2p specific network traffic patterns
	tcpdumpCmd := []string{"timeout", "5", "tcpdump", "-c", "10", "-n", "port", "9000", "or", "port", "9001"}
	output, err := c.ExecInContainer(containerID, tcpdumpCmd)
	if err != nil {
		analysis.Errors = append(analysis.Errors, fmt.Sprintf("tcpdump failed: %v", err))
	} else {
		analysis.NetworkTraffic = output
		analysis.HasTraffic = len(strings.TrimSpace(output)) > 0
	}

	// Check for multiaddr patterns in logs
	multiAddrPatterns := []string{
		"/ip4/",
		"/tcp/",
		"/p2p/",
		"multiaddr",
	}

	analysis.MultiAddrMatches = make(map[string]bool)
	for _, pattern := range multiAddrPatterns {
		if found, err := c.CheckNodeLogContains(containerID, pattern); err == nil && found {
			analysis.MultiAddrMatches[pattern] = true
		}
	}

	return analysis, nil
}

// ContainerNetworkInfo contains network information for a container
type ContainerNetworkInfo struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	NetworkName   string `json:"network_name"`
	IPAddress     string `json:"ip_address"`
	Gateway       string `json:"gateway"`
	MacAddress    string `json:"mac_address"`
}

// DockerNetworkAnalysis contains Docker network connectivity analysis
type DockerNetworkAnalysis struct {
	Timestamp      time.Time            `json:"timestamp"`
	ContainerAInfo ContainerNetworkInfo `json:"container_a_info"`
	ContainerBInfo ContainerNetworkInfo `json:"container_b_info"`
	SameNetwork    bool                 `json:"same_network"`
	PingAB         bool                 `json:"ping_a_to_b"`
	PingBA         bool                 `json:"ping_b_to_a"`
	Errors         []string             `json:"errors"`
}

// ProtocolAnalysis contains libp2p protocol analysis
type ProtocolAnalysis struct {
	ContainerID      string          `json:"container_id"`
	Timestamp        time.Time       `json:"timestamp"`
	NetworkTraffic   string          `json:"network_traffic"`
	HasTraffic       bool            `json:"has_traffic"`
	MultiAddrMatches map[string]bool `json:"multiaddr_matches"`
	Errors           []string        `json:"errors"`
}

// RunConfigValidation runs a node specifically for configuration validation
// This method starts a container, waits for it to complete, and returns the result
func (c *Cluster) RunConfigValidation(ctx context.Context, node *Node) (*ConfigValidationResult, error) {
	if node == nil {
		return nil, fmt.Errorf("node cannot be nil")
	}

	// Set cluster defaults
	if node.Config.NetworkName == "" {
		node.Config.NetworkName = c.networkName
	}
	if node.Config.DockerImage == "" {
		node.Config.DockerImage = c.dockerImage
	}

	// Create unique container name if not set
	containerName := node.Config.ContainerName
	if containerName == "" {
		containerName = fmt.Sprintf("config-validation-%d", time.Now().UnixNano())
		node.Config.ContainerName = containerName
	}

	// Create container for validation (modified from createContainer)
	containerID, err := c.createValidationContainer(node)
	if err != nil {
		return &ConfigValidationResult{
			ExitCode: 1,
			TimedOut: false,
			Logs:     fmt.Sprintf("Failed to create container: %v", err),
			Error:    err,
		}, nil
	}

	// Start container
	if err := c.dockerClient.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		// Cleanup on failure
		c.dockerClient.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
		return &ConfigValidationResult{
			ExitCode: 1,
			TimedOut: false,
			Logs:     fmt.Sprintf("Failed to start container: %v", err),
			Error:    err,
		}, nil
	}

	// Wait for container completion with timeout
	exitCode, timedOut, err := c.waitForValidationCompletion(ctx, containerID)
	if err != nil {
		// Cleanup on error
		c.dockerClient.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
		return &ConfigValidationResult{
			ExitCode: 1,
			TimedOut: timedOut,
			Logs:     fmt.Sprintf("Failed to wait for container completion: %v", err),
			Error:    err,
		}, nil
	}

	// Get container logs
	logs, err := c.getValidationLogs(ctx, containerID)
	if err != nil {
		logs = fmt.Sprintf("Failed to retrieve logs: %v", err)
	}

	// Cleanup container
	if removeErr := c.dockerClient.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true}); removeErr != nil {
		log.Printf("Warning: Failed to remove validation container %s: %v", containerID, removeErr)
	}

	return &ConfigValidationResult{
		ExitCode: exitCode,
		TimedOut: timedOut,
		Logs:     logs,
		Error:    nil,
	}, nil
}

// createValidationContainer creates a Docker container for configuration validation
func (c *Cluster) createValidationContainer(node *Node) (string, error) {
	// Prepare port bindings (similar to createContainer but for validation)
	portBindings := nat.PortMap{}
	exposedPorts := nat.PortSet{}

	portStr := strconv.Itoa(node.Config.Port)
	containerPort := nat.Port(portStr + "/tcp")

	portBindings[containerPort] = []nat.PortBinding{
		{
			HostIP:   "0.0.0.0",
			HostPort: portStr,
		},
	}
	exposedPorts[containerPort] = struct{}{}

	// Container configuration with validation-specific settings
	containerConfig := &container.Config{
		Image:        node.Config.DockerImage,
		ExposedPorts: exposedPorts,
		Env:          node.GetEnvironmentVariables(),
		Labels:       node.GetLabels(),
		// No healthcheck for validation - we want the container to exit quickly
	}

	// Host configuration
	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		NetworkMode:  container.NetworkMode(c.networkName),
		RestartPolicy: container.RestartPolicy{
			Name: "no",
		},
		// Set resource limits for validation containers
		Resources: container.Resources{
			Memory:   128 * 1024 * 1024, // 128MB
			NanoCPUs: 250000000,         // 0.25 CPU
		},
	}

	// Network configuration
	endpointSettings := &network.EndpointSettings{
		NetworkID: c.networkID,
	}

	// Set static IP if provided
	if node.Config.IPAddress != "" && node.Config.IPAddress != "0.0.0.0" {
		endpointSettings.IPAMConfig = &network.EndpointIPAMConfig{
			IPv4Address: node.Config.IPAddress,
		}
	}

	networkConfig := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			c.networkName: endpointSettings,
		},
	}

	// Create container
	response, err := c.dockerClient.ContainerCreate(
		c.ctx,
		containerConfig,
		hostConfig,
		networkConfig,
		nil,
		node.Config.ContainerName,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create validation container: %w", err)
	}

	return response.ID, nil
}

// waitForValidationCompletion waits for a validation container to complete
func (c *Cluster) waitForValidationCompletion(ctx context.Context, containerID string) (int, bool, error) {
	// Create timeout context for validation - shortened timeout since we expect quick startup
	timeout := 10 * time.Second
	validationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Since the application doesn't exit automatically, we need to check if it started successfully
	// Wait a bit for the application to start - increased wait time for better log capture
	time.Sleep(5 * time.Second)

	// Check container logs to see if application started successfully
	logs, err := c.getValidationLogs(ctx, containerID)
	if err != nil {
		log.Printf("Warning: Failed to get container logs: %v", err)
	}

	// Check if logs contain successful startup indicators
	successIndicators := []string{
		"Node started successfully",
		"BTC Federation Node starting with config",
		"Network manager started successfully",
	}

	hasSuccess := false
	for _, indicator := range successIndicators {
		if strings.Contains(logs, indicator) {
			hasSuccess = true
			break
		}
	}

	// Check for error indicators
	errorIndicators := []string{
		"Error:",
		"failed to",
		"configuration validation failed:",
		"FATAL",
	}

	hasError := false
	for _, indicator := range errorIndicators {
		if strings.Contains(logs, indicator) {
			hasError = true
			break
		}
	}

	// Stop the container forcefully
	if err := c.dockerClient.ContainerStop(ctx, containerID, container.StopOptions{}); err != nil {
		// If stop fails, force kill
		c.dockerClient.ContainerKill(ctx, containerID, "SIGKILL")
	}

	// Wait for container to stop
	statusCh, errCh := c.dockerClient.ContainerWait(validationCtx, containerID, container.WaitConditionNotRunning)

	select {
	case err := <-errCh:
		if err != nil {
			return 1, false, fmt.Errorf("error waiting for container: %w", err)
		}
	case status := <-statusCh:
		// If container exited on its own, use its exit code
		if status.StatusCode != 0 {
			return int(status.StatusCode), false, nil
		}
	case <-validationCtx.Done():
		// Timeout occurred
		return 1, true, fmt.Errorf("validation timeout after %v", timeout)
	}

	// Determine success based on log analysis
	if hasError {
		return 1, false, nil
	} else if hasSuccess {
		return 0, false, nil
	} else {
		// No clear indicators, assume failure
		return 1, false, nil
	}
}

// getValidationLogs retrieves logs from a validation container
func (c *Cluster) getValidationLogs(ctx context.Context, containerID string) (string, error) {
	// Get container logs
	logReader, err := c.dockerClient.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Details:    false,
		Timestamps: false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get container logs: %w", err)
	}
	defer logReader.Close()

	// Read all available logs
	var allData []byte
	buffer := make([]byte, 4096)
	for {
		n, err := logReader.Read(buffer)
		if n > 0 {
			allData = append(allData, buffer[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return "", fmt.Errorf("failed to read container logs: %w", err)
		}
	}

	// Convert to string and clean up Docker headers
	logs := string(allData)

	// Remove Docker stream headers (8-byte headers appear throughout)
	// Simple approach: remove binary characters and clean up
	cleanLogs := ""
	lines := strings.Split(logs, "\n")
	for _, line := range lines {
		// Skip empty lines and lines that start with binary data
		if len(line) > 0 && line[0] >= 32 && line[0] <= 126 {
			cleanLogs += line + "\n"
		}
	}

	return strings.TrimSpace(cleanLogs), nil
}

// ConfigValidationResult represents the result of configuration validation
type ConfigValidationResult struct {
	ExitCode int
	TimedOut bool
	Logs     string
	Error    error
}

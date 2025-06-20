package testsuite

import (
	"context"
	"fmt"
	"os"
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
	if err := cluster.createNetwork(); err != nil {
		return nil, fmt.Errorf("failed to create Docker network: %w", err)
	}

	return cluster, nil
}

// createNetwork creates a Docker network for the cluster
// Following vtcpd-test-suite network management patterns
func (c *Cluster) createNetwork() error {
	// Check if network already exists (following vtcpd-test-suite approach)
	networks, err := c.dockerClient.NetworkList(c.ctx, types.NetworkListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}

	for _, net := range networks {
		if net.Name == c.networkName {
			c.networkID = net.ID
			return nil // Network already exists, reuse it
		}
	}

	// Create new network only if it doesn't exist (vtcpd-test-suite pattern)
	networkResponse, err := c.dockerClient.NetworkCreate(c.ctx, c.networkName, types.NetworkCreate{
		CheckDuplicate: true,
		Driver:         "bridge",
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
	return nil
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
		// t.Logf("Cleaning up container %s", containerName)

		// // Stop container gracefully
		// timeout := int(ContainerShutdownTimeout.Seconds())
		// if stopErr := c.dockerClient.ContainerStop(context.Background(), containerID, container.StopOptions{Timeout: &timeout}); stopErr != nil {
		// 	t.Logf("Warning: Failed to stop container %s: %v", containerName, stopErr)
		// }

		// // Remove container
		// if removeErr := c.dockerClient.ContainerRemove(context.Background(), containerID, types.ContainerRemoveOptions{Force: true}); removeErr != nil {
		// 	t.Logf("Warning: Failed to remove container %s: %v", containerName, removeErr)
		// }

		// // Update node state
		// node.IsRunning = false
		// delete(c.nodes, containerName)

		// t.Logf("✓ Container %s cleaned up", containerName)
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
			Test:        []string{"CMD", "pgrep", "-f", "btc-federation"},
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
			Name: "unless-stopped",
		},
	}

	// Network configuration
	networkConfig := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			c.networkName: {
				NetworkID: c.networkID,
			},
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

// ConfigureNetworkConditions applies network conditions to the cluster
// Adapted from vtcpd-test-suite network condition management
func (c *Cluster) ConfigureNetworkConditions(conditions map[string]interface{}) error {
	// Implementation for network conditions (latency, packet loss, etc.)
	// This is a simplified implementation - can be extended for specific network conditions

	if conditions == nil {
		return nil
	}

	// Apply conditions to each running node
	for _, node := range c.nodes {
		if !node.IsRunning {
			continue
		}

		// Example: Apply latency if specified
		if latency, exists := conditions["latency"]; exists {
			if err := c.applyLatency(node, latency); err != nil {
				return fmt.Errorf("failed to apply latency to node %s: %w", node.Config.ContainerName, err)
			}
		}

		// Example: Apply packet loss if specified
		if packetLoss, exists := conditions["packet_loss"]; exists {
			if err := c.applyPacketLoss(node, packetLoss); err != nil {
				return fmt.Errorf("failed to apply packet loss to node %s: %w", node.Config.ContainerName, err)
			}
		}
	}

	return nil
}

// RemoveNetworkConditions removes network conditions from the cluster
// Adapted from vtcpd-test-suite network condition cleanup
func (c *Cluster) RemoveNetworkConditions() error {
	// Remove network conditions from all running nodes
	for _, node := range c.nodes {
		if !node.IsRunning {
			continue
		}

		if err := c.clearNetworkConditions(node); err != nil {
			return fmt.Errorf("failed to clear network conditions for node %s: %w", node.Config.ContainerName, err)
		}
	}

	return nil
}

// applyLatency applies network latency to a node
func (c *Cluster) applyLatency(node *Node, latency interface{}) error {
	// Simplified implementation using tc (traffic control)
	latencyStr, ok := latency.(string)
	if !ok {
		return fmt.Errorf("invalid latency value type")
	}

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", latencyStr}
	return c.execInContainer(node, cmd)
}

// applyPacketLoss applies packet loss to a node
func (c *Cluster) applyPacketLoss(node *Node, packetLoss interface{}) error {
	// Simplified implementation using tc (traffic control)
	lossStr, ok := packetLoss.(string)
	if !ok {
		return fmt.Errorf("invalid packet loss value type")
	}

	cmd := []string{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", lossStr}
	return c.execInContainer(node, cmd)
}

// clearNetworkConditions clears all network conditions from a node
func (c *Cluster) clearNetworkConditions(node *Node) error {
	cmd := []string{"tc", "qdisc", "del", "dev", "eth0", "root"}
	return c.execInContainer(node, cmd)
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

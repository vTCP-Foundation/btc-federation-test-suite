// Package testsuite provides infrastructure for BTC federation node testing
// Adapted from: https://github.com/vTCP-Foundation/vtcpd-test-suite/blob/main/pkg/testsuite/node.go
// Modified for BTC federation node configuration and single binary execution

package testsuite

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
)

// Node configuration constants
const (
	// DefaultPort is the default port for BTC federation nodes
	DefaultPort = 9000
	// DefaultPeerExchangeInterval is the default interval for peer exchange
	DefaultPeerExchangeInterval = "30s"
	// DefaultConnectionTimeout is the default connection timeout
	DefaultConnectionTimeout = "10s"
	// DefaultLogLevel is the default logging level
	DefaultLogLevel = "info"
	// DefaultLogFormat is the default logging format
	DefaultLogFormat = "json"
)

// NodeConfig represents the configuration for a BTC federation node
// Based on vtcpd-test-suite node configuration patterns
type NodeConfig struct {
	// Node configuration
	PrivateKey string `yaml:"private_key"`

	// Network configuration
	IPAddress string   `yaml:"ip_address"`
	Port      int      `yaml:"port"`
	Addresses []string `yaml:"addresses"`

	// Peer configuration
	PeerExchangeInterval string `yaml:"peer_exchange_interval"`
	ConnectionTimeout    string `yaml:"connection_timeout"`

	// Logging configuration
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`

	// Container configuration
	ContainerName string `yaml:"container_name"`
	NetworkName   string `yaml:"network_name"`
	DockerImage   string `yaml:"docker_image"`
}

// Node represents a BTC federation node instance
// Adapted from vtcpd-test-suite Node structure
type Node struct {
	Config      *NodeConfig
	ContainerID string
	IsRunning   bool
}

// NewNode creates a new BTC federation node instance with the given configuration
// Adapted from vtcpd-test-suite NewNode implementation for BTC federation specifics
func NewNode(config *NodeConfig) (*Node, error) {
	if config == nil {
		return nil, fmt.Errorf("node configuration cannot be nil")
	}

	// Validate and set defaults for configuration
	if err := validateAndSetDefaults(config); err != nil {
		return nil, fmt.Errorf("invalid node configuration: %w", err)
	}

	node := &Node{
		Config:    config,
		IsRunning: false,
	}

	return node, nil
}

// validateAndSetDefaults validates the node configuration and sets default values
// Following vtcpd-test-suite validation patterns
func validateAndSetDefaults(config *NodeConfig) error {
	// Generate private key if not provided
	if config.PrivateKey == "" {
		privateKey, err := generatePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		config.PrivateKey = privateKey
	}

	// Set default IP address
	if config.IPAddress == "" {
		config.IPAddress = "0.0.0.0"
	}

	// Validate IP address format
	if net.ParseIP(config.IPAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", config.IPAddress)
	}

	// Set default port
	if config.Port == 0 {
		config.Port = DefaultPort
	}

	// Validate port range
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be between 1 and 65535)", config.Port)
	}

	// Build network addresses if not provided
	if len(config.Addresses) == 0 {
		config.Addresses = []string{
			fmt.Sprintf("/ip4/%s/tcp/%d", config.IPAddress, config.Port),
		}
	}

	// Set peer configuration defaults
	if config.PeerExchangeInterval == "" {
		config.PeerExchangeInterval = DefaultPeerExchangeInterval
	}

	if config.ConnectionTimeout == "" {
		config.ConnectionTimeout = DefaultConnectionTimeout
	}

	// Set logging defaults
	if config.LogLevel == "" {
		config.LogLevel = DefaultLogLevel
	}

	if config.LogFormat == "" {
		config.LogFormat = DefaultLogFormat
	}

	// Set container defaults
	if config.ContainerName == "" {
		config.ContainerName = fmt.Sprintf("btc-federation-node-%d", config.Port)
	}

	if config.NetworkName == "" {
		config.NetworkName = "btc-federation-test-net"
	}

	if config.DockerImage == "" {
		config.DockerImage = "btc-federation-test:ubuntu"
	}

	return nil
}

// generatePrivateKey generates a random private key for testing
// Based on vtcpd-test-suite key generation patterns
func generatePrivateKey() (string, error) {
	// Generate 64 bytes of random data for the private key
	keyBytes := make([]byte, 64)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// Encode as base64 string
	return base64.StdEncoding.EncodeToString(keyBytes), nil
}

// GetEnvironmentVariables returns the environment variables needed for the container
// Following vtcpd-test-suite environment configuration patterns
func (n *Node) GetEnvironmentVariables() []string {
	return []string{
		fmt.Sprintf("PRIVATE_KEY=%s", n.Config.PrivateKey),
		fmt.Sprintf("IP_ADDRESS=%s", n.Config.IPAddress),
		fmt.Sprintf("PORT=%s", strconv.Itoa(n.Config.Port)),
	}
}

// GetPortBindings returns the port bindings for the container
// Adapted from vtcpd-test-suite port configuration
func (n *Node) GetPortBindings() map[string]string {
	portStr := strconv.Itoa(n.Config.Port)
	return map[string]string{
		portStr + "/tcp": portStr,
	}
}

// GetLabels returns the Docker labels for the container
// Following vtcpd-test-suite labeling conventions
func (n *Node) GetLabels() map[string]string {
	return map[string]string{
		"btc-federation-test": "true",
		"node-type":           "btc-federation",
		"node-port":           strconv.Itoa(n.Config.Port),
		"test-suite":          "btc-federation-test-suite",
	}
}

// String returns a string representation of the node
func (n *Node) String() string {
	status := "stopped"
	if n.IsRunning {
		status = "running"
	}
	return fmt.Sprintf("Node[%s:%d, container=%s, status=%s]",
		n.Config.IPAddress, n.Config.Port, n.Config.ContainerName, status)
}

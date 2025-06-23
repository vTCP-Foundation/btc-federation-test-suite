// Package testsuite provides infrastructure for BTC federation node testing
// Adapted from: https://github.com/vTCP-Foundation/vtcpd-test-suite/blob/main/pkg/testsuite/node.go
// Modified for BTC federation node configuration and single binary execution

package testsuite

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
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
	// DefaultConsoleOutput is the default console output setting
	DefaultConsoleOutput = true
	// DefaultConsoleColor is the default console color setting
	DefaultConsoleColor = true
	// DefaultFileOutput is the default file output setting
	DefaultFileOutput = true
	// DefaultFileName is the default log file name
	DefaultFileName = "btc-federation.log"
	// DefaultFileMaxSize is the default log file max size
	DefaultFileMaxSize = "10MB"
)

// PeerConfig represents configuration for a single peer
// Added for task 03-3: Peers configuration support
type PeerConfig struct {
	// PublicKey is the public key of the peer
	PublicKey string `yaml:"public_key"`

	// Addresses is a list of network addresses for the peer
	Addresses []string `yaml:"addresses"`

	// Additional connection parameters
	ConnectionTimeout string `yaml:"connection_timeout,omitempty"`
	MaxRetries        int    `yaml:"max_retries,omitempty"`
}

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

	// Peers configuration - Added for task 03-3
	Peers []PeerConfig `yaml:"peers,omitempty"`

	// Logging configuration
	LogLevel      string `yaml:"log_level"`
	LogFormat     string `yaml:"log_format"`
	ConsoleOutput bool   `yaml:"console_output"`
	ConsoleColor  bool   `yaml:"console_color"`
	FileOutput    bool   `yaml:"file_output"`
	FileName      string `yaml:"file_name"`
	FileMaxSize   string `yaml:"file_max_size"`

	// Container configuration
	ContainerName string `yaml:"container_name"`
	NetworkName   string `yaml:"network_name"`
	DockerImage   string `yaml:"docker_image"`
}

// Node represents a BTC federation node instance
// Adapted from vtcpd-test-suite Node structure
type Node struct {
	Config             *NodeConfig
	ContainerID        string
	IsRunning          bool
	updatedPeersConfig []byte
	needsPeersUpdate   bool
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

	// Set default values for new logging fields
	config.ConsoleOutput = DefaultConsoleOutput
	config.ConsoleColor = DefaultConsoleColor
	config.FileOutput = DefaultFileOutput

	if config.FileName == "" {
		config.FileName = DefaultFileName
	}

	if config.FileMaxSize == "" {
		config.FileMaxSize = DefaultFileMaxSize
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

	// Validate peers configuration - Added for task 03-3
	if err := validatePeersConfig(config.Peers); err != nil {
		return fmt.Errorf("invalid peers configuration: %w", err)
	}

	return nil
}

// validatePeersConfig validates the peers configuration
// Added for task 03-3: Peers configuration validation
func validatePeersConfig(peers []PeerConfig) error {
	for i, peer := range peers {
		// Validate public key
		if peer.PublicKey == "" {
			return fmt.Errorf("peer %d: public key is required", i)
		}

		// Validate addresses
		if len(peer.Addresses) == 0 {
			return fmt.Errorf("peer %d: at least one address is required", i)
		}

		// Validate address formats (basic validation)
		for j, addr := range peer.Addresses {
			if strings.TrimSpace(addr) == "" {
				return fmt.Errorf("peer %d, address %d: address cannot be empty", i, j)
			}
		}

		// Set default connection timeout if not provided
		if peer.ConnectionTimeout == "" {
			peers[i].ConnectionTimeout = DefaultConnectionTimeout
		}

		// Set default max retries if not provided
		if peer.MaxRetries == 0 {
			peers[i].MaxRetries = 3 // Default value
		}
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
// Extended for task 03-3: Added PEERS_YAML_CONTENT support
func (n *Node) GetEnvironmentVariables() []string {
	envVars := []string{
		fmt.Sprintf("PRIVATE_KEY=%s", n.Config.PrivateKey),
		fmt.Sprintf("IP_ADDRESS=%s", n.Config.IPAddress),
		fmt.Sprintf("PORT=%s", strconv.Itoa(n.Config.Port)),
		fmt.Sprintf("LOGGING_FILE_NAME=%s", n.Config.FileName),
		fmt.Sprintf("LOGGING_FILE_MAX_SIZE=%s", n.Config.FileMaxSize),
	}

	// Add peers configuration if available - Added for task 03-3
	if len(n.Config.Peers) > 0 {
		peersYAML, err := n.generatePeersYAMLContent()
		if err == nil && peersYAML != "" {
			envVars = append(envVars, fmt.Sprintf("PEERS_YAML_CONTENT=%s", peersYAML))
		}
	}

	return envVars
}

// generatePeersYAMLContent generates YAML content for peers configuration
// Added for task 03-3: Peers YAML generation for environment variables
func (n *Node) generatePeersYAMLContent() (string, error) {
	if len(n.Config.Peers) == 0 {
		return "", nil
	}

	// Create a map structure for YAML generation
	peersData := map[string]interface{}{
		"peers": n.Config.Peers,
	}

	// Convert to YAML
	yamlData, err := yaml.Marshal(peersData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal peers to YAML: %w", err)
	}

	return string(yamlData), nil
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

// CheckLogContains searches for a specific pattern in the node's log file
// Added for task 03-2: Log analysis capability for P2P connection verification
func (n *Node) CheckLogContains(pattern string) (bool, error) {
	if !n.IsRunning {
		return false, fmt.Errorf("node is not running")
	}

	// This method requires cluster context for container access
	// In practice, this method would be called through the cluster
	return false, fmt.Errorf("method must be called through cluster reference - use cluster.CheckNodeLogContains instead")
}

// GetPeersConfig retrieves the peers configuration from the peers.yaml file
// Added for task 03-2: Peers configuration access for testing validation
func (n *Node) GetPeersConfig() (map[string]interface{}, error) {
	if !n.IsRunning {
		return nil, fmt.Errorf("node is not running")
	}

	// This method requires cluster context for container access
	// In practice, this would be called through cluster methods
	return nil, fmt.Errorf("method must be called through cluster reference - use cluster.GetNodePeersConfig instead")
}

// Helper method to be used by cluster for log analysis
// This approach maintains separation of concerns while enabling testing
func (n *Node) getLogFilePath() string {
	return fmt.Sprintf("/btc-federation/%s", n.Config.FileName)
}

// Helper method to get peers config file path
func (n *Node) getPeersConfigPath() string {
	return "/btc-federation/peers.yaml"
}

// UpdatePeersConfig updates the peers.yaml file in the running container
// This method regenerates the peers configuration and writes it to the container
func (n *Node) UpdatePeersConfig() error {
	if !n.IsRunning {
		return fmt.Errorf("node %s is not running", n.Config.ContainerName)
	}

	// Generate peers configuration using the same format as generatePeersYAMLContent
	peersData := map[string]interface{}{
		"peers": n.Config.Peers,
	}

	// Convert to YAML
	yamlData, err := yaml.Marshal(peersData)
	if err != nil {
		return fmt.Errorf("failed to marshal peers config to YAML: %w", err)
	}

	// Write the file to the container filesystem
	// We need access to the cluster's docker client, so we'll use a different approach
	// Create a temporary file and copy it to the container
	tempFile, err := os.CreateTemp("", "peers-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Write YAML data to temporary file
	if _, err := tempFile.Write(yamlData); err != nil {
		return fmt.Errorf("failed to write YAML data to temporary file: %w", err)
	}

	// Close the file so it can be copied
	tempFile.Close()

	// We need the cluster instance to copy the file, but we don't have it here
	// So we'll store the config in the node and let the cluster handle the copy
	n.updatedPeersConfig = yamlData
	n.needsPeersUpdate = true

	return nil
}

// Helper method to check if peers config needs update
func (n *Node) NeedsPeersUpdate() bool {
	return n.needsPeersUpdate
}

// Helper method to get updated peers config data
func (n *Node) GetUpdatedPeersConfig() []byte {
	return n.updatedPeersConfig
}

// Helper method to mark peers config as updated
func (n *Node) MarkPeersUpdated() {
	n.needsPeersUpdate = false
	n.updatedPeersConfig = nil
}

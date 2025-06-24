// Package conf provides configuration scenario generators for testing
// Task 05-1: Test Infrastructure Setup - Configuration Scenario Builders
// Simplified to only generate NodeConfig instances for cluster/node-based testing

package conf

import (
	"btc-federation-test-suite/pkg/testsuite"
)

// Configuration scenario constants
const (
	// Valid test private key for consistent testing
	TestPrivateKey = "5OFXNqsWjmN97iEEERn8jgchOL9QaRzbg/H0FIqgccYRD/3qJ4Zxf0dmDsmdxMqrT/SJkDRrhfAbPel9UFsl2w=="

	// Test network addresses
	TestAddress = "/ip4/0.0.0.0/tcp/9000"

	// Test timeout values
	TestConnectionTimeout = "10s"

	// Test logging values
	TestLogLevel    = "info"
	TestLogFormat   = "json"
	TestLogFileName = "btc-federation.log"
	TestLogMaxSize  = "10MB"

	// Invalid values for testing
	InvalidPrivateKey = "invalid-private-key"
	InvalidTimeout    = "invalid-timeout"
	InvalidLogLevel   = "invalid-level"
	InvalidLogFormat  = "invalid-format"
	InvalidLogMaxSize = "invalid-size"
)

// ConfigScenarios provides methods for generating various configuration scenarios
type ConfigScenarios struct{}

// NewConfigScenarios creates a new configuration scenarios generator
func NewConfigScenarios() *ConfigScenarios {
	return &ConfigScenarios{}
}

// Success scenarios (exit code 0)

// CreateNodeConfigForMissingConfigFile creates NodeConfig for scenario 1: Missing conf.yaml
func (s *ConfigScenarios) CreateNodeConfigForMissingConfigFile() *testsuite.NodeConfig {
	// For missing config file, we provide minimal valid configuration
	// This should trigger default config generation and succeed
	return &testsuite.NodeConfig{
		// Don't set PrivateKey - let the system generate default
		IPAddress: "0.0.0.0",
		Port:      9001, // Use different port to avoid conflicts
		LogLevel:  "info",
		LogFormat: "json",
	}
}

// CreateNodeConfigForMissingPrivateKey creates NodeConfig for scenario 4: Missing private_key
func (s *ConfigScenarios) CreateNodeConfigForMissingPrivateKey() *testsuite.NodeConfig {
	// Missing private key should trigger key generation (success scenario)
	return &testsuite.NodeConfig{
		// Don't set PrivateKey - should trigger generation
		IPAddress: "0.0.0.0",
		Port:      9002, // Use different port to avoid conflicts
		LogLevel:  "info",
		LogFormat: "json",
	}
}

// Error scenarios (exit code 1)

// CreateNodeConfigForEmptyConfigFile creates NodeConfig for scenario 2: Empty conf.yaml
func (s *ConfigScenarios) CreateNodeConfigForEmptyConfigFile() *testsuite.NodeConfig {
	// For empty config file scenario, we provide invalid/empty values
	return &testsuite.NodeConfig{
		PrivateKey: "", // Empty private key should cause error
		IPAddress:  "", // Empty IP should cause error
		Port:       0,  // Invalid port should cause error
	}
}

// CreateNodeConfigForMalformedConfigFile creates NodeConfig for scenario 3: Malformed YAML
func (s *ConfigScenarios) CreateNodeConfigForMalformedConfigFile() *testsuite.NodeConfig {
	// For malformed YAML, we use values that break validation
	return &testsuite.NodeConfig{
		PrivateKey: "invalid-yaml-characters: [}malformed{",
		IPAddress:  "invalid-ip-format",
		Port:       -1, // Invalid port
	}
}

// CreateNodeConfigForInvalidPrivateKey creates NodeConfig for scenario 5: Invalid private_key
func (s *ConfigScenarios) CreateNodeConfigForInvalidPrivateKey() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: InvalidPrivateKey, // Use invalid private key
		IPAddress:  "0.0.0.0",
		Port:       9000,
		LogLevel:   "info",
		LogFormat:  "json",
	}
}

// CreateNodeConfigForMissingNetwork creates NodeConfig for scenario 6: Missing network section
func (s *ConfigScenarios) CreateNodeConfigForMissingNetwork() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		// Don't set IPAddress and Port - should cause error
		LogLevel:  "info",
		LogFormat: "json",
	}
}

// CreateNodeConfigForMissingAddresses creates NodeConfig for scenario 7: Missing network.addresses
func (s *ConfigScenarios) CreateNodeConfigForMissingAddresses() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "", // Empty IP should cause missing addresses
		Port:       9000,
		LogLevel:   "info",
		LogFormat:  "json",
	}
}

// CreateNodeConfigForEmptyAddresses creates NodeConfig for scenario 8: Empty network.addresses
func (s *ConfigScenarios) CreateNodeConfigForEmptyAddresses() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       0, // Invalid port creates empty addresses
		LogLevel:   "info",
		LogFormat:  "json",
	}
}

// CreateNodeConfigForInvalidAddress creates NodeConfig for scenario 9: Invalid address format
func (s *ConfigScenarios) CreateNodeConfigForInvalidAddress() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "999.999.999.999", // Invalid IP format
		Port:       9000,
		LogLevel:   "info",
		LogFormat:  "json",
	}
}

// CreateNodeConfigForMissingPeers creates NodeConfig for scenario 10: Missing peers section
func (s *ConfigScenarios) CreateNodeConfigForMissingPeers() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       9000,
		// Don't set Peers - should use defaults (success)
		LogLevel:  "info",
		LogFormat: "json",
	}
}

// CreateNodeConfigForMissingConnectionTimeout creates NodeConfig for scenario 11: Missing connection timeout
func (s *ConfigScenarios) CreateNodeConfigForMissingConnectionTimeout() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       9000,
		// Don't set ConnectionTimeout - should use defaults (success)
		LogLevel:  "info",
		LogFormat: "json",
	}
}

// CreateNodeConfigForInvalidConnectionTimeout creates NodeConfig for scenario 12: Invalid connection timeout
func (s *ConfigScenarios) CreateNodeConfigForInvalidConnectionTimeout() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey:        TestPrivateKey,
		IPAddress:         "0.0.0.0",
		Port:              9000,
		ConnectionTimeout: "invalid-timeout-format", // Invalid timeout format
		LogLevel:          "info",
		LogFormat:         "json",
	}
}

// CreateNodeConfigForMissingLogging creates NodeConfig for scenario 13: Missing logging section
func (s *ConfigScenarios) CreateNodeConfigForMissingLogging() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       9000,
		// Don't set logging fields - should use defaults (success)
	}
}

// CreateNodeConfigForInvalidLogLevel creates NodeConfig for scenario 14: Invalid log level
func (s *ConfigScenarios) CreateNodeConfigForInvalidLogLevel() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       9000,
		LogLevel:   "invalid-log-level", // Invalid log level
		LogFormat:  "json",
	}
}

// CreateNodeConfigForInvalidLogFormat creates NodeConfig for scenario 15: Invalid log format
func (s *ConfigScenarios) CreateNodeConfigForInvalidLogFormat() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       9000,
		LogLevel:   "info",
		LogFormat:  "invalid-log-format", // Invalid log format
	}
}

// CreateNodeConfigForInvalidConsoleOutput creates NodeConfig for scenario 16: Invalid console output
func (s *ConfigScenarios) CreateNodeConfigForInvalidConsoleOutput() *testsuite.NodeConfig {
	// Since ConsoleOutput is bool, we need to simulate invalid value differently
	// We'll use a complex scenario with other invalid fields
	return &testsuite.NodeConfig{
		PrivateKey:    TestPrivateKey,
		IPAddress:     "0.0.0.0",
		Port:          9000,
		LogLevel:      "info",
		LogFormat:     "json",
		ConsoleOutput: true,                  // Valid bool, but we'll add invalid filename
		FileName:      "",                    // Empty filename should cause error
		FileMaxSize:   "invalid-size-format", // Invalid size format
	}
}

// CreateNodeConfigForInvalidFileMaxSize creates NodeConfig for scenario 17: Invalid file max size
func (s *ConfigScenarios) CreateNodeConfigForInvalidFileMaxSize() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey:  TestPrivateKey,
		IPAddress:   "0.0.0.0",
		Port:        9000,
		LogLevel:    "info",
		LogFormat:   "json",
		FileName:    "test.log",
		FileMaxSize: "invalid-size-format", // Invalid size format
	}
}

// CreateNodeConfigForInvalidPort creates NodeConfig for scenario 18: Invalid port number
func (s *ConfigScenarios) CreateNodeConfigForInvalidPort() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey: TestPrivateKey,
		IPAddress:  "0.0.0.0",
		Port:       70000, // Port out of valid range (1-65535)
		LogLevel:   "info",
		LogFormat:  "json",
	}
}

// CreateNodeConfigForMixedValidInvalid creates NodeConfig for scenario 19: Mixed valid/invalid sections
func (s *ConfigScenarios) CreateNodeConfigForMixedValidInvalid() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey:        TestPrivateKey,    // Valid
		IPAddress:         "999.999.999.999", // Invalid IP
		Port:              9000,              // Valid
		ConnectionTimeout: "invalid-timeout", // Invalid timeout
		LogLevel:          "info",            // Valid
		LogFormat:         "invalid-format",  // Invalid format
		FileName:          "test.log",        // Valid
		FileMaxSize:       "invalid-size",    // Invalid size
	}
}

// CreateNodeConfigForCompletelyInvalid creates NodeConfig for scenario 20: Completely invalid configuration
func (s *ConfigScenarios) CreateNodeConfigForCompletelyInvalid() *testsuite.NodeConfig {
	return &testsuite.NodeConfig{
		PrivateKey:        "invalid-key",     // Invalid private key
		IPAddress:         "invalid-ip",      // Invalid IP
		Port:              -1,                // Invalid port
		ConnectionTimeout: "invalid-timeout", // Invalid timeout
		LogLevel:          "invalid-level",   // Invalid log level
		LogFormat:         "invalid-format",  // Invalid log format
		FileName:          "",                // Empty filename
		FileMaxSize:       "invalid-size",    // Invalid size
	}
}

// ========================================
// Peers.yaml Validation Scenarios
// Task 05-3: peers.yaml Validation Tests
// ========================================

// CreateNodeConfigForMissingPeersFile creates NodeConfig for scenario 1: Missing peers.yaml
// This should result in standalone mode (success scenario with exit code 0)
func (s *ConfigScenarios) CreateNodeConfigForMissingPeersFile() *testsuite.NodeConfig {
	// For missing peers.yaml, provide valid base configuration
	// The system should start successfully without peers.yaml and log standalone mode
	return &testsuite.NodeConfig{
		PrivateKey:    TestPrivateKey, // Use valid private key
		IPAddress:     "0.0.0.0",
		Port:          9100, // Use high port range to avoid conflicts
		LogLevel:      TestLogLevel,
		LogFormat:     TestLogFormat,
		ConsoleOutput: true,
		// Don't set Peers - should trigger standalone mode (success)
	}
}

// CreateNodeConfigForEmptyPeersFile creates NodeConfig for scenario 2: Empty peers.yaml file
// This should result in a validation error (exit code 1)
func (s *ConfigScenarios) CreateNodeConfigForEmptyPeersFile() *testsuite.NodeConfig {
	// For empty peers.yaml file scenario, we create a configuration that should cause
	// the system to expect peers.yaml but find it empty
	return &testsuite.NodeConfig{
		PrivateKey:    TestPrivateKey, // Valid private key
		IPAddress:     "0.0.0.0",
		Port:          9101, // Use high port range to avoid conflicts
		LogLevel:      TestLogLevel,
		LogFormat:     TestLogFormat,
		ConsoleOutput: true,
		// Simulate empty peers.yaml by providing invalid/empty peer configuration
		Peers: []testsuite.PeerConfig{}, // Empty but present - should cause parsing error
	}
}

// CreateNodeConfigForEmptyPeersValue creates NodeConfig for scenario 3: Empty peers value
// This should result in standalone mode (success scenario with exit code 0)
func (s *ConfigScenarios) CreateNodeConfigForEmptyPeersValue() *testsuite.NodeConfig {
	// For empty peers value scenario (peers: [] or peers:), provide valid base config
	// This should start successfully and log standalone mode message
	return &testsuite.NodeConfig{
		PrivateKey:    TestPrivateKey, // Use valid private key
		IPAddress:     "0.0.0.0",
		Port:          9102, // Use high port range to avoid conflicts
		LogLevel:      TestLogLevel,
		LogFormat:     TestLogFormat,
		ConsoleOutput: true,
		// Empty peers slice should trigger standalone mode (success)
		Peers: []testsuite.PeerConfig{}, // Explicitly set empty peers
	}
}

package config

// Config holds the configuration for the Trayce Agent
type Config struct {
	BtfFilePath string
	LibSslPath  string
	FilterCmd   string
	Verbose     bool
}

// NewConfig creates a new Config instance
func NewConfig(btfFilePath, libSslPath, filterCmd string, verbose bool) Config {
	return Config{
		BtfFilePath: btfFilePath,
		LibSslPath:  libSslPath,
		FilterCmd:   filterCmd,
		Verbose:     verbose,
	}
}

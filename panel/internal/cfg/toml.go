// TOML (de)serialization for panel.toml.
package cfg

import (
	toml "github.com/pelletier/go-toml/v2"
)

func parse(raw []byte) (*Config, error) {
	c := &Config{}
	if err := toml.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	return c, nil
}

func render(c *Config) ([]byte, error) {
	// Marshal deterministic struct output; panel.toml is small and only
	// ever read back by this same binary.
	return toml.Marshal(c)
}

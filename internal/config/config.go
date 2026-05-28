package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

const (
	appDirName     = ".phoneaccess"
	configFileName = "config.yaml"
)

type Config struct {
	APIKeys map[string]string `yaml:"api_keys" json:"api_keys"`
}

type Store struct {
	path string
}

func NewDefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("find home directory: %w", err)
	}
	return &Store{path: filepath.Join(home, appDirName, configFileName)}, nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Load() (*Config, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{APIKeys: map[string]string{}}, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.APIKeys == nil {
		cfg.APIKeys = map[string]string{}
	}
	return cfg, nil
}

func (s *Store) Save(cfg *Config) error {
	if cfg.APIKeys == nil {
		cfg.APIKeys = map[string]string{}
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func (s *Store) ListKeys() ([]string, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(cfg.APIKeys))
	for key := range cfg.APIKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *Store) SetKey(key, value string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	cfg.APIKeys[key] = value
	return s.Save(cfg)
}

func (s *Store) UnsetKey(key string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	delete(cfg.APIKeys, key)
	return s.Save(cfg)
}

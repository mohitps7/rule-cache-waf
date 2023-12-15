package main

import (
	"encoding/json"
	"os"
)

type WAFConfig struct {
	OriginURL        string   `json:"origin_url"`
	Rules            []Rule   `json:"rules"`
	BlockedSubnets   []string `json:"blocked_subnets"`
	ValidHeaders     []string `json:"valid_headers"`
	CertFileLocation string   `json:"cert_file_location"`
	KeyFileLocation  string   `json:"key_file_location"`
}

func LoadConfig(filename string) (*WAFConfig, error) {
	var config WAFConfig

	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

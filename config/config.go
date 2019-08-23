package config

import (
	"os"
	"path/filepath"

	log "github.com/inconshreveable/log15"
	"github.com/spf13/viper"
)

// Config contains the config.yml settings
type Config struct {
	DatabaseAddresses  string
	DatabaseUsername   string
	DatabseUserPassord string
	Database           string
}

// Env contains the environment variables
type Env struct {
	Environment      string
	DatabasePassword string
	ProjectRootPath  string
}

// GetEnvVariables gets the environment variables and returns a new env struct
func GetEnvVariables() *Env {
	viper.AutomaticEnv()
	viper.SetDefault("go_env", "development")
	viper.SetDefault("database_password", "")

	// Get the current environment
	environment := viper.GetString("go_env")

	log.Info("Initializing", "ENVIROMENT", environment)

	// Get the enviroment variables
	log.Info("Obtaining env variables")
	databasePassword := viper.GetString("database_password")

	env := &Env{
		Environment:      environment,
		DatabasePassword: databasePassword,
		// Secret:      secret,
	}

	return env
}

// GetConfig reads the configuration file and returns a new config
func GetConfig(env Env) *Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath(env.ProjectRootPath)

	log.Info("Reading config file")
	err := viper.ReadInConfig()
	if err != nil {
		log.Error("Missing configuration file.", "Error:", err)
		os.Exit(1)
	}

	var config Config

	err = viper.UnmarshalKey(env.Environment, &config)
	if err != nil {
		panic("Unable to unmarshal config")
	}

	return &config
}

// GetTestingEnvVariables returns env variables for testing
func GetTestingEnvVariables() *Env {

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	// Since we are loading configuration files from the root dir, when running from main package
	// this is fine but for testing we need to find the root dir
	dir := filepath.Dir(wd)

	for dir[len(dir)-24:] != "gopg-casbin-adapter" {
		dir = filepath.Dir(dir)
	}

	return &Env{Environment: "test", ProjectRootPath: dir}
}

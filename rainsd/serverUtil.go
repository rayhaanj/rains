package rainsd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strconv"
	"time"
)

const (
	configPath = "config/server.conf"
)

type rainsdConfig struct {
	ServerIPAddr    string
	ServerPort      uint16
	MaxConnections  uint
	KeepAlivePeriod time.Duration
	TCPTimeout      time.Duration

	CertificateFile string
	PrivateKeyFile  string
}

//ProtocolType enumerates protocol types
type ProtocolType int

const (
	TCP ProtocolType = iota
)

//ConnInfo contains address information about one actor of a connection of the declared type
//type 1 contains IPAddr and Port information
type ConnInfo struct {
	Type   ProtocolType
	IPAddr string
	Port   uint16
}

//IPAddrAndPort returns IP address and port in the format IPAddr:Port
func (c ConnInfo) IPAddrAndPort() string {
	return c.IPAddr + ":" + c.PortToString()
}

//PortToString return the port number as a string
func (c ConnInfo) PortToString() string {
	return strconv.Itoa(int(c.Port))
}

//Config contains configurations for this server
var Config rainsdConfig

//load config and stores it into global variable config
func loadConfig() {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal("Could not open config file...", "path", configPath, "error", err)
	}
	json.Unmarshal(file, &Config)
}

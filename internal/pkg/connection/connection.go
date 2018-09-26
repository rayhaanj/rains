package connection

import (
	"fmt"
	"net"

	log "github.com/inconshreveable/log15"
)

//Info contains address information about one actor of a connection of the declared type
type Info struct {
	//Type determines the network address type
	Type Type

	TCPAddr *net.TCPAddr
}

//String returns the string representation of the connection information according to its type
func (c Info) String() string {
	switch c.Type {
	case TCP:
		return c.TCPAddr.String()
	default:
		log.Warn("Unsupported network address", "typeCode", c.Type)
		return ""
	}
}

//NetworkAndAddr returns the network name and addr of the connection separated by space
func (c Info) NetworkAndAddr() string {
	switch c.Type {
	case TCP:
		return fmt.Sprintf("%s %s", c.TCPAddr.Network(), c.String())
	default:
		log.Warn("Unsupported network address type", "type", c.Type)
		return ""
	}
}

//Hash returns a string containing all information uniquely identifying a Info.
func (c Info) Hash() string {
	return fmt.Sprintf("%v_%s", c.Type, c.String())
}

//Equal returns true if both Connection Information have the same existing type and the values corresponding to this type are identical.
func (c Info) Equal(conn Info) bool {
	if c.Type == conn.Type {
		switch c.Type {
		case TCP:
			return c.TCPAddr.IP.Equal(conn.TCPAddr.IP) && c.TCPAddr.Port == conn.TCPAddr.Port && c.TCPAddr.Zone == conn.TCPAddr.Zone
		default:
			log.Warn("Not supported network address type")
		}
	}
	return false
}

//Type enumerates connection types
type Type int

//run 'go generate' in this directory if a new networkAddrType is added [source https://github.com/campoy/jsonenums]
//go:generate jsonenums -type=Type
const (
	TCP Type = iota + 1
)

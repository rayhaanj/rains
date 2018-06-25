//The switchboard handles incoming connections from servers and clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/cbor"
	"github.com/netsec-ethz/rains/utils/protoParser"
)

//sendTo sends message to the specified receiver.
func sendTo(message rainslib.RainsMessage, receiver rainslib.ConnInfo, retries, backoffMilliSeconds int) error {
	var err error

	log.Debug(fmt.Sprintf("called SendTo with message: %v", message))
	conns, ok := connCache.GetConnection(receiver)
	if !ok {
		conn, err := createConnection(receiver)
		//add connection to cache
		conns = append(conns, conn)
		if err != nil {
			log.Warn("Could not establish connection", "error", err, "receiver", receiver)
			return err
		}
		connCache.AddConnection(conn)
		//handle connection
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			go handleConnection(conn, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr})
		} else {
			log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
		}
		//add capabilities to message
		message.Capabilities = []rainslib.Capability{rainslib.Capability(capabilityHash)}
	}

	for _, conn := range conns {
		writer := borat.NewCBORWriter(conn)
		if err := cbor.ConfigureWriter(writer); err != nil {
			return fmt.Errorf("failed to configure CBOR writer: %v", err)
		}
		if err = writer.Marshal(&message); err != nil {
			log.Warn(fmt.Sprintf("failed to marshal message to conn: %v", err))
			continue
		}
		glog.Infof("sent response to peer: %v", conn.RemoteAddr())
		return nil
	}

	if retries > 0 {
		time.Sleep(time.Duration(backoffMilliSeconds) * time.Millisecond)
		return sendTo(message, receiver, retries-1, 2*backoffMilliSeconds)
	}
	log.Error("Was not able to send the message. No retries left.", "receiver", receiver)
	return errors.New("Was not able to send the mesage. No retries left")
}

//createConnection establishes a connection with receiver
func createConnection(receiver rainslib.ConnInfo) (net.Conn, error) {
	switch receiver.Type {
	case rainslib.TCP:
		dialer := &net.Dialer{
			KeepAlive: Config.KeepAlivePeriod,
		}
		return tls.DialWithDialer(dialer, receiver.TCPAddr.Network(), receiver.String(), &tls.Config{RootCAs: roots, InsecureSkipVerify: true})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//Listen listens for incoming connections and creates a go routine for each connection.
func Listen() {
	srvLogger := log.New("addr", serverConnInfo.String())
	glog.Infof("Starting listen in rainsd library")
	switch serverConnInfo.Type {
	case rainslib.TCP:
		srvLogger.Info("Start TCP listener")
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		listener, err := tls.Listen(serverConnInfo.TCPAddr.Network(), serverConnInfo.String(), tlsConfig)
		if err != nil {
			srvLogger.Error("Listener error on startup", "error", err)
			return
		}
		defer listener.Close()
		defer srvLogger.Info("Shutdown listener")
		for {
			conn, err := listener.Accept()
			if err != nil {
				srvLogger.Error("listener could not accept connection", "error", err)
				continue
			}
			if isIPBlacklisted(conn.RemoteAddr()) {
				continue
			}
			connCache.AddConnection(conn)
			go handleConnCBOR(conn)
		}
	default:
		log.Warn("Unsupported Network address type.")
	}
}

func handleConnCBOR(conn net.Conn) {
	var msg rainslib.RainsMessage
	reader := borat.NewCBORReader(conn)
	if err := cbor.ConfigureReader(reader); err != nil {
		log.Warn(fmt.Sprintf("failed to configure reader to read from client: %v", err))
	}
	for {
		log.Info("waiting for input from client") // TODO: delete after testing.
		if err := reader.Unmarshal(&msg); err != nil {
			log.Warn(fmt.Sprintf("failed to read from client: %v", err))
			break
		}
		fmt.Printf("received message: %+v\n", msg)
		deliverCBOR(&msg, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: conn.RemoteAddr().(*net.TCPAddr)})
	}
	connCache.CloseAndRemoveConnection(conn)
}

//handleConnection deframes all incoming messages on conn and passes them to the inbox along with the dstAddr
func handleConnection(conn net.Conn, dstAddr rainslib.ConnInfo) {
	var framer rainslib.MsgFramer
	framer = new(protoParser.ProtoParserAndFramer)
	framer.InitStreams(conn, nil)
	for framer.DeFrame() {
		log.Info("Received a message", "sender", dstAddr)
		deliver(framer.Data(), dstAddr)
		conn.SetDeadline(time.Now().Add(Config.TCPTimeout))
	}
	connCache.CloseAndRemoveConnection(conn)
	log.Debug("connection removed from cache", "remoteAddr", conn.RemoteAddr())
}

//isIPBlacklisted returns true if addr is blacklisted
func isIPBlacklisted(addr net.Addr) bool {
	log.Warn("TODO CFE ip blacklist not yet implemented")
	return false
}

package publisher

import (
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"

	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/spath"
)

func setupPath(local, remote *snet.Addr) error {
	if !remote.IA.Eq(local.IA) {
		pathEntry := choosePath(local, remote)
		if pathEntry == nil {
			return fmt.Errorf("failed to find path from %s to %s", local, remote)
		}
		remote.Path = spath.New(pathEntry.Path.FwdPath)
		remote.Path.InitOffsets()
		remote.NextHop, _ = pathEntry.HostInfo.Overlay()
	}
	return nil
}

func choosePath(local, remote *snet.Addr) *sd.PathReplyEntry {
	var paths []*sd.PathReplyEntry
	var pathIndex uint64
	pathMan := snet.DefNetwork.PathResolver()
	pathSet := pathMan.Query(local.IA, remote.IA)
	if len(pathSet) == 0 {
		return nil
	}
	for _, p := range pathSet {
		paths = append(paths, p.Entry)
	}
	// TODO: Insert any path choosing logic here.
	return paths[pathIndex]
}

//connectAndSendMsg establishes a connection to server and sends msg. It returns the server info on
//the result channel if it was not able to send the whole msg to it, else nil.
func connectAndSendMsg(msg message.Message, localAddr *snet.Addr, server connection.Info, result chan<- *connection.Info) {
	//TODO CFE use certificate for tls
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	switch server.Type {
	case connection.SCION:
		setupPath(localAddr, server.SCIONAddr)
		qsess, err := squic.DialSCION(nil, localAddr, server.SCIONAddr)
		if err != nil {
			log.Error("Was not able to DialSCION", "error", err)
			result <- &server
			return
		}
		defer qsess.Close()
		qstr, err := qsess.OpenStreamSync()
		if err != nil {
			log.Error("failed to OpenStreamSync", "error", err)
			result <- &server
			return
		}
		success := make(chan bool)
		go listen(qstr, msg.Token, success)
		writer := cbor.NewWriter(qstr)
		if err := writer.Marshal(&msg); err != nil {
			log.Error("failed to write CBOR to stream", "error", err)
			result <- &server
			return
		}
		if <-success {
			log.Debug("Successfully published message", "msg", msg)
			result <- nil
		} else {
			result <- &server
		}
	case connection.TCP:
		conn, err := tls.Dial(server.TCPAddr.Network(), server.String(), conf)
		if err != nil {
			log.Error("Was not able to establish a connection.", "server", server, "error", err)
			result <- &server
			return
		}
		success := make(chan bool)
		go listen(conn, msg.Token, success)
		writer := cbor.NewWriter(conn)
		if err := writer.Marshal(&msg); err != nil {
			conn.Close()
			log.Error("Was not able to frame the message.", "msg", msg, "server", server, "error", err)
			result <- &server
			return
		}

		if <-success {
			log.Debug("Successful published information.", "serverAddresses", server.String())
			result <- nil
		} else {
			result <- &server
		}
	default:
		log.Error("Unsupported connection information type.", "connType", server.Type)
		result <- &server
	}
}

//listen receives incoming messages for one second. If the message's token matches the query's
//token, it handles the response.
func listen(conn io.ReadCloser, token token.Token, success chan<- bool) {
	//close connection after 1 second assuming everything went well
	deadline := make(chan bool)
	result := make(chan bool)
	go func() {
		time.Sleep(time.Second)
		deadline <- true
	}()
	go waitForResponse(conn, token, result)
	for true {
		select {
		case <-deadline:
			conn.Close()
			success <- true
			return
		case err := <-result:
			if err {
				success <- false
			} else {
				go waitForResponse(conn, token, result)
			}
		}
	}
}

func waitForResponse(conn io.ReadCloser, token token.Token, serverError chan<- bool) {
	reader := cbor.NewReader(conn)
	var msg message.Message
	if err := reader.Unmarshal(&msg); err != nil {
		errs := strings.Split(err.Error(), ": ")
		if errs[len(errs)-1] == "use of closed network connection" {
			log.Info("Connection has been closed", "conn", conn)
		} else {
			log.Warn("Was not able to decode received message", "error", err)
		}
		serverError <- false
		return
	}
	//Rainspub only accepts notification messages in response to published information.
	if n, ok := msg.Content[0].(*section.Notification); ok && n.Token == token {
		if handleResponse(msg.Content[0].(*section.Notification)) {
			conn.Close()
			serverError <- true
			return
		}
		serverError <- false
		return
	}
	//TODO CFE do we need the token?
	log.Debug("Token of sent message does not match the token of the received message",
		"messageToken", token, "recvToken", msg.Token)
}

//handleResponse handles the received notification message and returns true if the connection can
//be closed.
func handleResponse(n *section.Notification) bool {
	switch n.Type {
	case section.NTHeartbeat, section.NTNoAssertionsExist, section.NTNoAssertionAvail:
	//nop
	case section.NTCapHashNotKnown:
	//TODO CFE send back the whole capability list in an empty message
	case section.NTBadMessage:
		log.Error("Sent msg was malformed", "data", n.Data)
	case section.NTRcvInconsistentMsg:
		log.Error("Sent msg was inconsistent", "data", n.Data)
	case section.NTMsgTooLarge:
		log.Error("Sent msg was too large", "data", n.Data)
		//What should we do in this case. apparently it is not possible to send a zone because
		//it is too large. send shards instead?
	case section.NTUnspecServerErr:
		log.Error("Unspecified error of other server", "data", n.Data)
		//TODO CFE resend?
	case section.NTServerNotCapable:
		log.Error("Other server was not capable", "data", n.Data)
		//TODO CFE when can this occur?
	default:
		log.Error("Received non existing notification type")
	}
	return false
}

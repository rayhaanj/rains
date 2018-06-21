package rainsd

import (
	"fmt"
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
)

//incoming messages are buffered in one of these channels until they get processed by a worker go routine
//the prioChannel only contains incoming sections in response to a delegation query issued by this server.
var prioChannel chan msgSectionSender
var normalChannel chan msgSectionSender
var notificationChannel chan msgSectionSender

//These channels limit the number of go routines working on the different queues to avoid memory exhaustion.
var prioWorkers chan struct{}
var normalWorkers chan struct{}
var notificationWorkers chan struct{}

func initQueuesAndWorkers(done chan bool) error {
	//init Channels
	prioChannel = make(chan msgSectionSender, Config.PrioBufferSize)
	normalChannel = make(chan msgSectionSender, Config.NormalBufferSize)
	notificationChannel = make(chan msgSectionSender, Config.NotificationBufferSize)

	//init max amount of concurrent workers
	prioWorkers = make(chan struct{}, Config.PrioWorkerCount)
	normalWorkers = make(chan struct{}, Config.NormalWorkerCount)
	notificationWorkers = make(chan struct{}, Config.NotificationWorkerCount)

	go workPrio(done)
	go workNotification()
	go workBoth(done)
	return nil
}

func deliverCBOR(msg *rainslib.RainsMessage, sender rainslib.ConnInfo) {
	// TODO: Check length of message.
	processCapability(msg.Capabilities, sender, msg.Token)

	//handle message content
	for _, m := range msg.Content {
		switch m := m.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
			if !isZoneBlacklisted(m.(rainslib.MessageSectionWithSig).GetSubjectZone()) {
				addMsgSectionToQueue(m, msg.Token, sender)
			}
		case *rainslib.QuerySection, *rainslib.AddressQuerySection:
			log.Debug(fmt.Sprintf("add %T to normal queue", m))
			normalChannel <- msgSectionSender{Sender: sender, Section: m, Token: msg.Token}
		case *rainslib.NotificationSection:
			log.Debug("Add notification to notification queue", "token", msg.Token)
			notificationChannel <- msgSectionSender{Sender: sender, Section: m, Token: msg.Token}
		default:
			log.Warn(fmt.Sprintf("unsupported message section type %T", m))
			return
		}
	}
}

//deliver pushes all incoming messages to the prio or normal channel.
//A message is added to the priority channel if it is the response to a non-expired delegation query
func deliver(message []byte, sender rainslib.ConnInfo) {
	//check message length
	if uint(len(message)) > Config.MaxMsgByteLength {
		token, _ := msgParser.Token(message)
		sendNotificationMsg(token, sender, rainslib.NTMsgTooLarge, "")
		return
	}
	msg, err := msgParser.Decode(message)
	if err != nil {
		sendNotificationMsg(msg.Token, sender, rainslib.NTBadMessage, "")
		return
	}
	log.Debug("Parsed Message", "msg", msg)

	//TODO CFE get infrastructure key from cache and if not present send a infra query, add a new cache for whole messages to wait for missing public keys
	if !rainsSiglib.CheckMessageSignatures(&msg, rainslib.PublicKey{}, sigEncoder) {
	}

	processCapability(msg.Capabilities, sender, msg.Token)

	//handle message content
	for _, m := range msg.Content {
		switch m := m.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
			if !isZoneBlacklisted(m.(rainslib.MessageSectionWithSig).GetSubjectZone()) {
				addMsgSectionToQueue(m, msg.Token, sender)
			}
		case *rainslib.QuerySection, *rainslib.AddressQuerySection:
			log.Debug(fmt.Sprintf("add %T to normal queue", m))
			normalChannel <- msgSectionSender{Sender: sender, Section: m, Token: msg.Token}
		case *rainslib.NotificationSection:
			log.Debug("Add notification to notification queue", "token", msg.Token)
			notificationChannel <- msgSectionSender{Sender: sender, Section: m, Token: msg.Token}
		default:
			log.Warn(fmt.Sprintf("unsupported message section type %T", m))
			return
		}
	}
}

//processCapability processes capabilities and sends a notification back to the sender if the hash
//is not understood.
func processCapability(caps []rainslib.Capability, sender rainslib.ConnInfo, token rainslib.Token) {
	log.Debug("Process capabilities", "capabilities", caps)
	if len(caps) > 0 {
		isHash := !strings.HasPrefix(string(caps[0]), "urn:")
		if isHash {
			if caps, ok := capabilities.Get([]byte(caps[0])); ok {
				addCapabilityAndRespond(sender, caps)
			} else { //capability hash not understood
				sendNotificationMsg(token, sender, rainslib.NTCapHashNotKnown, capabilityHash)
			}
		} else {
			addCapabilityAndRespond(sender, caps)
		}
	}
}

//addCapabilityAndRespond adds caps to the connection cache entry of sender and sends its own
//capabilities back if it has not already received capability information on this connection.
func addCapabilityAndRespond(sender rainslib.ConnInfo, caps []rainslib.Capability) {
	if !connCache.AddCapabilityList(sender, caps) {
		sendCapability(sender, []rainslib.Capability{rainslib.Capability(capabilityHash)})
	}
}

//addMsgSectionToQueue looks up the token of the msg in the activeTokens cache and if present adds the msg section to the prio cache, otherwise to the normal cache.
func addMsgSectionToQueue(msgSection rainslib.MessageSection, tok rainslib.Token, sender rainslib.ConnInfo) {
	if pendingKeys.ContainsToken(tok) {
		log.Debug("add section with signature to priority queue", "token", tok)
		prioChannel <- msgSectionSender{Sender: sender, Section: msgSection, Token: tok}
	} else {
		log.Debug("add section with signature to normal queue", "token", tok)
		normalChannel <- msgSectionSender{Sender: sender, Section: msgSection, Token: tok}
	}
}

//isZoneBlacklisted returns true if zone is blacklisted
func isZoneBlacklisted(zone string) bool {
	log.Warn("TODO CFE zone blacklist not yet implemented")
	return false
}

//workBoth works on the prioChannel and on the normalChannel. A worker only fetches a message from the normalChannel if the prioChannel is empty.
//the channel normalWorkers enforces a maximum number of go routines working on the prioChannel and normalChannel.
func workBoth(done chan bool) {
	for {
		select {
		case msg := <-prioChannel:
			verify(msg)
			continue
		default:
			// Fallthrough to second select.
		}
		select {
		case msg := <-prioChannel:
			verify(msg)
		case msg := <-normalChannel:
			verify(msg)
		case <-done:
			return
		}
	}
}

//workPrio works on the prioChannel. It waits on the prioChannel and creates a new go routine which handles the section.
//the channel prioWorkers enforces a maximum number of go routines working on the prioChannel.
//The prio channel is necessary to avoid a blocking of the server. e.g. in the following unrealistic scenario
//1) normal queue fills up with non delegation queries which all are missing a public key
//2) The non-delegation queries get processed by the normalWorkers and added to the pendingSignature cache
//3) For each non-delegation query that gets taken off the queue a new non-delegation query or expired
//   delegation query wins against all waiting valid delegation-queries.
//4) Then although the server is working all the time, no section is added to the caches.
func workPrio(done chan bool) {
	for {
		select {
		case msg := <-prioChannel:
			verify(msg)
		case <-done:
			return
		}
	}
}

//workNotification works on the notificationChannel. It waits on the notificationChannel and creates a new go routine which handles the notification.
//the channel notificationWorkers enforces a maximum number of go routines working on the notificationChannel
func workNotification() {
	for {
		notificationWorkers <- struct{}{}
		msg := <-notificationChannel
		go handleNotification(msg)
	}
}

//handleNotification works on notificationChannel.
func handleNotification(msg msgSectionSender) {
	notify(msg)
	<-notificationWorkers
}

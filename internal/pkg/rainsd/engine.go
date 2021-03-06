package rainsd

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//enoughSystemRessources returns true if the server has enough resources to make consistency checks
var enoughSystemRessources bool

//initEngine initialized the engine, which processes valid sections and queries.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapEngine()
func initEngine() {
	go measureSystemRessources()
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified and there MUST be at least one valid
//rains signature on the message
func (s *Server) assert(ss sectionWithSigSender, isAuthoritative bool) {
	log.Debug("Adding assertion to cache", "assertion", ss)
	if enoughSystemRessources && sectionIsInconsistent(ss.Section, s.caches.ConsistCache,
		s.caches.AssertionsCache, s.caches.NegAssertionCache) {
		log.Warn("section is inconsistent with cached elements.", "section", ss.Section)
		sendNotificationMsg(ss.Token, ss.Sender, section.NTRcvInconsistentMsg, "", s)
		return
	}
	addSectionToCache(ss.Section, isAuthoritative, s.caches.AssertionsCache,
		s.caches.NegAssertionCache, s.caches.ZoneKeyCache)
	pendingKeysCallback(ss, s.caches.PendingKeys, s.queues.Normal)
	pendingQueriesCallback(ss, s)
	log.Info(fmt.Sprintf("Finished handling %T", ss.Section), "section", ss.Section)
}

//sectionIsInconsistent returns true if section is not consistent with cached element which are valid
//at the same time.
func sectionIsInconsistent(sec section.WithSig, consistCache consistencyCache,
	assertionsCache assertionCache, negAssertionCache negativeAssertionCache) bool {
	//TODO CFE There are new run time checks. Add Todo's for those that are not yet implemented
	//TODO CFE drop a shard or zone if it is not sorted.
	switch sec := sec.(type) {
	case *section.Assertion:
		return !isAssertionConsistent(sec, consistCache, assertionsCache, negAssertionCache)
	case *section.Shard:
		return !isShardConsistent(sec, consistCache, assertionsCache, negAssertionCache)
	case *section.Zone:
		return !isZoneConsistent(sec, assertionsCache, negAssertionCache)
	case *section.AddrAssertion:
		return !isAddressAssertionConsistent(sec)
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
		return true
	}
}

//sectionIsInconsistent returns true if section is not consistent with cached element which are valid
//at the same time.
func addSectionToCache(sec section.WithSig, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	switch sec := sec.(type) {
	case *section.Assertion:
		if shouldAssertionBeCached(sec) {
			addAssertionToCache(sec, isAuthoritative, assertionsCache, zoneKeyCache)
		}
	case *section.Shard:
		if shouldShardBeCached(sec) {
			addShardToCache(sec, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
		}
	case *section.Pshard:
		if shouldPshardBeCached(sec) {
			addPshardToCache(sec, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
		}
	case *section.Zone:
		if shouldZoneBeCached(sec) {
			addZoneToCache(sec, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
		}
	case *section.AddrAssertion:
		if shouldAddressAssertionBeCached(sec) {
			addAddressAssertionToCache(sec, isAuthoritative)
		}
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
}

//shouldAssertionBeCached returns true if assertion should be cached
func shouldAssertionBeCached(assertion *section.Assertion) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//shouldShardBeCached returns true if shard should be cached
func shouldShardBeCached(shard *section.Shard) bool {
	log.Info("Shard will be cached", "shard", shard)
	//TODO CFE implement when necessary
	return true
}

//shouldShardBeCached returns true if shard should be cached
func shouldPshardBeCached(pshard *section.Pshard) bool {
	log.Info("Shard will be cached", "shard", pshard)
	//TODO CFE implement when necessary
	return true
}

//shouldZoneBeCached returns true if zone should be cached
func shouldZoneBeCached(zone *section.Zone) bool {
	log.Info("Zone will be cached", "zone", zone)
	//TODO CFE implement when necessary
	return true
}

//shouldAddressAssertionBeCached returns true if assertion should be cached
func shouldAddressAssertionBeCached(assertion *section.AddrAssertion) bool {
	log.Info("Assertion will be cached", "AddressAssertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//addAssertionToCache adds a to the assertion cache and to the public key cache in case a holds a
//public key.
func addAssertionToCache(a *section.Assertion, isAuthoritative bool, assertionsCache assertionCache,
	zoneKeyCache zonePublicKeyCache) {
	assertionsCache.Add(a, a.ValidUntil(), isAuthoritative)
	log.Debug("Added assertion to cache", "assertion", *a)
	for _, obj := range a.Content {
		if obj.Type == object.OTDelegation {
			if publicKey, ok := obj.Value.(keys.PublicKey); ok {
				publicKey.ValidSince = a.ValidSince()
				publicKey.ValidUntil = a.ValidUntil()
				ok := zoneKeyCache.Add(a, publicKey, isAuthoritative)
				if !ok {
					log.Warn("number of entries in the zoneKeyCache reached a critical amount")
				}
				log.Debug("Added publicKey to cache", "publicKey", publicKey)
			} else {
				log.Error("Object type and value type mismatch. This case must be prevented beforehand")
			}
		}
	}
}

//addShardToCache adds shard to the negAssertion cache and all contained assertions to the
//assertionsCache.
func addShardToCache(shard *section.Shard, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	negAssertionCache.AddShard(shard, shard.ValidUntil(), isAuthoritative)
	log.Debug("Added shard to cache", "shard", *shard)
	for _, assertion := range shard.Content {
		if shouldAssertionBeCached(assertion) {
			a := assertion.Copy(shard.Context, shard.SubjectZone)
			addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
		}
	}
}

//addPshardToCache adds pshard to the negAssertion cache
func addPshardToCache(pshard *section.Pshard, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	negAssertionCache.AddPshard(pshard, pshard.ValidUntil(), isAuthoritative)
	log.Debug("Added pshard to cache", "pshard", *pshard)
}

//addZoneToCache adds zone and all contained shards to the negAssertion cache and all contained
//assertions to the assertionCache.
func addZoneToCache(zone *section.Zone, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	negAssertionCache.AddZone(zone, zone.ValidUntil(), isAuthoritative)
	log.Debug("Added zone to cache", "zone", *zone)
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *section.Assertion:
			if shouldAssertionBeCached(sec) {
				a := sec.Copy(zone.Context, zone.SubjectZone)
				addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
			}
		case *section.Shard:
			if shouldShardBeCached(sec) {
				s := sec.Copy(zone.Context, zone.SubjectZone)
				addShardToCache(s, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", sec))
		}
	}
}

//addAddressAssertionToCache adds a to the addressSection cache.
func addAddressAssertionToCache(a *section.AddrAssertion, isAuthoritative bool) {
	log.Warn("Address assertion are not yet supported")
	/*if err := getAddressCache(a.SubjectAddr, a.Context).AddAddressAssertion(a); err != nil {
		log.Warn("Was not able to add addressAssertion to cache", "addressAssertion", a)
	}*/
}

func pendingKeysCallback(swss sectionWithSigSender, pendingKeys pendingKeyCache, normalChannel chan msgSectionSender) {
	//TODO CFE also add a section to the queue when an unrelated assertion answers it
	if sectionSenders := pendingKeys.GetAndRemoveByToken(swss.Token); len(sectionSenders) > 0 {
		//An external service MUST check that the received response makes sense. Otherwise these
		//sections would be in the cache as long as the sender responds in time with 'fake' answers
		//(which results in putting these sections on the normal queue from which they are added
		//again to the pending key cache and so forth until the section expires.
		for _, ss := range sectionSenders {
			normalChannel <- msgSectionSender{Sender: ss.Sender, Section: ss.Section, Token: ss.Token}
		}
	}
}

func pendingQueriesCallback(swss sectionWithSigSender, s *Server) {
	//TODO CFE make wait time configurable
	query, ok := s.caches.PendingQueries.GetQuery(swss.Token)
	if !ok {
		//TODO CFE Check by content when token does not match
		return
	}
	if isAnswerToQuery(swss.Section, query) {
		switch section := swss.Section.(type) {
		case *section.Assertion:
			sendAssertionAnswer(section, query, swss.Token, s)
		case *section.Shard:
			sendShardAnswer(section, query, swss.Token, s)
		case *section.Zone:
			sendZoneAnswer(section, query, swss.Token, s)
		default:
			log.Error("Not supported message section with sig. This case must be prevented beforehand")
		}
	}
	//Delegation case
	switch section := swss.Section.(type) {
	case *section.Assertion:
		zoneAndName := fmt.Sprintf("%s.%s", section.SubjectName, section.SubjectZone)
		if iterativeLookupAllowed() {
			if _, ok := object.ContainsType(section.Content, object.OTDelegation); ok {
				if sendToRedirect(zoneAndName, section.Context, swss.Token, query, s) {
					return
				}
			}
			if _, ok := object.ContainsType(section.Content, object.OTRedirection); ok {
				if sendToRedirect(zoneAndName, section.Context, swss.Token, query, s) {
					return
				}
			}
			if o, ok := object.ContainsType(section.Content, object.OTIP6Addr); ok {
				if resendPendingQuery(query, swss.Token, zoneAndName, o.Value.(string),
					time.Now().Add(s.config.QueryValidity).Unix(), s) {
					return
				}
			}
			if o, ok := object.ContainsType(section.Content, object.OTIP4Addr); ok {
				if resendPendingQuery(query, swss.Token, zoneAndName, o.Value.(string),
					time.Now().Add(s.config.QueryValidity).Unix(), s) {
					return
				}
			}
		}
	case *section.Shard, *section.Zone:
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
	sectionSenders, _ := s.caches.PendingQueries.GetAndRemoveByToken(swss.Token, 0)
	for _, ss := range sectionSenders {
		sendNotificationMsg(ss.Token, ss.Sender, section.NTNoAssertionAvail, "", s)
		log.Warn("Was not able to use answer to query.", "query", query, "token", swss.Token,
			"sender", swss.Sender, "section", swss.Section)
	}
}

//isAnswerToQuery returns true if section answers the query.
func isAnswerToQuery(sec section.WithSig, q section.Section) bool {
	switch sec := sec.(type) {
	case *section.Assertion:
		if q, ok := q.(*query.Name); ok {
			if q.Name == fmt.Sprintf("%s.%s", sec.SubjectName, sec.SubjectZone) {
				for _, oType := range q.Types {
					if _, ok := object.ContainsType(sec.Content, oType); ok {
						return true
					}
				}
			}
		}
		return false
	case *section.Shard:
		if q, ok := q.(*query.Name); ok {
			if name, ok := getSubjectName(q.Name, sec.SubjectZone); ok {
				return sec.InRange(name)
			}
		}
		return false
	case *section.Zone:
		if q, ok := q.(*query.Name); ok {
			if _, ok := getSubjectName(q.Name, sec.SubjectZone); ok {
				return true
			}
		}
		return false
	case *section.AddrAssertion:
		//TODO CFE implement the host address and network address case if delegation is a response
		//or not.
		_, ok := q.(*query.Address)
		return ok
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
	return true
}

//getSubjectName returns true and the subjectName of queryName if queryName's suffix is subjectZone
//and queryName != subjectZone is zone. Otherwise an empty string and false is returned
func getSubjectName(queryName, subjectZone string) (string, bool) {
	if strings.HasSuffix(queryName, subjectZone) {
		zonePoints := strings.Count(subjectZone, ".")
		pointDiff := strings.Count(queryName, ".") - zonePoints
		if pointDiff > 0 {
			return strings.Join(strings.Split(queryName, ".")[:pointDiff], "."), true
		}
	}
	return "", false
}

//sendAssertionAnswer sends all assertions arrived during a configurable waitTime back to all
//pending queries waiting on token.
func sendAssertionAnswer(section section.WithSig, query section.Section, token token.Token, s *Server) {
	waitTime := 10 * time.Millisecond
	deadline := time.Now().Add(waitTime).UnixNano()
	s.caches.PendingQueries.AddAnswerByToken(section, token, deadline)
	time.Sleep(waitTime)
	sectionSenders, answers := s.caches.PendingQueries.GetAndRemoveByToken(token, deadline)
	for _, ss := range sectionSenders {
		sendSections(answers, ss.Token, ss.Sender, s)
	}
}

//sendShardAnswer sends either section or contained assertions answering query back to all pending
//queries waiting on token.
func sendShardAnswer(sec *section.Shard, q section.Section, token token.Token, s *Server) {
	name, _ := getSubjectName(q.(*query.Name).Name, sec.SubjectZone)
	answers := sec.AssertionsByNameAndTypes(name, q.(*query.Name).Types)
	sectionSenders, _ := s.caches.PendingQueries.GetAndRemoveByToken(token, 0)
	var secs []section.Section
	if len(answers) > 0 {
		secs = make([]section.Section, len(answers))
		for i := 0; i < len(answers); i++ {
			secs[i] = answers[i]
		}
	} else {
		secs = append(secs, sec)
	}
	for _, ss := range sectionSenders {
		sendSections(secs, ss.Token, ss.Sender, s)
	}
}

//sendZoneAnswer sends either section or contained assertions or shards answering query back to all
//pending queries waiting on token.
func sendZoneAnswer(sec *section.Zone, q section.Section, token token.Token, s *Server) {
	name, _ := getSubjectName(q.(*query.Name).Name, sec.SubjectZone)
	assertions, shards := sec.SectionsByNameAndTypes(name, q.(*query.Name).Types)
	sectionSenders, _ := s.caches.PendingQueries.GetAndRemoveByToken(token, 0)
	var secs []section.Section
	if len(assertions) > 0 {
		secs = make([]section.Section, len(assertions))
		for i := 0; i < len(assertions); i++ {
			secs[i] = assertions[i]
		}
	} else if len(shards) > 0 {
		shortestShard := shards[0]
		for _, s := range shards {
			if len(s.Content) < len(shortestShard.Content) {
				shortestShard = s
			}
		}
		secs = append(secs, shortestShard)
	} else {
		secs = append(secs, sec)
	}
	for _, ss := range sectionSenders {
		sendSections(secs, ss.Token, ss.Sender, s)
	}
}

//sendToRedirect looks up connection information by name in the redirectCache and sends query to it.
//In case there is no connection information stored for name an IP query is sent to a super ordinate
//zone. It then updates token in the redirect cache to the token of the newly sent query.
//Return true if it was able to send a query and update the token
func sendToRedirect(name, context string, oldToken token.Token, q section.Section, s *Server) bool {
	//TODO CFE policy to pick connInfo
	if conns := s.caches.RedirectCache.GetConnsInfo(name); len(conns) > 0 {
		tok := token.New()
		if s.caches.PendingQueries.UpdateToken(oldToken, tok) {
			sendSection(q, tok, conns[0], s)
			return true
		}
		return false
	}
	redirectName := name
	for name != "" {
		if strings.Contains(name, ".") {
			i := strings.Index(name, ".")
			name = name[i+1:]
		} else {
			name = "."
		}
		if conns := s.caches.RedirectCache.GetConnsInfo(name); len(conns) > 0 {
			tok := token.New()
			if s.caches.PendingQueries.UpdateToken(oldToken, tok) {
				newQuery := &query.Name{
					Name:       redirectName,
					Context:    context,
					Expiration: time.Now().Add(s.config.QueryValidity).Unix(),
					Types:      []object.Type{object.OTIP6Addr, object.OTIP4Addr},
				}
				sendSection(newQuery, tok, conns[0], s)
				return true
			}
			return false
		}
	}
	return false
}

//resendPendingQuery resends query to a connInfo retrieved from the redirectCache based on name.
//Token is updated in the cache. ipAddr is the response to a IP query with token. True is returned
//if the token could have been updated in the cache and the new query is sent out.
func resendPendingQuery(query section.Section, oldToken token.Token, name, ipAddr string,
	expiration int64, s *Server) bool {
	//TODO CFE which port to choose?
	if tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%d", ipAddr, 5022)); err != nil {
		connInfo := connection.Info{Type: connection.TCP, TCPAddr: tcpAddr}
		if s.caches.RedirectCache.AddConnInfo(name, connInfo, expiration) {
			tok := token.New()
			if s.caches.PendingQueries.UpdateToken(oldToken, tok) {
				sendSection(query, tok, connInfo, s)
				return true
			}
		}
		//No redirect/delegation for connInfo in cache, send notification back to senders.
	}
	return false
}

//iterativeLookupAllowed returns true if iterative lookup is enabled for this server
func iterativeLookupAllowed() bool {
	//TODO CFE implement some policy
	return false
}

//processQuery processes msgSender containing a query section
func (s *Server) processQuery(msgSender msgSectionSender) {
	switch section := msgSender.Section.(type) {
	case *query.Name:
		answerQuery(section, msgSender.Sender, msgSender.Token, s)
	case *query.Address:
		addressQuery(section, msgSender.Sender, msgSender.Token)
	default:
		log.Error("Not supported query message section. This case must be prevented beforehand")
	}
}

// queryTransitiveClosure fetches the missing records when a :redir: record is encountered.
// Note: the redirection value must be an FQDN otherwise we can't look it up yet.
func queryTransitiveClosure(as *[]*section.Assertion, qCtx string, assertionsCache assertionCache) {
	unresolved := make(map[string]bool)
	ctr := 0
	for _, as := range *as {
		for _, o := range as.Content {
			if o.Type == object.OTRedirection {
				unresolved[o.Value.(string)] = true
				ctr++
			}
		}
	}
	for ctr > 0 {
		for name := range unresolved {
			delete(unresolved, name)
			ctr--
			res := make([]*section.Assertion, 0)
			if asserts, ok := assertionsCache.Get(name, qCtx, object.OTRedirection, true); ok {
				res = append(res, asserts...)
			}
			if asserts, ok := assertionsCache.Get(name, qCtx, object.OTServiceInfo, true); ok {
				unresolved[name] = true
				res = append(res, asserts...)
			}
			if asserts, ok := assertionsCache.Get(name, qCtx, object.OTIP4Addr, true); ok {
				res = append(res, asserts...)
			}
			if asserts, ok := assertionsCache.Get(name, qCtx, object.OTIP6Addr, true); ok {
				res = append(res, asserts...)
			}
			if len(res) == 0 {
				log.Warn("queryTransitiveClosure: no targets for serviceinfo", "name", name)
			}
			for _, resAssert := range res {
				for _, obj := range resAssert.Content {
					if obj.Type == object.OTRedirection {
						log.Debug("Adding redirection target", "from", name, "to", obj.Value.(string), "unresolved", unresolved)
						unresolved[obj.Value.(string)] = true
						ctr++
					}
					if obj.Type == object.OTServiceInfo {
						sin := obj.Value.(object.ServiceInfo)
						log.Debug("Adding serviceinfo target", "from", name, "to", sin.Name, "unresolved", unresolved)
						unresolved[sin.Name] = true
						ctr++
					}
				}
			}
			for _, a := range res {
				log.Debug("Adding assertion for transitive closure", "assertion", a)
				*as = append(*as, a)
			}
		}
	}
}

//query directly answers the query if the result is cached. Otherwise it issues
//a new query and adds this query to the pendingQueries Cache.
func answerQuery(q *query.Name, sender connection.Info, oldToken token.Token, s *Server) {
	log.Debug("Start processing query", "query", q)
	trace(oldToken, fmt.Sprintf("Processing QueryForward for name: %v, connection: %v", q.Name, q.Types))

	assertions := []section.Section{}
	assertionSet := make(map[string]bool)
	asKey := func(a *section.Assertion) string {
		return fmt.Sprintf("%s_%s_%s", a.SubjectName, a.SubjectZone, a.Context)
	}

	for _, t := range q.Types {
		if asserts, ok := s.caches.AssertionsCache.Get(q.Name, q.Context, t, false); ok {
			trace(oldToken, fmt.Sprintf("received from cache: %v", asserts))
			//TODO implement a more elaborate policy to filter returned assertions instead
			//of sending all non expired once back.
			log.Debug(fmt.Sprintf("before transitive closure: %v", asserts))
			queryTransitiveClosure(&asserts, q.Context, s.caches.AssertionsCache)
			log.Debug(fmt.Sprintf("after transitive closure: %v", asserts))
			for _, a := range asserts {
				if _, ok := assertionSet[asKey(a)]; ok {
					continue
				}
				if a.ValidUntil() > time.Now().Unix() {
					trace(oldToken, fmt.Sprintf("appending valid assertion %v to response", a))
					log.Debug(fmt.Sprintf("appending valid assertion: %v", a))
					assertions = append(assertions, a)
					assertionSet[asKey(a)] = true
				}
			}
		}
	}
	if len(assertions) > 0 {
		sendSections(assertions, oldToken, sender, s)
		trace(oldToken, fmt.Sprintf("successfully sent response assertions: %v", assertions))
		log.Info("Finished handling query by sending assertion from cache", "query", q)
		return
	}
	trace(oldToken, "no entry found in assertion cache")
	log.Debug("No entry found in assertion cache", "name", q.Name,
		"context", q.Context, "type", q.Types)

	//negative answer lookup (note that it can occur a positive answer if assertion removed from cache)
	subject, zone, err := toSubjectZone(q.Name)
	if err != nil {
		sendNotificationMsg(oldToken, sender, section.NTRcvInconsistentMsg,
			"query name must end with root zone dot '.'", s)
		log.Warn("failed to concert query name to subject and zone: %v", err)
		return
	}
	negAssertion, ok := s.caches.NegAssertionCache.Get(zone, q.Context, section.StringInterval{Name: subject})
	if ok {
		//TODO CFE For each type check if one of the zone or shards contain the queried
		//assertion. If there is at least one assertion answer with it. If no assertion is
		//contained in a zone or shard for any of the queried connection, answer with the shortest
		//element. shortest according to what? size in bytes? how to efficiently determine that.
		//e.g. using gob encoding. alternatively we could also count the number of contained
		//elements.
		sendSection(negAssertion[0], oldToken, sender, s)
		trace(oldToken, fmt.Sprintf("found negative assertion matching query: %v", negAssertion[0]))
		log.Info("Finished handling query by sending shard or zone from cache", "query", q)
		return
	}
	log.Debug("No entry found in negAssertion cache matching the query")
	trace(oldToken, "no entry found in negative assertion cache")

	// If cached answers only option is set then stop after looking in the local cache.
	if q.ContainsOption(query.QOCachedAnswersOnly) {
		log.Debug("Send a notification message back due to query option: 'Cached Answers only'",
			"destination", sender)
		sendNotificationMsg(oldToken, sender, section.NTNoAssertionAvail, "", s)
		trace(oldToken, "returned no assertion available message due to CachedAnswersOnly query option")
		log.Info("Finished handling query (unsuccessful, cached answers only) ", "query", q)
		return
	}

	trace(oldToken, "forwarding query")
	//forward query (no answer in cache)
	var delegate connection.Info
	if iterativeLookupAllowed() {
		if conns := s.caches.RedirectCache.GetConnsInfo(q.Name); len(conns) > 0 {
			//TODO CFE design policy which server to choose (same as pending query callback?)
			delegate = conns[0]
		} else {
			sendNotificationMsg(oldToken, sender, section.NTNoAssertionAvail, "", s)
			log.Error("no delegate found to send query to")
			return
		}
	} else {
		delegate = getRootAddr()
	}
	if delegate.Equal(s.config.ServerAddress) {
		sendNotificationMsg(oldToken, sender, section.NTNoAssertionAvail, "", s)
		log.Error("Stop processing query. I am authoritative and have no answer in cache")
		return
	}
	//we have a valid delegation
	tok := oldToken
	if !q.ContainsOption(query.QOTokenTracing) {
		tok = token.New()
	}
	validUntil := time.Now().Add(s.config.QueryValidity).Unix() //Upper bound for forwarded query expiration time
	if q.Expiration < validUntil {
		validUntil = q.Expiration
	}
	isNew := s.caches.PendingQueries.Add(msgSectionSender{Section: q, Sender: sender, Token: oldToken})
	log.Info("Added query into to pending query cache", "query", q)
	if isNew {
		if s.caches.PendingQueries.AddToken(tok, validUntil, delegate, q.Name, q.Context, q.Types) {
			newQuery := &query.Name{
				Name:       q.Name,
				Context:    q.Context,
				Expiration: validUntil,
				Types:      q.Types,
			}
			if err := sendSection(newQuery, tok, delegate, s); err == nil {
				log.Info("Sent query.", "destination", delegate, "query", newQuery)
			}
		} //else answer already arrived and callback function has already been invoked
	} else {
		log.Info("Query already sent.")
	}
}

//addressQuery directly answers the query if the result is cached. Otherwise it issues a new query
//and adds this query to the pendingQueries Cache.
func addressQuery(q *query.Address, sender connection.Info, oldToken token.Token) {
	log.Warn("Address Queries not yet supported")
	//FIXME CFE make it compatible with the new caches
	/*log.Debug("Start processing address query", "addressQuery", q)
	assertion, ok := getAddressCache(q.SubjectAddr, q.Context).Get(q.SubjectAddr, q.Types)
	//TODO CFE add heuristic which assertion to return
	if ok {
		if assertion != nil {
			sendSection(assertion, oldToken, sender)
			log.Debug("Finished handling query by sending address assertion from cache", "q", q)
			return
		}
	}
	log.Debug("No entry found in address cache matching the query")

	if q.ContainsOption(query.QOCachedAnswersOnly) {
		log.Debug("Send a notification message back to the sender due to query option: 'Cached Answers only'")
		sendNotificationMsg(oldToken, sender, section.NTNoAssertionAvail, "")
		log.Debug("Finished handling query (unsuccessful) ", "query", q)
		return
	}

	delegate := getRootAddr()
	if delegate.Equal(serverConnInfo) {
		sendNotificationMsg(oldToken, sender, section.NTNoAssertionAvail, "")
		log.Error("Stop processing query. I am authoritative and have no answer in cache")
		return
	}
	//we have a valid delegation
	tok := oldToken
	if !q.ContainsOption(query.QOTokenTracing) {
		tok = token.New()
	}
	newQuery := *q
	//Upper bound for forwarded query expiration time
	if newQuery.Expiration > time.Now().Add(Config.AddressQueryValidity).Unix() {
		newQuery.Expiration = time.Now().Add(Config.AddressQueryValidity).Unix()
	}
	//FIXME CFE allow multiple connection
	//FIXME CFE only send query if not already in cache.
	pendingQueries.Add(msgSectionSender{Section: q, Sender: sender, Token: oldToken})
	log.Debug("Added query into to pending query cache", "query", q)
	sendSection(&newQuery, tok, delegate)*/
}

// toSubjectZone splits a name into a subject and zone.
// Invariant: name always ends with the '.'.
func toSubjectZone(name string) (subject, zone string, e error) {
	//TODO CFE use also different heuristics
	if !strings.HasSuffix(name, ".") {
		return "", "", fmt.Errorf("invariant that query name ends with '.' is broken: %v", name)
	}
	parts := strings.Split(name, ".")
	if parts[0] == "" {
		zone = "."
		subject = ""
		return
	}
	subject = parts[0]
	zone = strings.Join(parts[1:], ".")

	log.Debug("Split into zone and name", "subject", subject, "zone", zone)
	return
}

//handleShardOrZoneQueryResponse checks if section.Content contains an assertion with subjectName,
//subjectZone and context. If it does not find an entry it sends the section back to the querier and
//returns true. Otherwise it checks if the entry has an unexpired signature. In that case it sends
//the assertion back to the querier and returns true, otherwise it return false
func handleShardOrZoneQueryResponse(sec section.WithSigForward, subjectName, subjectZone,
	context string, queryType object.Type, sender connection.Info, token token.Token, s *Server) bool {
	assertions := []*section.Assertion{}
	switch sec := sec.(type) {
	case *section.Shard:
		assertions = sec.Content
	case *section.Zone:
		for _, sec := range sec.Content {
			switch sec := sec.(type) {
			case *section.Assertion:
				assertions = append(assertions, sec)
			case *section.Shard:
				assertions = append(assertions, sec.Content...)
			default:
				log.Warn(fmt.Sprintf("Unsupported zone.Content Expected assertion or shard. actual=%T", sec))
			}
		}
	default:
		log.Warn(fmt.Sprintf("Unexpected WithSigForward. Expected zone or shard. actual=%T", sec))
	}
	if entryFound, hasSig := containedAssertionQueryResponse(assertions, subjectName,
		subjectZone, context, queryType, sender, token, s); entryFound {
		return hasSig
	}
	sendSection(sec, token, sender, s)
	return true
}

//containedAssertionQueryResponse checks if assertions contains an assertion with subjectName,
//subjectZone and context. If it does not find an entry it returns (false, false). Otherwise it
//checks if the entry has an unexpired signature. In that case it sends the assertion back to the
//querier and returns (true, true), otherwise it return (true, false)
func containedAssertionQueryResponse(assertions []*section.Assertion, subjectName, subjectZone,
	context string, queryType object.Type, sender connection.Info, token token.Token, s *Server) (
	entryFound bool, hasSig bool) {
	for _, a := range assertions {
		//TODO CFE handle case where assertion can have multiple connection
		if a.SubjectName == subjectName && a.SubjectZone == subjectZone &&
			a.Context == context && a.Content[0].Type == queryType {
			for _, sig := range a.Sigs(keys.RainsKeySpace) {
				//TODO CFE only check for this condition when queryoption 5 is not set
				if sig.ValidUntil > time.Now().Unix() {
					sendSection(a, token, sender, s)
					return true, true
				}
			}
			return true, false
		}
	}
	return false, false
}

package rainspub

import (
	"errors"
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
)

//signSectionUnsafe signs section and all contained sections (if it is a shard or zone). The
//signature meta data must already be present. SignSectionUnsafe returns an error if it was not able
//to sign the section and all contained sections. The section is signed as is. The Caller must make
//sure that the section is sorted and adheres to the protocol and policies.
func signSectionUnsafe(section rainslib.MessageSectionWithSig, keys map[rainslib.PublicKeyID]interface{}) error {
	//TODO implement signing with airgapping
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return signAssertion(section, keys)
	case *rainslib.ShardSection:
		return signShard(section, keys)
	case *rainslib.ZoneSection:
		return signZone(section, keys)
	case *rainslib.AddressAssertionSection:
		log.Warn("Signing address assertions not yet implemented")
		return errors.New("Signing address assertions not yet implemented")
	}
	return nil
}

//signZone signs the zone and all contained shards and assertions with the zone's private key. It
//removes the subjectZone and context of the contained assertions and shards after the signatures
//have been added. It returns an error if it was unable to sign the zone or any of the contained
//shards and assertions.
func signZone(zone *rainslib.ZoneSection, keys map[rainslib.PublicKeyID]interface{}) error {
	if zone == nil {
		return errors.New("zone is nil")
	}
	for _, sig := range zone.Signatures {
		if ok := rainsSiglib.SignSectionUnsafe(zone, keys[sig.PublicKeyID], sig, signatureEncoder); !ok {
			log.Error("Was not able to sign and add the signature", "zone", zone, "signature", sig)
			return errors.New("Was not able to sign and add the signature")
		}
	}
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if err := signAssertion(sec, keys); err != nil {
				return err
			}
			sec.Context = ""
			sec.SubjectZone = ""
		case *rainslib.ShardSection:
			if err := signShard(sec, keys); err != nil {
				return err
			}
			sec.Context = ""
			sec.SubjectZone = ""
		default:
			return fmt.Errorf("Zone contained unexpected type expected *ShardSection or *AssertionSection actual=%T", sec)
		}
	}
	return nil
}

//signShard signs the shard and all contained assertions with the zone's private key. It removes the
//subjectZone and context of the contained assertions after the signatures have been added. It
//returns an error if it was unable to sign the shard or any of the assertions.
func signShard(s *rainslib.ShardSection, keys map[rainslib.PublicKeyID]interface{}) error {
	if s == nil {
		return errors.New("shard is nil")
	}
	for _, sig := range s.Signatures {
		if ok := rainsSiglib.SignSectionUnsafe(s, keys[sig.PublicKeyID], sig, signatureEncoder); !ok {
			log.Error("Was not able to sign and add the signature", "shard", s, "signature", sig)
			return errors.New("Was not able to sign and add the signature")
		}
	}
	for _, a := range s.Content {
		if err := signAssertion(a, keys); err != nil {
			return err
		}
		a.Context = ""
		a.SubjectZone = ""
	}
	return nil
}

//signAssertion computes the signature data for all contained signatures.
//It returns an error if it was unable to create all signatures on the assertion.
func signAssertion(a *rainslib.AssertionSection, keys map[rainslib.PublicKeyID]interface{}) error {
	if a == nil {
		return errors.New("assertion is nil")
	}
	for _, sig := range a.Signatures {
		if ok := rainsSiglib.SignSectionUnsafe(a, keys[sig.PublicKeyID], sig, signatureEncoder); !ok {
			log.Error("Was not able to sign and add the signature", "assertion", a, "signature", sig)
			return errors.New("Was not able to sign and add the signature")
		}
	}
	return nil
}

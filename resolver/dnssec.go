package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

// DNSSEC key flags
const (
	DNSKEY_ZSK uint16 = 256 // Zone Signing Key
	DNSKEY_KSK uint16 = 257 // Key Signing Key
)

type contextKey string

const (
	contextTrace  contextKey = "trace"  // Context key for recursion depth
	contextDepth  contextKey = "depth"  // Context key for recursion depth
	initialDomain contextKey = "domain" // Context key for the initial domain
)

// SignatureSets represents a collection of SignatureSet pointers
type SignatureSets []*SignatureSet

// SignatureSet represents a set of DNS Records along with their corresponding RRSIG and DNSKEY
type SignatureSet struct {
	key       *dns.DNSKEY // DNSKEY used to validate the signature
	signature *dns.RRSIG  // RRSIG record
	records   []dns.RR    // DNS records covered by the RRSIG
}

// newSignatureSets creates and initializes SignatureSets from a given set of DNS Records
func newSignatureSets(rrset []dns.RR) (SignatureSets, error) {
	answers := make([]dns.RR, 0)
	signatures := make(SignatureSets, 0)

	// Separate RRSIG Records from other DNS Records
	for _, answer := range rrset {
		if signature, ok := answer.(*dns.RRSIG); ok {
			signatures = append(signatures, &SignatureSet{
				records:   make([]dns.RR, 0),
				signature: signature,
			})
		} else {
			answers = append(answers, answer)
		}
	}

	if len(signatures) == 0 {
		return nil, fmt.Errorf("no RRSIG records found. this might indicate that DNSSEC is not enabled for this domain, or that the nameserver used does not return RRSIG records")
	}

	// Associate each DNS record with at least one RRSIG
	var assigned bool
	for _, answer := range answers {
		assigned = false
		for _, signature := range signatures {
			assigned = signature.addRR(answer) || assigned
		}

		// Return an error if any DNS record is not assigned to a RRSIG
		if !assigned {
			return nil, fmt.Errorf("[%s] was unable to be assigned to any RRSIG", answer.String())
		}
	}

	return signatures, nil
}

// verify checks the validity of the signature within the SignatureSet
func (ss *SignatureSet) verify() error {
	if !ss.signature.ValidityPeriod(time.Now()) {
		return fmt.Errorf("signature outside of the allowed inception or expiration range")
	}
	return ss.signature.Verify(ss.key, ss.records)
}

// addRR adds a DNS record to the SignatureSet if it matches the RRSIG criteria
func (ss *SignatureSet) addRR(rr dns.RR) bool {
	// Check if the record type matches the type covered by the RRSIG
	if ss.signature.TypeCovered != rr.Header().Rrtype {
		return false
	}

	// Check if the record's name has the correct suffix
	if !strings.HasSuffix(rr.Header().Name, ss.signature.SignerName) {
		return false
	}

	// Check if the number of labels matches
	if int(ss.signature.Labels) != countLabels(rr.Header().Name) {
		return false
	}

	// Record matches, add it to the SignatureSet
	ss.records = append(ss.records, rr)
	return true
}

// addKey associates a DNSKEY with the SignatureSet if it matches the RRSIG's key tag and type
func (ss *SignatureSet) addKey(key *dns.DNSKEY, keyType uint16) bool {
	tag := key.KeyTag()
	if key.Flags == keyType && ss.signature.KeyTag == tag {
		ss.key = key
		return true
	}
	return false
}

// Authenticate verifies the DNSSEC signatures in the DNS response message
func (d *Resolver) Authenticate(msg *dns.Msg, ctx context.Context) error {
	if msg == nil {
		return fmt.Errorf("no DNS message provided")
	}

	// Retrieve the depth from the context, default to 0 if not found
	depth, ok := ctx.Value(contextDepth).(uint8)
	if !ok {
		depth = 0
		ctx = context.WithValue(ctx, contextDepth, depth)
	}

	// Check if maximum authentication depth is reached
	if depth >= d.maxAuthenticationDepth {
		return fmt.Errorf("maximum authentication depth of %d reached", d.maxAuthenticationDepth)
	}

	// Retrieve the initial domain from the context, default to the query name if not found
	domain, ok := ctx.Value(initialDomain).(string)
	if !ok {
		domain = msg.Question[0].Name
		ctx = context.WithValue(ctx, initialDomain, domain)
	}

	logger := d.logger.With().
		Str("domain", msg.Question[0].Name).
		Uint8("depth", depth).
		Logger()

	logger.Info().Str("type", rrtypeToString(msg.Question[0].Qtype)).Msg("Authenticating answer")

	// Authenticate the Zone Signing Key (ZSK)
	keySignatureSets, err := d.authenticateZoneSigningKey(msg, ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Error authenticating with the Zone Signing Key")
		return err
	}

	// Check if we are at the root zone
	for _, kss := range keySignatureSets {
		if kss.signature.SignerName == "." {
			logger.Info().Str("zone", kss.signature.SignerName).Msg("Using root DS digest anchor")

			for _, answer := range d.RootDNSSECRecords {
				keyDS := kss.key.ToDS(answer.DigestType)
				// Case-insensitive string match for DS digest
				if answer.KeyTag == keyDS.KeyTag && answer.Algorithm == keyDS.Algorithm && strings.EqualFold(answer.Digest, keyDS.Digest) {
					logger.Info().
						Str("digest", answer.Digest).
						Msg("Key Signing Key authenticated at root.")
					if trace, ok := ctx.Value(contextTrace).(*AuthenticationTrace); ok {
						trace.Add(newAuthenticationTraceDelegationSignerCheck(depth, msg.Question[0].Name, kss.signature.SignerName, keyDS.Digest))
					}
					return nil
				}
			}

			logger.Error().Msg("Authentication failed - unable to find a matching DS digest at the root.")
			return fmt.Errorf("unable to find a matching DS digest at the root")
		} else {
			// Check the parent DS digest
			logger.Info().Str("zone", kss.signature.SignerName).Msg("Checking parent DS digest")

			//answers, dsMsg, _, err := d.QueryDS(kss.signature.SignerName)
			dsMsg, _, err := d.query(kss.signature.SignerName, dns.TypeDS, ctx)
			if err != nil {
				return err
			}
			answers := extractRecordsOfType[*dns.DS](dsMsg.Answer)

			for _, answer := range answers {
				keyDS := kss.key.ToDS(answer.DigestType)
				// Case-insensitive string match for DS digest
				if answer.KeyTag == keyDS.KeyTag && answer.Algorithm == keyDS.Algorithm && strings.EqualFold(answer.Digest, keyDS.Digest) {
					logger.Info().
						Str("digest", answer.Digest).
						Str("zone", kss.signature.SignerName).
						Msg("Key Signing Key authenticated at parent. Next authenticating parent's zone.")
					if trace, ok := ctx.Value(contextTrace).(*AuthenticationTrace); ok {
						trace.Add(newAuthenticationTraceDelegationSignerCheck(depth, msg.Question[0].Name, kss.signature.SignerName, keyDS.Digest))
					}
					return d.Authenticate(dsMsg, context.WithValue(ctx, contextDepth, depth+1))
				}
			}

			logger.Error().Msg("Authentication failed - unable to find a matching DS digest at the parent.")
			return fmt.Errorf("unable to find a matching DS digest at the parent")
		}
	}

	return fmt.Errorf("no signature sets found, unable to validate")
}

// authenticateZoneSigningKey authenticates the Zone Signing Key (ZSK) for the given DNS response message
func (d *Resolver) authenticateZoneSigningKey(msg *dns.Msg, ctx context.Context) ([]*SignatureSet, error) {
	allValidKeysSignatureSets := make([]*SignatureSet, 0)

	var ok bool
	var depth uint8 = 0
	if depth, ok = ctx.Value(contextDepth).(uint8); !ok {
		return nil, fmt.Errorf("missing depth from context")
	}

	logger := d.logger.With().Uint8("depth", depth).Str("domain", msg.Question[0].Name).Logger()

	// Create signature sets from the DNS response
	zoneSignatureSets, err := newSignatureSets(msg.Answer)
	if err != nil {
		return nil, err
	}

	logger.Info().Int("number-of-signatures", len(zoneSignatureSets)).Msg("Authenticating zone's ZSK and KSK")

	for _, zss := range zoneSignatureSets {
		// Request DNSKEY Records for the signer name
		//keys, keysMsg, _, err := d.QueryDNSKEY(zss.signature.SignerName)
		keysMsg, _, err := d.query(zss.signature.SignerName, dns.TypeDNSKEY, ctx)
		if err != nil {
			return nil, err
		}
		keys := extractRecordsOfType[*dns.DNSKEY](keysMsg.Answer)

		// Add matching Zone Signing Key (ZSK)
		for _, key := range keys {
			if zss.addKey(key, DNSKEY_ZSK) {
				break
			}
		}
		if zss.key == nil {
			return nil, fmt.Errorf("%s does not have a matching key", zss.signature.String())
		}

		// Verify the signature with the ZSK
		err = zss.verify()

		if trace, ok := ctx.Value(contextTrace).(*AuthenticationTrace); ok {
			trace.Add(
				newAuthenticationTraceSignatureValidation(depth, msg.Question[0].Name, zss.signature.SignerName, "zsk", zss.key, zss.signature, zss.records, err),
			)
		}

		if err != nil {
			return nil, fmt.Errorf("unable to verify %s; received %s", zss.signature.String(), err.Error())
		}

		logger.Info().Str("flag", "zsk").
			Str("zone", zss.signature.SignerName).
			Str("key", tabsToSpaces(zss.key.String())).
			Str("signature", tabsToSpaces(zss.signature.String())).
			Msg("Signature verified with Zone Signing Key")

		// Create signature sets from the DNSKEY response
		keysSignatureSets, err := newSignatureSets(keysMsg.Answer)
		if err != nil {
			return nil, err
		}

		for _, kss := range keysSignatureSets {
			// Add matching Key Signing Key (KSK)
			for _, key := range keys {
				if kss.addKey(key, DNSKEY_KSK) {
					break
				}
			}

			if kss.key == nil {
				return nil, fmt.Errorf("%s does not have a matching key", tabsToSpaces(kss.signature.String()))
			}

			// Verify the signature with the KSK
			err = kss.verify()

			if trace, ok := ctx.Value(contextTrace).(*AuthenticationTrace); ok {
				trace.Add(
					newAuthenticationTraceSignatureValidation(depth, msg.Question[0].Name, kss.signature.SignerName, "ksk", kss.key, kss.signature, kss.records, err),
				)
			}

			if err != nil {
				return nil, fmt.Errorf("unable to verify %s; received %s", tabsToSpaces(kss.signature.String()), err.Error())
			}

			logger.Info().Str("flag", "ksk").
				Str("zone", kss.signature.SignerName).
				Str("key", tabsToSpaces(kss.key.String())).
				Str("signature", tabsToSpaces(kss.signature.String())).
				Msg("Signature verified with Key Signing Key")

			allValidKeysSignatureSets = append(allValidKeysSignatureSets, kss)
		}
	}

	return allValidKeysSignatureSets, nil
}

// countLabels counts the number of labels in a domain name
func countLabels(domain string) int {
	domain = strings.TrimRight(domain, ".")
	if domain == "" {
		return 0
	}
	return len(strings.Split(domain, "."))
}

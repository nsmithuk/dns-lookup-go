package resolver

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

type AuthenticationTrace struct {
	Records []authenticationTraceRecord
}

func (t *AuthenticationTrace) Add(r authenticationTraceRecord) {
	if t.Records == nil {
		t.Records = make([]authenticationTraceRecord, 0)
	}
	t.Records = append(t.Records, r)
}

type authenticationTraceRecord interface{}

type AuthenticationTraceLookup struct {
	Domain     string
	Rrtype     string
	Nameserver string
	Latency    time.Duration
	Answers    []string
}

func newAuthenticationTraceLookup(domain string, rrtype uint16, nameserver string, latency time.Duration, answers []dns.RR) AuthenticationTraceLookup {
	return AuthenticationTraceLookup{
		Domain:     domain,
		Rrtype:     rrtypeToString(rrtype),
		Nameserver: nameserver,
		Latency:    latency,
		Answers:    rrsetToStrings(answers),
	}
}

//---

type AuthenticationTraceSignatureValidation struct {
	Depth     uint8
	KeyType   string
	Domain    string
	Zone      string
	Key       string
	KeySha256 string
	Algorithm string
	Signature string
	Records   []string
	Err       error
	Valid     bool
}

func newAuthenticationTraceSignatureValidation(depth uint8, domain, zone, keyType string, key *dns.DNSKEY, signature *dns.RRSIG, records []dns.RR, err error) AuthenticationTraceSignatureValidation {
	return AuthenticationTraceSignatureValidation{
		Depth:     depth,
		Domain:    domain,
		Zone:      zone,
		KeyType:   keyType,
		Key:       tabsToSpaces(key.String()),
		KeySha256: key.ToDS(dns.SHA256).Digest,
		Algorithm: algorithmToString(key.Algorithm),
		Signature: tabsToSpaces(signature.String()),
		Records:   rrsetToStrings(records),
		Err:       err,
		Valid:     err == nil,
	}
}

//---

type AuthenticationTraceDelegationSignerCheck struct {
	Depth  uint8
	Child  string
	Parent string
	Hash   string
}

func newAuthenticationTraceDelegationSignerCheck(depth uint8, child, parent, hash string) AuthenticationTraceDelegationSignerCheck {
	return AuthenticationTraceDelegationSignerCheck{
		Depth:  depth,
		Child:  child,
		Parent: parent,
		Hash:   strings.ToLower(hash),
	}
}

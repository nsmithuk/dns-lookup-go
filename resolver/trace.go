package resolver

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

type Trace struct {
	Records []traceRecord
}

func (t *Trace) Add(r traceRecord) {
	if t.Records == nil {
		t.Records = make([]traceRecord, 0)
	}
	t.Records = append(t.Records, r)
}

type traceRecord interface{}

type TraceLookup struct {
	Domain     string
	Rrtype     string
	Nameserver string
	Latency    time.Duration
	Answers    []string
}

func newtTraceLookup(domain string, rrtype uint16, nameserver string, latency time.Duration, answers []dns.RR) TraceLookup {
	return TraceLookup{
		Domain:     domain,
		Rrtype:     rrtypeToString(rrtype),
		Nameserver: nameserver,
		Latency:    latency,
		Answers:    rrsetToStrings(answers),
	}
}

//---

type TraceSignatureValidation struct {
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

func newTraceSignatureValidation(depth uint8, domain, zone, keyType string, key *dns.DNSKEY, signature *dns.RRSIG, records []dns.RR, err error) TraceSignatureValidation {
	return TraceSignatureValidation{
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

type TraceDelegationSignerCheck struct {
	Depth  uint8
	Child  string
	Parent string
	Hash   string
}

func newTraceDelegationSignerCheck(depth uint8, child, parent, hash string) TraceDelegationSignerCheck {
	return TraceDelegationSignerCheck{
		Depth:  depth,
		Child:  child,
		Parent: parent,
		Hash:   strings.ToLower(hash),
	}
}

package lookup

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

//func (r TraceLookup) String() string {
//	result := fmt.Sprintf("DNS Lookup for [%s] %s @%s took %s and returned %d answers:", r.Domain, r.Rrtype, r.Nameserver, r.Latency, len(r.Answers))
//	for _, r := range r.Answers {
//		result += fmt.Sprintf("\n   [%s]", r)
//	}
//	return result
//}

//---

type TraceSignatureValidation struct {
	Depth     uint8
	KeyType   string
	Domain    string
	Zone      string
	Key       string
	KeySha256 string
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
		Signature: tabsToSpaces(signature.String()),
		Records:   rrsetToStrings(records),
		Err:       err,
		Valid:     err == nil,
	}
}

//func (r TraceSignatureValidation) String() string {
//	validation := "passed"
//	if !r.Valid {
//		validation = "failed"
//	}
//	result := fmt.Sprintf("Signature validation %s for Key [%s] with Signature [%s] for records:", validation, r.Key, r.Signature)
//	for _, r := range r.Records {
//		result += fmt.Sprintf("\n   [%s]", r)
//	}
//	return result
//}

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

//func (r TraceDelegationSignerCheck) String() string {
//	return ""
//}

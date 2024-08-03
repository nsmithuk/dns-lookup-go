package resolver

import (
	"github.com/miekg/dns"
	"time"
)

type RecursiveQueryTrace struct {
	Records []recursiveQueryTraceRecord
}

func (t *RecursiveQueryTrace) Add(r recursiveQueryTraceRecord) {
	if t.Records == nil {
		t.Records = make([]recursiveQueryTraceRecord, 0)
	}
	t.Records = append(t.Records, r)
}

type recursiveQueryTraceRecord interface{}

type RecursiveQueryTraceLookup struct {
	Depth       uint8
	Domain      string
	Rrtype      string
	ServerHost  string
	ServerUri   string
	Latency     time.Duration
	Answers     []string
	Nameservers []string
	Extra       []string
}

func newRecursiveQueryTraceLookup(depth uint8, domain string, rrtype uint16, hostname string, connectionUri string, latency time.Duration, answers []dns.RR, nameservers []dns.RR, extra []dns.RR) RecursiveQueryTraceLookup {
	// Only include A records in extra.
	extraA := extractRecordsOfType[*dns.A](extra)
	extraRR := make([]dns.RR, len(extraA))
	for i, record := range extraA {
		extraRR[i] = record
	}

	return RecursiveQueryTraceLookup{
		Depth:       depth,
		Domain:      domain,
		Rrtype:      rrtypeToString(rrtype),
		ServerHost:  hostname,
		ServerUri:   connectionUri,
		Latency:     latency,
		Answers:     rrsetToStrings(answers),
		Nameservers: rrsetToStrings(nameservers),
		Extra:       rrsetToStrings(extraRR),
	}
}

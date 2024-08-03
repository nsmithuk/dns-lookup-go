package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRrtypeToString(t *testing.T) {
	tests := []struct {
		rrtype   uint16
		expected string
	}{
		{rrtype: 1, expected: "A"},
		{rrtype: 2, expected: "NS"},
		{rrtype: 5, expected: "CNAME"},
		{rrtype: 6, expected: "SOA"},
		{rrtype: 12, expected: "PTR"},
		{rrtype: 15, expected: "MX"},
		{rrtype: 16, expected: "TXT"},
		{rrtype: 28, expected: "AAAA"},
		{rrtype: 33, expected: "SRV"},
		{rrtype: 35, expected: "NAPTR"},
		{rrtype: 36, expected: "KX"},
		{rrtype: 37, expected: "CERT"},
		{rrtype: 39, expected: "DNAME"},
		{rrtype: 43, expected: "DS"},
		{rrtype: 46, expected: "RRSIG"},
		{rrtype: 47, expected: "NSEC"},
		{rrtype: 48, expected: "DNSKEY"},
		{rrtype: 50, expected: "NSEC3"},
		{rrtype: 51, expected: "NSEC3PARAM"},
		{rrtype: 257, expected: "CAA"},
		{rrtype: 9999, expected: "unknown"},
	}

	for _, test := range tests {
		result := rrtypeToString(test.rrtype)
		if result != test.expected {
			t.Errorf("Expected '%s' for rrtype %d, got '%s'", test.expected, test.rrtype, result)
		}
	}
}

func TestQuestionsToStrings(t *testing.T) {
	questions := []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "example.net.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}

	expected := []string{
		";example.com. IN  A",
		";example.net. IN  AAAA",
	}

	results := questionsToStrings(questions)
	for i, result := range results {
		if result != expected[i] {
			t.Errorf("Expected '%s', got '%s'", expected[i], result)
		}
	}
}

func TestRrsetToStrings(t *testing.T) {
	rrset := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "example.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}

	expected := []string{
		"example.com. 300 IN A 192.0.2.1",
		"example.net. 300 IN AAAA 2001:db8::1",
	}

	results := rrsetToStrings(rrset)
	for i, result := range results {
		if result != expected[i] {
			t.Errorf("Expected '%s', got '%s'", expected[i], result)
		}
	}
}

func TestRrsigToStrings(t *testing.T) {
	// Using time values in Unix format
	expiration := uint32(time.Date(1970, 1, 1, 1, 0, 0, 0, time.UTC).Unix())
	inception := uint32(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Unix())

	rrset := []dns.RRSIG{
		{
			Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeA,
			Algorithm:   dns.RSASHA1,
			Labels:      2,
			OrigTtl:     300,
			Expiration:  expiration,
			Inception:   inception,
			KeyTag:      12345,
			SignerName:  "example.com.",
			Signature:   "ABCD",
		},
	}

	expected := []string{
		"example.com. 300 IN RRSIG A 5 2 300 19700101010000 19700101000000 12345 example.com. ABCD",
	}

	results := rrsigToStrings(rrset)
	for i, result := range results {
		if result != expected[i] {
			t.Errorf("Expected '%s', got '%s'", expected[i], result)
		}
	}
}

func TestTabsToSpaces(t *testing.T) {
	input := "example.com.\tIN\tA\t192.0.2.1"
	expected := "example.com. IN A 192.0.2.1"
	result := tabsToSpaces(input)
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

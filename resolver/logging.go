package resolver

import (
	"github.com/miekg/dns"
	"strings"
)

// dnsRecordTypes maps a rrtype id to a string representation
var dnsRecordTypes = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	35:  "NAPTR",
	36:  "KX",
	37:  "CERT",
	39:  "DNAME",
	43:  "DS",
	46:  "RRSIG",
	47:  "NSEC",
	48:  "DNSKEY",
	50:  "NSEC3",
	51:  "NSEC3PARAM",
	257: "CAA",
}

var dnsAlgorithms = map[uint8]string{
	1:   "RSA MD5",
	2:   "DH",
	3:   "DSA",
	5:   "RSA SHA1",
	6:   "DSA-NSEC3-SHA1",
	7:   "RSASHA1-NSEC3-SHA1",
	8:   "RSA SHA256",
	10:  "RSA SHA512",
	12:  "ECC-GOST",
	13:  "ECDSA P256 SHA256",
	14:  "ECDSA P384 SHA384",
	15:  "ED25519",
	16:  "ED448",
	252: "Indirect",
	253: "PrivateDNS",
	254: "PrivateOID",
}

func algorithmToString(algorithm uint8) string {
	if name, ok := dnsAlgorithms[algorithm]; ok {
		return name
	} else {
		return "unknown"
	}
}

// rrtypeToString returns a string representation of a given rrtype integer.
func rrtypeToString(rrtype uint16) string {
	if name, ok := dnsRecordTypes[rrtype]; ok {
		return name
	} else {
		return "unknown"
	}
}

//---

// questionsToStrings returns string representations of a slice of questions
func questionsToStrings(rrset []dns.Question) []string {
	results := make([]string, len(rrset))
	for i, result := range rrset {
		results[i] = tabsToSpaces(result.String())
	}
	return results
}

// rrsetToStrings returns string representations of a slice of rrs
func rrsetToStrings(rrset []dns.RR) []string {
	results := make([]string, len(rrset))
	for i, result := range rrset {
		results[i] = tabsToSpaces(result.String())
	}
	return results
}

// rrsigToStrings returns string representations of a slice of rrsigs
func rrsigToStrings(rrset []dns.RRSIG) []string {
	results := make([]string, len(rrset))
	for i, result := range rrset {
		results[i] = tabsToSpaces(result.String())
	}
	return results
}

// tabsToSpaces replace the tab character with spaces. Gives a cleaner output in some cases.
func tabsToSpaces(s string) string {
	return strings.ReplaceAll(s, "\t", " ")
}

package lookup

import (
	"github.com/miekg/dns"
	"time"
)

// Not DRY but easy to auto-generate and avoids some ugly generics.

// QueryA retrieves A records for the given name.
func (d *DnsLookup) QueryA(name string) ([]dns.A, *dns.Msg, time.Duration, error) {
	answers := make([]dns.A, 0)

	// Perform DNS query for A records
	msg, dur, err := d.Query(name, dns.TypeA)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect A records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.A); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryAAAA retrieves AAAA records for the given name.
func (d *DnsLookup) QueryAAAA(name string) ([]dns.AAAA, *dns.Msg, time.Duration, error) {
	answers := make([]dns.AAAA, 0)

	// Perform DNS query for AAAA records
	msg, dur, err := d.Query(name, dns.TypeAAAA)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect AAAA records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.AAAA); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryTXT retrieves TXT records for the given name.
func (d *DnsLookup) QueryTXT(name string) ([]dns.TXT, *dns.Msg, time.Duration, error) {
	answers := make([]dns.TXT, 0)

	// Perform DNS query for TXT records
	msg, dur, err := d.Query(name, dns.TypeTXT)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect TXT records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.TXT); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryDS retrieves DS records for the given name.
func (d *DnsLookup) QueryDS(name string) ([]dns.DS, *dns.Msg, time.Duration, error) {
	answers := make([]dns.DS, 0)

	// Perform DNS query for DS records
	msg, dur, err := d.Query(name, dns.TypeDS)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect DS records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.DS); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryDNSKEY retrieves DNSKEY records for the given name.
func (d *DnsLookup) QueryDNSKEY(name string) ([]dns.DNSKEY, *dns.Msg, time.Duration, error) {
	answers := make([]dns.DNSKEY, 0)

	// Perform DNS query for DNSKEY records
	msg, dur, err := d.Query(name, dns.TypeDNSKEY)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect DNSKEY records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.DNSKEY); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryRRSIG retrieves RRSIG records for the given name.
func (d *DnsLookup) QueryRRSIG(name string) ([]dns.RRSIG, *dns.Msg, time.Duration, error) {
	answers := make([]dns.RRSIG, 0)

	// Perform DNS query for RRSIG records
	msg, dur, err := d.Query(name, dns.TypeRRSIG)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect RRSIG records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.RRSIG); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryCNAME retrieves CNAME records for the given name.
func (d *DnsLookup) QueryCNAME(name string) ([]dns.CNAME, *dns.Msg, time.Duration, error) {
	answers := make([]dns.CNAME, 0)

	// Perform DNS query for CNAME records
	msg, dur, err := d.Query(name, dns.TypeCNAME)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect CNAME records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.CNAME); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryMX retrieves MX records for the given name.
func (d *DnsLookup) QueryMX(name string) ([]dns.MX, *dns.Msg, time.Duration, error) {
	answers := make([]dns.MX, 0)

	// Perform DNS query for MX records
	msg, dur, err := d.Query(name, dns.TypeMX)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect MX records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.MX); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryNS retrieves NS records for the given name.
func (d *DnsLookup) QueryNS(name string) ([]dns.NS, *dns.Msg, time.Duration, error) {
	answers := make([]dns.NS, 0)

	// Perform DNS query for NS records
	msg, dur, err := d.Query(name, dns.TypeNS)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect NS records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.NS); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryPTR retrieves PTR records for the given name.
func (d *DnsLookup) QueryPTR(name string) ([]dns.PTR, *dns.Msg, time.Duration, error) {
	answers := make([]dns.PTR, 0)

	// Perform DNS query for PTR records
	msg, dur, err := d.Query(name, dns.TypePTR)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect PTR records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.PTR); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QuerySOA retrieves SOA records for the given name.
func (d *DnsLookup) QuerySOA(name string) ([]dns.SOA, *dns.Msg, time.Duration, error) {
	answers := make([]dns.SOA, 0)

	// Perform DNS query for SOA records
	msg, dur, err := d.Query(name, dns.TypeSOA)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect SOA records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.SOA); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QuerySRV retrieves SRV records for the given name.
func (d *DnsLookup) QuerySRV(name string) ([]dns.SRV, *dns.Msg, time.Duration, error) {
	answers := make([]dns.SRV, 0)

	// Perform DNS query for SRV records
	msg, dur, err := d.Query(name, dns.TypeSRV)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect SRV records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.SRV); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryCAA retrieves CAA records for the given name.
func (d *DnsLookup) QueryCAA(name string) ([]dns.CAA, *dns.Msg, time.Duration, error) {
	answers := make([]dns.CAA, 0)

	// Perform DNS query for CAA records
	msg, dur, err := d.Query(name, dns.TypeCAA)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect CAA records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.CAA); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QueryNAPTR retrieves NAPTR records for the given name.
func (d *DnsLookup) QueryNAPTR(name string) ([]dns.NAPTR, *dns.Msg, time.Duration, error) {
	answers := make([]dns.NAPTR, 0)

	// Perform DNS query for NAPTR records
	msg, dur, err := d.Query(name, dns.TypeNAPTR)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect NAPTR records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.NAPTR); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

// QuerySPF retrieves SPF records for the given name.
func (d *DnsLookup) QuerySPF(name string) ([]dns.SPF, *dns.Msg, time.Duration, error) {
	answers := make([]dns.SPF, 0)

	// Perform DNS query for SPF records
	msg, dur, err := d.Query(name, dns.TypeSPF)
	if err != nil {
		return answers, msg, dur, err
	}

	// Process and collect SPF records from the response
	for _, record := range msg.Answer {
		if answer, ok := record.(*dns.SPF); ok {
			answers = append(answers, *answer)
		}
	}

	return answers, msg, dur, err
}

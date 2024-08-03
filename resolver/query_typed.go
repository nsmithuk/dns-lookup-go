package resolver

import (
	"github.com/miekg/dns"
)

// Not DRY, but easy to auto-generate, and means we have some nice strong typing for everything.

// QueryA performs a DNS query for A records
func (d *Resolver) QueryA(name string) ([]*dns.A, error) {
	msg, _, err := d.Query(name, dns.TypeA)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.A](msg.Answer), nil
}

// QueryAAAA performs a DNS query for AAAA records
func (d *Resolver) QueryAAAA(name string) ([]*dns.AAAA, error) {
	msg, _, err := d.Query(name, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.AAAA](msg.Answer), nil
}

// QueryCNAME performs a DNS query for CNAME records
func (d *Resolver) QueryCNAME(name string) ([]*dns.CNAME, error) {
	msg, _, err := d.Query(name, dns.TypeCNAME)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.CNAME](msg.Answer), nil
}

// QueryMX performs a DNS query for MX records
func (d *Resolver) QueryMX(name string) ([]*dns.MX, error) {
	msg, _, err := d.Query(name, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.MX](msg.Answer), nil
}

// QueryNS performs a DNS query for NS records
func (d *Resolver) QueryNS(name string) ([]*dns.NS, error) {
	msg, _, err := d.Query(name, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.NS](msg.Answer), nil
}

// QueryPTR performs a DNS query for PTR records
func (d *Resolver) QueryPTR(name string) ([]*dns.PTR, error) {
	msg, _, err := d.Query(name, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.PTR](msg.Answer), nil
}

// QuerySOA performs a DNS query for SOA records
func (d *Resolver) QuerySOA(name string) ([]*dns.SOA, error) {
	msg, _, err := d.Query(name, dns.TypeSOA)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.SOA](msg.Answer), nil
}

// QuerySRV performs a DNS query for SRV records
func (d *Resolver) QuerySRV(name string) ([]*dns.SRV, error) {
	msg, _, err := d.Query(name, dns.TypeSRV)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.SRV](msg.Answer), nil
}

// QueryTXT performs a DNS query for TXT records
func (d *Resolver) QueryTXT(name string) ([]*dns.TXT, error) {
	msg, _, err := d.Query(name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.TXT](msg.Answer), nil
}

// QueryDS performs a DNS query for DS records
func (d *Resolver) QueryDS(name string) ([]*dns.DS, error) {
	msg, _, err := d.Query(name, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.DS](msg.Answer), nil
}

// QueryDNSKEY performs a DNS query for DNSKEY records
func (d *Resolver) QueryDNSKEY(name string) ([]*dns.DNSKEY, error) {
	msg, _, err := d.Query(name, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	return extractRecordsOfType[*dns.DNSKEY](msg.Answer), nil
}

// QueryANY performs a DNS query for ANY records
func (d *Resolver) QueryANY(name string) ([]dns.RR, error) {
	msg, _, err := d.Query(name, dns.TypeANY)
	if err != nil {
		return nil, err
	}
	return msg.Answer, nil
}

package resolver

import (
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

// protocol defines the type for connection protocol.
type protocol string

// Constants representing supported connection protocol.
const (
	udp    protocol = "udp"
	tcp    protocol = "tcp"
	tcpTls protocol = "tcp-tls"
)

// DNSClient interface abstracts the dns.Client to allow mocking in tests.
type DNSClient interface {
	Exchange(m *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error)
}

// NameServer interface defines the methods for a DNS name server.
type NameServer interface {
	// Query perform the DNS query/lookup.
	Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error)

	// String returns a human-readable string representation of the NameServer's details.
	String() string
}

// LookupNameserver represents the details of a DNS name server, including protocol, address, port, and client.
type LookupNameserver struct {
	protocol protocol  // Connection protocol: udp, tcp, or tcp-tls
	domain   string    // Domain name for TLS certificate verification
	address  string    // IP address of the name server
	port     string    // Port number of the name server
	client   DNSClient // DNS client for sending queries
}

// NewUdpNameserver creates a LookupNameserver instance using UDP protocol.
func NewUdpNameserver(address, port string) NameServer {
	return &LookupNameserver{
		protocol: udp,
		address:  address,
		port:     port,
		client: &dns.Client{
			Net: string(udp),
		},
	}
}

// NewTcpNameserver creates a LookupNameserver instance using TCP protocol.
func NewTcpNameserver(address, port string) NameServer {
	return &LookupNameserver{
		protocol: tcp,
		address:  address,
		port:     port,
		client: &dns.Client{
			Net: string(tcp),
		},
	}
}

// NewTlsNameserver creates a LookupNameserver instance using TCP over TLS protocol.
// The domain parameter is required for TLS certificate verification.
func NewTlsNameserver(address, port, domain string) NameServer {
	return &LookupNameserver{
		protocol: tcpTls,
		address:  address,
		port:     port,
		domain:   domain,
		client: &dns.Client{
			Net: string(tcpTls),
			TLSConfig: &tls.Config{
				ServerName: domain,
			},
		},
	}
}

// String returns a human-readable string representation of the LookupNameserver details.
func (n LookupNameserver) String() string {
	details := fmt.Sprintf("%s://%s", n.protocol, n.getConnectionString())
	if n.domain != "" {
		details = fmt.Sprintf("%s#%s", details, n.domain)
	}
	return details
}

// getAddress returns the IP address of the LookupNameserver, formatted for IPv4 or IPv6.
func (n LookupNameserver) getAddress() string {
	if n.isIPv6() {
		return fmt.Sprintf("[%s]", n.address)
	}
	return n.address
}

// getConnectionString returns the connection string (address:port) of the LookupNameserver.
func (n LookupNameserver) getConnectionString() string {
	return fmt.Sprintf("%s:%s", n.getAddress(), n.port)
}

// isIPv6 checks if the LookupNameserver address is IPv6.
func (n LookupNameserver) isIPv6() bool {
	return strings.Count(n.address, ":") >= 2
}

// Query sends a DNS query to the LookupNameserver.
func (n LookupNameserver) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), rrtype)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true

	response, rtt, err := n.client.Exchange(msg, n.getConnectionString())
	if err != nil {
		return response, rtt, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return response, rtt, fmt.Errorf("query error returned (rcode %d)", response.Rcode)
	}

	return response, rtt, nil
}

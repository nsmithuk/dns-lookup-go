package lookup

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
	Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error)
	String() string
}

// NameServerConcrete represents the details of a DNS name server, including protocol, address, port, and client.
type NameServerConcrete struct {
	protocol protocol  // Connection protocol: udp, tcp, or tcp-tls
	domain   string    // Domain name for TLS certificate verification
	address  string    // IP address of the name server
	port     string    // Port number of the name server
	client   DNSClient // DNS client for sending queries
}

// NewUdpNameserver creates a NameServerConcrete instance using UDP protocol.
func NewUdpNameserver(address, port string) NameServer {
	return &NameServerConcrete{
		protocol: udp,
		address:  address,
		port:     port,
		client: &dns.Client{
			Net: string(udp),
		},
	}
}

// NewTcpNameserver creates a NameServerConcrete instance using TCP protocol.
func NewTcpNameserver(address, port string) NameServer {
	return &NameServerConcrete{
		protocol: tcp,
		address:  address,
		port:     port,
		client: &dns.Client{
			Net: string(tcp),
		},
	}
}

// NewTlsNameserver creates a NameServerConcrete instance using TCP over TLS protocol.
// The domain parameter is required for TLS certificate verification.
func NewTlsNameserver(address, port, domain string) NameServer {
	return &NameServerConcrete{
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

// String returns a human-readable string representation of the NameServerConcrete details.
func (n NameServerConcrete) String() string {
	details := fmt.Sprintf("%s://%s", n.protocol, n.getConnectionString())
	if n.domain != "" {
		details = fmt.Sprintf("%s#%s", details, n.domain)
	}
	return details
}

// getAddress returns the IP address of the NameServerConcrete, formatted for IPv4 or IPv6.
func (n NameServerConcrete) getAddress() string {
	if n.isIPv6() {
		return fmt.Sprintf("[%s]", n.address)
	}
	return n.address
}

// getConnectionString returns the connection string (address:port) of the NameServerConcrete.
func (n NameServerConcrete) getConnectionString() string {
	return fmt.Sprintf("%s:%s", n.getAddress(), n.port)
}

// isIPv6 checks if the NameServerConcrete address is IPv6.
func (n NameServerConcrete) isIPv6() bool {
	return strings.Count(n.address, ":") >= 2
}

// Query sends a DNS query to the NameServerConcrete.
func (n NameServerConcrete) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
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

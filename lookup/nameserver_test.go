package lookup

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockDNSClient is a mock implementation of the DNSClient interface for testing purposes.
type MockDNSClient struct {
	response *dns.Msg
	rtt      time.Duration
	err      error
	lastMsg  *dns.Msg
	lastAddr string
}

func (m *MockDNSClient) Exchange(msg *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
	m.lastMsg = msg
	m.lastAddr = address
	return m.response, m.rtt, m.err
}

func TestNewUdpNameserver(t *testing.T) {
	address := "127.0.0.1"
	port := "53"
	ns := NewUdpNameserver(address, port).(*NameServerConcrete)

	if ns.protocol != udp {
		t.Errorf("expected protocol %v, got %v", udp, ns.protocol)
	}
	if ns.address != address {
		t.Errorf("expected address %v, got %v", address, ns.address)
	}
	if ns.port != port {
		t.Errorf("expected port %v, got %v", port, ns.port)
	}
}

func TestNewTcpNameserver(t *testing.T) {
	address := "127.0.0.1"
	port := "53"
	ns := NewTcpNameserver(address, port).(*NameServerConcrete)

	if ns.protocol != tcp {
		t.Errorf("expected protocol %v, got %v", tcp, ns.protocol)
	}
	if ns.address != address {
		t.Errorf("expected address %v, got %v", address, ns.address)
	}
	if ns.port != port {
		t.Errorf("expected port %v, got %v", port, ns.port)
	}
}

func TestNewTlsNameserver(t *testing.T) {
	address := "127.0.0.1"
	port := "853"
	domain := "example.com"
	ns := NewTlsNameserver(address, port, domain).(*NameServerConcrete)

	if ns.protocol != tcpTls {
		t.Errorf("expected protocol %v, got %v", tcpTls, ns.protocol)
	}
	if ns.address != address {
		t.Errorf("expected address %v, got %v", address, ns.address)
	}
	if ns.port != port {
		t.Errorf("expected port %v, got %v", port, ns.port)
	}
	if ns.domain != domain {
		t.Errorf("expected domain %v, got %v", domain, ns.domain)
	}
	if ns.client.(*dns.Client).TLSConfig.ServerName != domain {
		t.Errorf("expected TLS ServerName %v, got %v", domain, ns.client.(*dns.Client).TLSConfig.ServerName)
	}
}

func TestNameServer_String(t *testing.T) {
	ns := NewTlsNameserver("127.0.0.1", "853", "example.com")
	expected := "tcp-tls://127.0.0.1:853#example.com"
	if ns.String() != expected {
		t.Errorf("expected %v, got %v", expected, ns.String())
	}
}

func TestNameServer_getAddress(t *testing.T) {
	ns := NewUdpNameserver("127.0.0.1", "53").(*NameServerConcrete)
	if ns.getAddress() != "127.0.0.1" {
		t.Errorf("expected %v, got %v", "127.0.0.1", ns.getAddress())
	}

	ns6 := NewUdpNameserver("::1", "53").(*NameServerConcrete)
	if ns6.getAddress() != "[::1]" {
		t.Errorf("expected %v, got %v", "[::1]", ns6.getAddress())
	}
}

func TestNameServer_getConnectionString(t *testing.T) {
	ns := NewUdpNameserver("127.0.0.1", "53").(*NameServerConcrete)
	expected := "127.0.0.1:53"
	if ns.getConnectionString() != expected {
		t.Errorf("expected %v, got %v", expected, ns.getConnectionString())
	}

	ns6 := NewUdpNameserver("::1", "53").(*NameServerConcrete)
	expected6 := "[::1]:53"
	if ns6.getConnectionString() != expected6 {
		t.Errorf("expected %v, got %v", expected6, ns6.getConnectionString())
	}
}

func TestNameServer_isIPv6(t *testing.T) {
	ns := NewUdpNameserver("127.0.0.1", "53").(*NameServerConcrete)
	if ns.isIPv6() {
		t.Errorf("expected false for IPv4 address, got true")
	}

	ns6 := NewUdpNameserver("::1", "53").(*NameServerConcrete)
	if !ns6.isIPv6() {
		t.Errorf("expected true for IPv6 address, got false")
	}
}

func TestNameServer_Query(t *testing.T) {
	mockRtt := 100 * time.Millisecond

	tests := []struct {
		name                  string
		rrtype                uint16
		nameserver            NameServer
		mockResponse          *dns.Msg
		mockRtt               time.Duration
		mockErr               error
		expectedErr           string
		expectedRcode         int
		expectedQuery         *dns.Msg
		expectedAuthenticated bool
	}{
		{
			name:                  "Successful query",
			rrtype:                dns.TypeA,
			nameserver:            &NameServerConcrete{protocol: udp, address: "8.8.8.8", port: "53", client: &MockDNSClient{response: newNameserverResponseMsgWithAD(dns.RcodeSuccess, true), rtt: mockRtt, err: nil}},
			mockResponse:          newNameserverResponseMsgWithAD(dns.RcodeSuccess, true),
			mockRtt:               mockRtt,
			expectedErr:           "",
			expectedRcode:         dns.RcodeSuccess,
			expectedQuery:         newNameserverQueryMsg("example.com", dns.TypeA),
			expectedAuthenticated: true,
		},
		{
			name:        "No nameserver set",
			rrtype:      dns.TypeA,
			nameserver:  nil,
			expectedErr: "invalid memory address or nil pointer dereference",
		},
		{
			name:                  "Query error with rcode",
			rrtype:                dns.TypeA,
			nameserver:            &NameServerConcrete{protocol: udp, address: "8.8.8.8", port: "53", client: &MockDNSClient{response: newNameserverResponseMsgWithAD(dns.RcodeNameError, true), rtt: mockRtt, err: nil}},
			mockResponse:          newNameserverResponseMsgWithAD(dns.RcodeNameError, true),
			mockRtt:               mockRtt,
			expectedErr:           "query error returned (rcode 3)",
			expectedRcode:         dns.RcodeNameError,
			expectedQuery:         newNameserverQueryMsg("example.com", dns.TypeA),
			expectedAuthenticated: true,
		},
		{
			name:                  "Exchange error",
			rrtype:                dns.TypeA,
			nameserver:            &NameServerConcrete{protocol: udp, address: "8.8.8.8", port: "53", client: &MockDNSClient{response: nil, rtt: mockRtt, err: fmt.Errorf("network error")}},
			mockResponse:          nil,
			mockRtt:               mockRtt,
			mockErr:               fmt.Errorf("network error"),
			expectedErr:           "network error",
			expectedQuery:         newNameserverQueryMsg("example.com", dns.TypeA),
			expectedAuthenticated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.nameserver != nil {
				tt.nameserver.(*NameServerConcrete).client = &MockDNSClient{
					response: tt.mockResponse,
					rtt:      tt.mockRtt,
					err:      tt.mockErr,
				}
			}

			if tt.nameserver != nil {
				resp, rtt, err := tt.nameserver.Query("example.com", tt.rrtype)

				if tt.expectedErr != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.expectedErr)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedRcode, resp.Rcode)
				}

				assert.Equal(t, tt.mockRtt, rtt)
				require.NotNil(t, tt.nameserver.(*NameServerConcrete).client.(*MockDNSClient).lastMsg)
				assert.Equal(t, tt.expectedQuery.Question, tt.nameserver.(*NameServerConcrete).client.(*MockDNSClient).lastMsg.Question)

				// Check if SetEdns0(4096, true) was called
				edns0 := tt.nameserver.(*NameServerConcrete).client.(*MockDNSClient).lastMsg.IsEdns0()
				require.NotNil(t, edns0)
				assert.Equal(t, uint16(4096), edns0.UDPSize())
				assert.True(t, edns0.Do())

				// Check if RecursionDesired is set to true
				assert.True(t, tt.nameserver.(*NameServerConcrete).client.(*MockDNSClient).lastMsg.RecursionDesired)

				// Check if AuthenticatedData is set correctly
				if tt.mockResponse != nil {
					assert.Equal(t, tt.expectedAuthenticated, resp.AuthenticatedData)
				}
			}
		})
	}
}

// newNameserverResponseMsgWithAD creates a new dns.Msg with the given Rcode and AuthenticatedData flag.
func newNameserverResponseMsgWithAD(rcode int, authenticatedData bool) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetRcode(msg, rcode)
	msg.AuthenticatedData = authenticatedData
	return msg
}

// newNameserverQueryMsg creates a new dns.Msg representing a query for a given name and rrtype.
func newNameserverQueryMsg(name string, rrtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), rrtype)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true
	return msg
}

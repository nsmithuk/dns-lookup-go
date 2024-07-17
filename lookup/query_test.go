package lookup

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDnsLookup_QueryFunction(t *testing.T) {
	tests := []struct {
		name                     string
		rrtype                   uint16
		nameservers              []*MockNameServer
		requireAuthenticatedData bool
		expectedErr              string
		expectedRcode            int
	}{
		{
			name:   "Successful query with one nameserver",
			rrtype: dns.TypeA,
			nameservers: []*MockNameServer{
				{response: newLookupResponseMsgWithAD(dns.RcodeSuccess, true), rtt: 100 * time.Millisecond, err: nil},
			},
			expectedErr:   "",
			expectedRcode: dns.RcodeSuccess,
		},
		{
			name:        "No nameservers set",
			rrtype:      dns.TypeA,
			nameservers: []*MockNameServer{},
			expectedErr: "no nameservers set",
		},
		{
			name:   "All nameservers return an error",
			rrtype: dns.TypeA,
			nameservers: []*MockNameServer{
				{response: nil, rtt: 100 * time.Millisecond, err: fmt.Errorf("network error")},
				{response: nil, rtt: 100 * time.Millisecond, err: fmt.Errorf("another network error")},
			},
			expectedErr: "no answer found on any configured nameserver",
		},
		{
			name:   "Require authenticated data but not provided",
			rrtype: dns.TypeA,
			nameservers: []*MockNameServer{
				{response: newLookupResponseMsgWithAD(dns.RcodeSuccess, false), rtt: 100 * time.Millisecond, err: nil},
			},
			requireAuthenticatedData: true,
			expectedErr:              "resolver dnssec authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := &DnsLookup{
				nameservers:              make([]NameServer, len(tt.nameservers)),
				RequireAuthenticatedData: tt.requireAuthenticatedData,
			}

			for i, ns := range tt.nameservers {
				lookup.nameservers[i] = ns
				ns.On("Query", "example.com.", tt.rrtype).Return(ns.response, ns.rtt, ns.err).Once()
			}

			resp, _, err := lookup.Query("example.com.", tt.rrtype)

			if tt.expectedErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
				if resp != nil {
					assert.Equal(t, tt.expectedRcode, resp.Rcode)
				}
			}

			for _, ns := range tt.nameservers {
				ns.AssertExpectations(t)
			}
		})
	}
}

// newLookupResponseMsgWithAD creates a new dns.Msg with the given Rcode and AuthenticatedData flag.
func newLookupResponseMsgWithAD(rcode int, authenticatedData bool) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetRcode(msg, rcode)
	msg.AuthenticatedData = authenticatedData
	if rcode == dns.RcodeSuccess {
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(127, 0, 0, 1),
			},
		}
	}
	return msg
}

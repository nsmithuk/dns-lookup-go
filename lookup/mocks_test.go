package lookup

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
	"time"
)

// MockNameServer represents a mock implementation of the NameServer interface.
type MockNameServer struct {
	mock.Mock
	response *dns.Msg
	rtt      time.Duration
	err      error
}

func (m *MockNameServer) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	args := m.Called(name, rrtype)
	if m.response != nil {
		return m.response, m.rtt, m.err
	}
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

func (m *MockNameServer) String() string {
	return "mock-nameserver"
}

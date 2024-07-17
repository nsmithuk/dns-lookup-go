package lookup

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

// MockNameServer is a mock implementation of the NameServer interface
type MockDnssecNameServer struct {
	mock.Mock
}

func (m *MockDnssecNameServer) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	args := m.Called(name, rrtype)
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

func (m *MockDnssecNameServer) String() string {
	return "mock-nameserver"
}

func TestAuthenticateFailMaxDepth(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)

	d := &DnsLookup{
		nameservers:            []NameServer{new(MockDnssecNameServer)},
		maxAuthenticationDepth: 3,
	}

	err := d.Authenticate(msg, context.WithValue(context.Background(), contextDepth, uint8(3)))
	assert.EqualError(t, err, "maximum authentication depth of 3 reached")
}

func TestAuthenticateValid(t *testing.T) {
	mockRecordChain, ds := mockCreateExampleComRecords()
	com, ds := mockCreateComRecords(ds)
	root, rootDs := mockCreateRootRecords(ds)

	mockRecordChain = append(mockRecordChain, com...)
	mockRecordChain = append(mockRecordChain, root...)

	//---

	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)
	msg.Answer = make([]dns.RR, 0)
	for _, r := range mockRecordChain {
		if r, ok := r.(*dns.A); ok && r.Header().Name == "test.example.com." {
			msg.Answer = append(msg.Answer, r)
		}
		if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "test.example.com." && r.TypeCovered == dns.TypeA {
			msg.Answer = append(msg.Answer, r)
		}
	}

	//---

	mockNameServer := new(MockDnssecNameServer)

	mockNameServer.On("Query", "example.com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "example.com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "example.com." && r.TypeCovered == dns.TypeDNSKEY {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	mockNameServer.On("Query", "example.com.", dns.TypeDS).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeDS)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DS); ok && r.Header().Name == "example.com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "example.com." && r.TypeCovered == dns.TypeDS {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	mockNameServer.On("Query", "com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "com." && r.TypeCovered == dns.TypeDNSKEY {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	mockNameServer.On("Query", "com.", dns.TypeDS).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("com.", dns.TypeDS)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DS); ok && r.Header().Name == "com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "com." && r.TypeCovered == dns.TypeDS {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	mockNameServer.On("Query", ".", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion(".", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "." && r.TypeCovered == dns.TypeDNSKEY {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	// The root DS is passed in RootDNSSECRecords

	//---

	d := &DnsLookup{
		nameservers:              []NameServer{mockNameServer},
		maxAuthenticationDepth:   3,
		RequireAuthenticatedData: false,
		RootDNSSECRecords:        []*dns.DS{rootDs},
	}

	err := d.Authenticate(msg, context.Background())
	assert.NoError(t, err)

	mockNameServer.AssertExpectations(t)
}

func TestAuthenticateSignatureExpired(t *testing.T) {
	mockRecordChain, ds := mockCreateExampleComRecords()
	com, ds := mockCreateComRecords(ds)
	root, rootDs := mockCreateRootRecords(ds)

	mockRecordChain = append(mockRecordChain, com...)
	mockRecordChain = append(mockRecordChain, root...)

	//---

	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)
	msg.Answer = make([]dns.RR, 0)
	for _, r := range mockRecordChain {
		if r, ok := r.(*dns.A); ok && r.Header().Name == "test.example.com." {
			msg.Answer = append(msg.Answer, r)
		}
		if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "test.example.com." && r.TypeCovered == dns.TypeA {
			msg.Answer = append(msg.Answer, r)
		}
	}

	//---

	mockNameServer := new(MockDnssecNameServer)

	mockNameServer.On("Query", "example.com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "example.com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "example.com." && r.TypeCovered == dns.TypeDNSKEY {
				//Override the dates such the signature has now expired.
				r.Inception = uint32(time.Now().Unix() - (3600 * 2))
				r.Expiration = uint32(time.Now().Unix() - 3600)
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	//---

	d := &DnsLookup{
		nameservers:              []NameServer{mockNameServer},
		maxAuthenticationDepth:   3,
		RequireAuthenticatedData: false,
		RootDNSSECRecords:        []*dns.DS{rootDs},
	}

	err := d.Authenticate(msg, context.Background())
	assert.ErrorContains(t, err,
		"received signature outside of the allowed inception or expiration range",
	)
}

func TestAuthenticateSignaturePreInception(t *testing.T) {
	mockRecordChain, ds := mockCreateExampleComRecords()
	com, ds := mockCreateComRecords(ds)
	root, rootDs := mockCreateRootRecords(ds)

	mockRecordChain = append(mockRecordChain, com...)
	mockRecordChain = append(mockRecordChain, root...)

	//---

	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)
	msg.Answer = make([]dns.RR, 0)
	for _, r := range mockRecordChain {
		if r, ok := r.(*dns.A); ok && r.Header().Name == "test.example.com." {
			msg.Answer = append(msg.Answer, r)
		}
		if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "test.example.com." && r.TypeCovered == dns.TypeA {
			msg.Answer = append(msg.Answer, r)
		}
	}

	//---

	mockNameServer := new(MockDnssecNameServer)

	mockNameServer.On("Query", "example.com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "example.com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "example.com." && r.TypeCovered == dns.TypeDNSKEY {
				//Override the dates such the signature has now expired.
				r.Inception = uint32(time.Now().Unix() + 3600)
				r.Expiration = uint32(time.Now().Unix() + (3600 * 2))
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	//---

	d := &DnsLookup{
		nameservers:              []NameServer{mockNameServer},
		maxAuthenticationDepth:   3,
		RequireAuthenticatedData: false,
		RootDNSSECRecords:        []*dns.DS{rootDs},
	}

	err := d.Authenticate(msg, context.Background())
	assert.ErrorContains(t, err,
		"received signature outside of the allowed inception or expiration range",
	)
}

func TestAuthenticateSignatureInvalid(t *testing.T) {
	mockRecordChain, ds := mockCreateExampleComRecords()
	com, ds := mockCreateComRecords(ds)
	root, rootDs := mockCreateRootRecords(ds)

	mockRecordChain = append(mockRecordChain, com...)
	mockRecordChain = append(mockRecordChain, root...)

	//---

	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)
	msg.Answer = make([]dns.RR, 0)
	for _, r := range mockRecordChain {
		if r, ok := r.(*dns.A); ok && r.Header().Name == "test.example.com." {
			// We change the IP address, so the signature is no longer valid.
			r.A = net.ParseIP("2.2.2.2")
			msg.Answer = append(msg.Answer, r)
		}
		if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "test.example.com." && r.TypeCovered == dns.TypeA {
			msg.Answer = append(msg.Answer, r)
		}
	}

	//---

	mockNameServer := new(MockDnssecNameServer)

	mockNameServer.On("Query", "example.com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "example.com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "example.com." && r.TypeCovered == dns.TypeDNSKEY {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	//---

	d := &DnsLookup{
		nameservers:              []NameServer{mockNameServer},
		maxAuthenticationDepth:   3,
		RequireAuthenticatedData: false,
		RootDNSSECRecords:        []*dns.DS{rootDs},
	}

	err := d.Authenticate(msg, context.Background())
	assert.ErrorContains(t, err,
		"bad signature",
	)
}

func TestAuthenticateSignatureKeyMissMatch(t *testing.T) {
	mockRecordChain, ds := mockCreateExampleComRecords()
	com, ds := mockCreateComRecords(ds)
	root, rootDs := mockCreateRootRecords(ds)

	mockRecordChain = append(mockRecordChain, com...)
	mockRecordChain = append(mockRecordChain, root...)

	//---

	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)
	msg.Answer = make([]dns.RR, 0)
	for _, r := range mockRecordChain {
		if r, ok := r.(*dns.A); ok && r.Header().Name == "test.example.com." {
			msg.Answer = append(msg.Answer, r)
		}
		if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "test.example.com." && r.TypeCovered == dns.TypeA {
			msg.Answer = append(msg.Answer, r)
		}
	}

	//---

	mockNameServer := new(MockDnssecNameServer)

	mockNameServer.On("Query", "example.com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		for _, r := range mockRecordChain {
			// We return the wrong keys; for .com rather than example.com
			if r, ok := r.(*dns.DNSKEY); ok && r.Header().Name == "com." {
				msg.Answer = append(msg.Answer, r)
			}
			if r, ok := r.(*dns.RRSIG); ok && r.Header().Name == "example.com." && r.TypeCovered == dns.TypeDNSKEY {
				msg.Answer = append(msg.Answer, r)
			}
		}
		return msg
	}(), time.Duration(0), nil).Once()

	//---

	d := &DnsLookup{
		nameservers:              []NameServer{mockNameServer},
		maxAuthenticationDepth:   3,
		RequireAuthenticatedData: false,
		RootDNSSECRecords:        []*dns.DS{rootDs},
	}

	err := d.Authenticate(msg, context.Background())
	assert.ErrorContains(t, err,
		"does not have a matching key",
	)
}

//---------------------------------------------------------------------------------------------
// Functions for generating a mock (self-signed) chain.

func mockGenerateDNSKEY(name string, flag uint16, algorithm uint8, bits int) (*dns.DNSKEY, crypto.Signer) {
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:     name,
			Rrtype:   dns.TypeDNSKEY,
			Class:    dns.ClassINET,
			Ttl:      0,
			Rdlength: 0,
		},
		Flags:     flag,
		Algorithm: algorithm,
		Protocol:  3,
	}

	secret, _ := key.Generate(bits)

	if signer, ok := secret.(*rsa.PrivateKey); ok {
		return key, signer
	} else if signer, ok := secret.(*ecdsa.PrivateKey); ok {
		return key, signer
	} else if signer, ok := secret.(ed25519.PrivateKey); ok {
		return key, signer
	}

	panic("unknown key type generation")
}

func mockGenerateRRSIG(key *dns.DNSKEY, signer crypto.Signer, rrset []dns.RR) *dns.RRSIG {
	rrsig := &dns.RRSIG{
		Inception:  uint32(time.Now().Unix() - 3600),
		Expiration: uint32(time.Now().Unix() + 3600),
		KeyTag:     key.KeyTag(),
		SignerName: key.Header().Name,
		Algorithm:  key.Algorithm,
	}
	rrsig.Sign(signer, rrset)
	return rrsig
}

func mockCreateExampleComRecords() ([]dns.RR, *dns.DS) {
	records := make([]dns.RR, 6)
	zone := "example.com."

	ksk, kskSecret := mockGenerateDNSKEY(zone, DNSKEY_KSK, dns.RSASHA256, 2024)
	zsk, zskSecret := mockGenerateDNSKEY(zone, DNSKEY_ZSK, dns.ECDSAP256SHA256, 256)

	records[0] = ksk
	records[1] = zsk

	//---

	a, _ := dns.NewRR(fmt.Sprintf("test.%s 3600 IN A 1.1.1.1", zone))
	records[2] = a

	rrsigA := mockGenerateRRSIG(zsk, zskSecret, []dns.RR{a})
	records[3] = rrsigA

	//---

	rrsigDNSKEY := mockGenerateRRSIG(ksk, kskSecret, []dns.RR{ksk, zsk})
	records[4] = rrsigDNSKEY

	//---

	ds := ksk.ToDS(dns.SHA256)
	records[5] = ds

	return records, ds
}

func mockCreateComRecords(childDS *dns.DS) ([]dns.RR, *dns.DS) {
	records := make([]dns.RR, 5)
	zone := "com."

	ksk, kskSecret := mockGenerateDNSKEY(zone, DNSKEY_KSK, dns.RSASHA512, 2024)
	zsk, zskSecret := mockGenerateDNSKEY(zone, DNSKEY_ZSK, dns.ECDSAP384SHA384, 384)

	records[0] = ksk
	records[1] = zsk

	//---

	rrsigDS := mockGenerateRRSIG(zsk, zskSecret, []dns.RR{childDS})
	records[2] = rrsigDS

	//---

	rrsigDNSKEY := mockGenerateRRSIG(ksk, kskSecret, []dns.RR{ksk, zsk})
	records[3] = rrsigDNSKEY

	//---

	ds := ksk.ToDS(dns.SHA384)
	records[4] = ds

	return records, ds
}

func mockCreateRootRecords(childDS *dns.DS) ([]dns.RR, *dns.DS) {
	records := make([]dns.RR, 5)
	zone := "."

	ksk, kskSecret := mockGenerateDNSKEY(zone, DNSKEY_KSK, dns.ED25519, 256)
	zsk, zskSecret := mockGenerateDNSKEY(zone, DNSKEY_ZSK, dns.ED25519, 256)

	records[0] = ksk
	records[1] = zsk

	//---

	rrsigDS := mockGenerateRRSIG(zsk, zskSecret, []dns.RR{childDS})
	records[2] = rrsigDS

	//---

	rrsigDNSKEY := mockGenerateRRSIG(ksk, kskSecret, []dns.RR{ksk, zsk})
	records[3] = rrsigDNSKEY

	//---

	ds := ksk.ToDS(dns.SHA512)
	records[4] = ds

	return records, ds
}

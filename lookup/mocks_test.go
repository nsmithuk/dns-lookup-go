package lookup

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
	"strings"
	"time"
)

// OriginalMockNameServer represents a mock implementation of the NameServer interface.
type OriginalMockNameServer struct {
	mock.Mock
	response *dns.Msg
	rtt      time.Duration
	err      error
}

func (m *OriginalMockNameServer) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	args := m.Called(name, rrtype)
	if m.response != nil {
		return m.response, m.rtt, m.err
	}
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

func (m *OriginalMockNameServer) String() string {
	return "mock-nameserver"
}

//-----------------------------------------------------------------------------------------------

type mockNameServer struct {
	mock.Mock

	rootDS *dns.DS

	zoneRoot       *mockNameServerZone // .
	zoneCom        *mockNameServerZone // com.
	zoneExampleCom *mockNameServerZone // example.com.
}

func (m *mockNameServer) String() string {
	return "mock-nameserver"
}

func (m *mockNameServer) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	name = strings.TrimRight(name, ".") + "." // Ensures the name ends with a period.
	args := m.Called(name, rrtype)
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

type mockNameServerZone struct {
	ksk       *dns.DNSKEY
	kskSigner crypto.Signer

	zsk       *dns.DNSKEY
	zskSigner crypto.Signer

	dnskeyRrsig *dns.RRSIG

	ds      *dns.DS
	dsRrsig *dns.RRSIG

	a      *dns.RR // Only used for the test.example.com.
	aRrsig *dns.RRSIG

	parent *mockNameServerZone
}

func (z *mockNameServerZone) rrsigA(inception, expiration int64) *dns.RRSIG {
	// Signed using the ZSK
	rrsig := &dns.RRSIG{
		Inception:  uint32(inception),
		Expiration: uint32(expiration),
		KeyTag:     z.zsk.KeyTag(),
		SignerName: z.zsk.Header().Name,
		Algorithm:  z.zsk.Algorithm,
	}
	rrsig.Sign(z.zskSigner, []dns.RR{*z.a})
	return rrsig
}

func (z *mockNameServerZone) rrsigDS(inception, expiration int64) *dns.RRSIG {
	// Signed using the ZSK
	rrsig := &dns.RRSIG{
		Inception:  uint32(inception),
		Expiration: uint32(expiration),
		KeyTag:     z.parent.zsk.KeyTag(),
		SignerName: z.parent.zsk.Header().Name,
		Algorithm:  z.parent.zsk.Algorithm,
	}
	rrsig.Sign(z.parent.zskSigner, []dns.RR{z.ds})
	return rrsig
}

func (z *mockNameServerZone) rrsigDNSKEY(inception, expiration int64) *dns.RRSIG {
	// Signed using the KSK
	rrsig := &dns.RRSIG{
		Inception:  uint32(inception),
		Expiration: uint32(expiration),
		KeyTag:     z.ksk.KeyTag(),
		SignerName: z.ksk.Header().Name,
		Algorithm:  z.ksk.Algorithm,
	}
	rrsig.Sign(z.kskSigner, []dns.RR{z.ksk, z.zsk})
	return rrsig
}

/*
We're going to mock an A record for test.example.com.
We're then going to mock the full DNSSEC chain for that record, down to the root.

We'll use a range of ciphers to cover a few options.
*/
func (m *mockNameServer) buildFullChain() *mockNameServer {
	inception := time.Now().Unix() - 60
	expiration := time.Now().Unix() + 60

	//---

	zone := "."
	root := new(mockNameServerZone)

	root.ksk, root.kskSigner = mockGenerateDNSKEY(zone, DNSKEY_KSK, dns.RSASHA512, 4096)
	root.zsk, root.zskSigner = mockGenerateDNSKEY(zone, DNSKEY_ZSK, dns.ED25519, 256)
	root.dnskeyRrsig = root.rrsigDNSKEY(inception, expiration)

	// The root DS is a special case we never look that up via a query.
	m.rootDS = root.ksk.ToDS(dns.SHA512)

	//---

	zone = "com."
	com := new(mockNameServerZone)

	com.parent = root

	com.ksk, com.kskSigner = mockGenerateDNSKEY(zone, DNSKEY_KSK, dns.RSASHA256, 2048)
	com.zsk, com.zskSigner = mockGenerateDNSKEY(zone, DNSKEY_ZSK, dns.ECDSAP384SHA384, 384)
	com.dnskeyRrsig = com.rrsigDNSKEY(inception, expiration)

	com.ds = com.ksk.ToDS(dns.SHA384)
	com.dsRrsig = com.rrsigDS(inception, expiration)

	//---

	zone = "example.com."
	example := new(mockNameServerZone)

	example.parent = com

	example.ksk, example.kskSigner = mockGenerateDNSKEY(zone, DNSKEY_KSK, dns.RSASHA256, 1024)
	example.zsk, example.zskSigner = mockGenerateDNSKEY(zone, DNSKEY_ZSK, dns.ECDSAP256SHA256, 256)
	example.dnskeyRrsig = example.rrsigDNSKEY(inception, expiration)

	// We add an A record to this zone.
	a, _ := dns.NewRR(fmt.Sprintf("test.%s 0 IN A 1.1.1.1", zone))
	example.a = &a
	example.aRrsig = example.rrsigA(inception, expiration)

	example.ds = example.ksk.ToDS(dns.SHA256)
	example.dsRrsig = example.rrsigDS(inception, expiration)

	//---

	m.zoneRoot = root
	m.zoneCom = com
	m.zoneExampleCom = example

	return m
}

/*
We'll support the following queries:
  - A test.example.com.
  - DNSKEY example.com.
  - DS example.com.
  - DNSKEY com.
  - DS com.
  - DNSKEY .
*/
func (m *mockNameServer) prepFullChain() *mockNameServer {
	//---
	// .

	m.On("Query", ".", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion(".", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		msg.Answer = append(msg.Answer, m.zoneRoot.zsk)
		msg.Answer = append(msg.Answer, m.zoneRoot.ksk)
		msg.Answer = append(msg.Answer, m.zoneRoot.dnskeyRrsig)
		return msg
	}(), time.Millisecond*10, nil)

	//---
	// com.

	m.On("Query", "com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		msg.Answer = append(msg.Answer, m.zoneCom.zsk)
		msg.Answer = append(msg.Answer, m.zoneCom.ksk)
		msg.Answer = append(msg.Answer, m.zoneCom.dnskeyRrsig)
		return msg
	}(), time.Millisecond*10, nil)

	m.On("Query", "com.", dns.TypeDS).Return(func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("com.", dns.TypeDS)
		msg.Answer = make([]dns.RR, 0)
		msg.Answer = append(msg.Answer, m.zoneCom.ds)
		msg.Answer = append(msg.Answer, m.zoneCom.dsRrsig)
		return msg
	}(), time.Millisecond*10, nil)

	//---
	// example.com.

	m.On("Query", "test.example.com.", dns.TypeA).Return(func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("test.example.com.", dns.TypeA)
		msg.Answer = make([]dns.RR, 0)
		msg.Answer = append(msg.Answer, *m.zoneExampleCom.a)
		msg.Answer = append(msg.Answer, m.zoneExampleCom.aRrsig)
		return msg
	}(), time.Millisecond*10, nil)

	m.On("Query", "example.com.", dns.TypeDNSKEY).Return(func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeDNSKEY)
		msg.Answer = make([]dns.RR, 0)
		msg.Answer = append(msg.Answer, m.zoneExampleCom.zsk)
		msg.Answer = append(msg.Answer, m.zoneExampleCom.ksk)
		msg.Answer = append(msg.Answer, m.zoneExampleCom.dnskeyRrsig)
		return msg
	}(), time.Millisecond*10, nil)

	m.On("Query", "example.com.", dns.TypeDS).Return(func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeDS)
		msg.Answer = make([]dns.RR, 0)
		msg.Answer = append(msg.Answer, m.zoneExampleCom.ds)
		msg.Answer = append(msg.Answer, m.zoneExampleCom.dsRrsig)
		return msg
	}(), time.Millisecond*10, nil)

	return m
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

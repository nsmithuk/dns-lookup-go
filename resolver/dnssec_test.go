package resolver

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAuthenticateValid(t *testing.T) {
	ns := new(mockNameServer).buildFullChain().prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   3,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.NoError(t, err)
}

func TestAuthenticateFailMaxDepth(t *testing.T) {
	ns := new(mockNameServer).buildFullChain().prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   2,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.EqualError(t, err, "maximum authentication depth of 2 reached")
}

func TestAuthenticateSignatureExpired(t *testing.T) {
	ns := new(mockNameServer).buildFullChain()

	//---

	// Pick an expiration that's in the past.
	inception := time.Now().Unix() - 120
	expiration := time.Now().Unix() - 60

	ns.zoneExampleCom.aRrsig = ns.zoneExampleCom.rrsigA(inception, expiration)

	//---

	ns.prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   3,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.ErrorContains(t, err,
		"received signature outside of the allowed inception or expiration range",
	)
}

func TestAuthenticateSignaturePreInception(t *testing.T) {
	ns := new(mockNameServer).buildFullChain()

	//---

	// Pick an inception that's in the future.
	inception := time.Now().Unix() + 60
	expiration := time.Now().Unix() + 120

	ns.zoneExampleCom.aRrsig = ns.zoneExampleCom.rrsigA(inception, expiration)

	//---

	ns.prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   3,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.ErrorContains(t, err,
		"received signature outside of the allowed inception or expiration range",
	)
}

func TestAuthenticateSignatureInvalid(t *testing.T) {
	ns := new(mockNameServer).buildFullChain()

	//---

	// We change the IP address so the original signature no longer aligns.
	a, _ := dns.NewRR("test.example.com. 0 IN A 2.2.2.2")
	ns.zoneExampleCom.a = &a

	//---

	ns.prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   3,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.ErrorContains(t, err,
		"bad signature",
	)
}

func TestAuthenticateSignatureNoRRSig(t *testing.T) {
	ns := new(mockNameServer).buildFullChain()

	//---

	// We'll take the signature from com and apply it to example.com.
	// This will result in the DNSKEY record having no RRSIG to be assigned to.
	ns.zoneExampleCom.dnskeyRrsig = ns.zoneCom.dnskeyRrsig

	//---

	ns.prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   3,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.ErrorContains(t, err,
		"was unable to be assigned to any RRSIG",
	)
}

func TestAuthenticateSignatureKeyMissMatch(t *testing.T) {
	ns := new(mockNameServer).buildFullChain()

	//---

	// We'll take the key from com and apply it to example.com.
	// This will result in no match key being found for the RRSIG
	ns.zoneExampleCom.zsk = ns.zoneCom.zsk

	//---

	ns.prepFullChain()

	d := &Resolver{
		nameservers:              []NameServer{ns},
		maxAuthenticationDepth:   3,
		RemotelyAuthenticateData: false,
		LocallyAuthenticateData:  true,
		RootDNSSECRecords:        []*dns.DS{ns.rootDS},
		EnableTrace:              true,
	}

	//---

	_, err := d.QueryA("test.example.com")
	assert.ErrorContains(t, err,
		"does not have a matching key",
	)
}

# Go DNS Lookup

A high-level API for [github.com/miekg/dns](https://github.com/miekg/dns).

DNS Lookup provides a simple Go based interface for performing DNS lookups against resolving nameservers, with local DNSSEC validation.

## Local DNSSEC Validation (Experimental)

DNS Lookup supports validating the DNSSEC trust chain locally, within Go.

This will take the full message response from your query and walk the DNS hierarchy, down to the root,
verifying the signatures of each domain label, and that the keys used to generate those signatures are verified
in the appropriate Delegation Signer (DS) records.

By default, the embedded trust anchors from [nsmithuk/dns-anchors-go](https://github.com/nsmithuk/dns-anchors-go) are used. 
Feel free to use these for convenience, however if you're serious about performing your own validation it is recommended to acquire and validate the root anchors independently to ensure trust in its content.
Use the included copy at your own risk.

You can download the `root-anchors.xml` file from [IANA DNSSEC files](https://www.iana.org/dnssec/files).
An example copy of root-anchors.xml is included in this repository. However, it is recommended to acquire and validate
this file independently to ensure trust in its content. Use the included copy at your own risk.

See [Supplying the Trust Anchors](#supplying-the-trust-anchors) below for details on how to use your own copy.

## Installation

To install the package, use:
```bash
go get github.com/nsmithuk/dns-lookup-go
```

## Basic Usage

Here is an example of how to use DNS Lookup to perform a basic DNS A record lookup:

```go
package main

import (
    "fmt"
    "github.com/nsmithuk/dns-lookup-go/lookup"
    "log"
)

func main() {
    
    client := lookup.NewDnsLookup([]lookup.NameServer{
        lookup.NewTlsNameserver("1.1.1.1", "853", "one.one.one.one"),
    })
    
    //---
    
    answers, err := client.QueryA("nsmith.net")
    if err != nil {
        // If DNSSEC validation fails, an error is returned.
        log.Fatalln(err)
    }
    
    fmt.Printf("%d answers found\n", len(answers))
    for i, answer := range answers {
        fmt.Printf("answer %d: %s\n", i, answer.String())
    }

}
```

## Multiple Nameservers

DNS Lookup supports three types of nameserver connections:
- Unencrypted UDP
- Unencrypted TCP
- Encrypted TLS (DoT)

All three support both IPv4 and IPv6 addresses.

When you set more than one nameserver:
- If a query fails to resolve on one server, it will be tried against all nameservers, and an error is returned if none succeed.
- The order in which the servers are selected is randomized per query to help balance load across them.


```go
package main

import (
    "fmt"
    "github.com/nsmithuk/dns-lookup-go/lookup"
    "log"
)

func main() {

    client := lookup.NewDnsLookup([]lookup.NameServer{
        lookup.NewUdpNameserver("1.1.1.1", "53"), // Unencrypted UDP example
        lookup.NewTcpNameserver("1.1.1.1", "53"), // Unencrypted TCP example
        lookup.NewTlsNameserver("1.1.1.1", "853", "one.one.one.one"), // Encrypted TCP example
        lookup.NewTlsNameserver("2606:4700:4700::1111", "853", "one.one.one.one"), // Encrypted TCP example over IPv6
    })
    
    //---
    
    answers, err := client.QueryA("nsmith.net")
    if err != nil {
        // If DNSSEC validation fails, an error is returned.
        log.Fatalln(err)
    }
    
    fmt.Printf("%d answers found\n", len(answers))
    for i, answer := range answers {
        fmt.Printf("answer %d: %s\n", i, answer.String())
    }

}
```

## Supplying the Trust Anchors

To supply your own copy of the trust anchors.

```go
package main

import (
    "fmt"
    "github.com/nsmithuk/dns-anchors-go/anchors"
    "github.com/nsmithuk/dns-lookup-go/lookup"
    "log"
)

func main() {

    client := lookup.NewDnsLookup([]lookup.NameServer{
        lookup.NewTlsNameserver("1.1.1.1", "853", "one.one.one.one"),
    })
    
    //---
    
    records, err := anchors.GetAllFromFile("root-anchors.xml")
    if err != nil {
        // Failed to load or parse the root anchors.
        log.Fatalln(err)
    }
    
    client.RootDNSSECRecords = records
    
    //---
    
    answers, err := client.QueryA("nsmith.net")
    if err != nil {
        // If DNSSEC validation fails, an error is returned.
        log.Fatalln(err)
    }
    
    fmt.Printf("%d answers found\n", len(answers))
    for i, answer := range answers {
        fmt.Printf("answer %d: %s\n", i, answer.String())
    }

}

```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
- [github.com/nsmithuk/dns-anchors-go license](https://github.com/nsmithuk/dns-anchors-go/blob/main/LICENSE)
- [github.com/rs/zerolog license](https://github.com/rs/zerolog/blob/master/LICENSE)
- [github.com/stretchr/testify license](https://github.com/stretchr/testify/blob/master/LICENSE)

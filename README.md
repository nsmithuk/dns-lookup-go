# dns-lookup-go

A high-level API for [github.com/miekg/dns](https://github.com/miekg/dns).

DNS Lookup provides a simple Go based interface for performing DNS lookups against resolving nameservers, with support for DNSSEC validation.

## Features
- Simple DNS lookup interface
- Resolver-based DNSSEC validation
- Local DNSSEC validation (experimental)

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
        lookup.NewTlsNameserver("8.8.8.8", "853", "dns.google"),
    })
    
    answers, _, _, err := client.QueryA("nsmith.net")
    if err != nil {
		log.Fatalf(err.Error())
    }
    
    fmt.Printf("%d answers found\n", len(answers))
    for i, answer := range answers {
        fmt.Printf("answer %d: %s\n", i, answer.String())
    }
}

```

## Resolver Based DNSSEC Validation

By default, DNS Lookup is strict on requiring authenticated data in response to a query. 
To disable this, set `client.RequireAuthenticatedData = false`.

```go
package main

import (
	"fmt"
	"github.com/nsmithuk/dns-lookup-go/lookup"
	"log"
)

func main() {
	client := lookup.NewDnsLookup([]lookup.NameServer{
		lookup.NewTlsNameserver("8.8.8.8", "853", "dns.google"),
	})

	client.RequireAuthenticatedData = false

	answers, _, _, err := client.QueryA("google.com")
	if err != nil {
		log.Fatalf(err.Error())
	}

	fmt.Printf("%d answers found\n", len(answers))
	for i, answer := range answers {
		fmt.Printf("answer %d: %s\n", i, answer.String())
	}
}

```

## Local DNSSEC Validation (Experimental)

DNS Lookup supports validating the DNSSEC trust chain locally within Go.

This will take the full message response from your query and walk the DNS hierarchy, down to the root, 
verifying the signatures of each domain label, and that the keys used to generate those signatures are verified 
in the appropriate Delegation Signer (DS) records. The root DS records must be provided manually, as discussed below.

You should acquire and validate the `root-anchors.xml` file from [IANA DNSSEC files](https://www.iana.org/dnssec/files).
An example copy of root-anchors.xml is included in this repository. However, it is recommended to acquire and validate 
this file independently to ensure trust in its content. Use the included copy at your own risk.

```go
package main

import (
	"context"
	"fmt"
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"github.com/nsmithuk/dns-lookup-go/lookup"
	"log"
	"os"
)

func main() {

	// Load the DNSSEC root anchors. Only needed if you're going to locally validate the trust chain with Authenticate().
	// Note that you should acquire and validate this file independently to ensure trust in its content.
	// The local copy is included for example only.
	xmlFile, err := os.Open("root-anchors.xml")
	if err != nil {
		panic(err)
	}
	defer xmlFile.Close()

	anchorsDSRecords, _ := anchors.GetValid(xmlFile)
	if err != nil {
		panic(err)
	}

	//---

	// Create the DNS Lookup Client
	client := lookup.NewDnsLookup([]lookup.NameServer{
		lookup.NewTlsNameserver("8.8.8.8", "853", "dns.google"),
	})

	client.RootDNSSECRecords = anchorsDSRecords

	// Perform the query
	answers, msg, _, err := client.QueryA("nsmith.net")
	if err != nil {
		log.Fatalf(err.Error())
	}

	// Locally authenticate the DNSSEC response
	err = client.Authenticate(msg, context.Background())
	if err != nil {
		log.Fatalf(err.Error())
	} else {
		fmt.Println("Response has been locally authenticated")
	}

	fmt.Printf("%d answers found\n", len(answers))
	for i, answer := range answers {
		fmt.Printf("answer %d: %s\n", i, answer.String())
	}
}

```

## Logging

Logging is support via [zerolog](https://github.com/rs/zerolog).

```go
package main

import (
	"context"
	"fmt"
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"github.com/nsmithuk/dns-lookup-go/lookup"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

func main() {

	// Load the DNSSEC root anchors. Only needed if you're going to locally validate the trust chain with Authenticate().
	// Note that you should acquire and validate this file independently to ensure trust in its content.
	// The local copy is included for example only.
	xmlFile, err := os.Open("root-anchors.xml")
	if err != nil {
		panic(err)
	}
	defer xmlFile.Close()

	anchorsDSRecords, _ := anchors.GetValid(xmlFile)
	if err != nil {
		panic(err)
	}

	//---

	// Create the DNS Lookup Client
	client := lookup.NewDnsLookup([]lookup.NameServer{
		lookup.NewTlsNameserver("8.8.8.8", "853", "dns.google"),
	})

	client.RootDNSSECRecords = anchorsDSRecords

	//---

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	client.SetLogger(log.Logger)

	//---

	// Perform the query
	answers, msg, _, err := client.QueryA("nsmith.net")
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	// Locally authenticate the DNSSEC response
	err = client.Authenticate(msg, context.Background())
	if err != nil {
		log.Fatal().Err(err).Send()
	} else {
		fmt.Println("Response has been locally authenticated")
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

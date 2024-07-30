package main

import (
	"fmt"
	"github.com/nsmithuk/dns-lookup-go/lookup"
	"log"
)

func main() {

	client := lookup.NewDnsLookup([]lookup.NameServer{
		//lookup.NewUdpNameserver("1.1.1.1", "53"), // Unencrypted UDP example
		//lookup.NewTcpNameserver("1.1.1.1", "53"),	// Unencrypted TCP example
		lookup.NewTlsNameserver("1.1.1.1", "853", "one.one.one.one"),
		//lookup.NewTlsNameserver("2606:4700:4700::1111", "853", "one.one.one.one"),
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

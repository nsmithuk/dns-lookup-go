package main

import (
	"context"
	"fmt"
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"github.com/nsmithuk/dns-lookup-go/lookup"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"time"
)

func main() {

	client := lookup.NewDnsLookup([]lookup.NameServer{
		//lookup.NewUdpNameserver("8.8.8.8", "53"),	// Unencrypted UDP example
		//lookup.NewTcpNameserver("8.8.8.8", "53"),	// Unencrypted TCP example
		lookup.NewTlsNameserver("8.8.8.8", "853", "dns.google"),
		lookup.NewTlsNameserver("2001:4860:4860::8888", "853", "dns.google"),
	})

	//---

	// Setup logging (optional)
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().UTC()
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	client.SetLogger(log.Logger)

	//---

	// Load the DNSSEC root anchors. Only needed if you're going to locally validate the trust chain with Authenticate().
	// Note that you should acquire and validate this file independently to ensure trust in its content.
	// The local copy is included for example only.
	xmlFile, err := os.Open("root-anchors.xml")
	if err != nil {
		panic(err)
	}
	defer xmlFile.Close()

	anchors, _ := anchors.GetValid(xmlFile)
	if err != nil {
		panic(err)
	}

	// If you'll be calling Authenticate()
	client.RootDNSSECRecords = anchors

	//---

	answers, msg, _, err := client.QueryA("nsmith.net")
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	err = client.Authenticate(msg, context.Background())
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	fmt.Printf("%d answers found\n", len(answers))
	for i, answer := range answers {
		fmt.Printf("answer %d: %s\n", i, answer.String())
	}

	//---

	// We expect an error as dnssec authentication will fail.
	_, _, _, err = client.QueryA("dnssec-failed.org")
	if err != nil {
		log.Error().Err(err).Send()
	}
}

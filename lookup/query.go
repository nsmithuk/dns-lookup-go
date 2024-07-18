package lookup

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"math/rand"
	"time"
)

type DnsLookup struct {
	logger                   zerolog.Logger
	nameservers              []NameServer
	RootDNSSECRecords        []*dns.DS
	RequireAuthenticatedData bool
	maxAuthenticationDepth   uint8
}

func NewDnsLookup(nameservers []NameServer) *DnsLookup {
	return &DnsLookup{
		logger:                   zerolog.New(io.Discard),
		nameservers:              nameservers,
		RequireAuthenticatedData: true,
		maxAuthenticationDepth:   10,
	}
}

func (d *DnsLookup) SetLogger(l zerolog.Logger) {
	d.logger = l
}

func (d *DnsLookup) getNameservers() []NameServer {
	if len(d.nameservers) > 1 {
		rand.Shuffle(len(d.nameservers), func(i, j int) {
			d.nameservers[i], d.nameservers[j] = d.nameservers[j], d.nameservers[i]
		})
	}
	return d.nameservers
}

func (d *DnsLookup) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	nameservers := d.getNameservers()

	if len(nameservers) < 1 {
		return nil, 0, fmt.Errorf("no nameservers set")
	}

	logger := d.logger.With().Str("domain", name).Str("type", rrtypeToString(rrtype)).Logger()

	logger.Info().Msg("Performing DNS query")
	logger.Debug().Interface("nameservers", nameservers).Msg("Using nameservers")

	var totalDuration time.Duration
	for _, nameserver := range nameservers {

		logger.Debug().Str("nameserver", nameserver.String()).Msg("Nameserver selected")

		result, duration, err := nameserver.Query(name, rrtype)
		totalDuration = totalDuration + duration

		if err != nil {
			logger.Warn().Dur("latency", duration).Str("nameserver", nameserver.String()).Err(err).
				Msg("Issue resolving query. If there are other nameservers they will still be tried.")
			continue
		}

		//---

		if d.RequireAuthenticatedData && !result.AuthenticatedData {
			logger.Error().Dur("latency", duration).Str("nameserver", nameserver.String()).
				Msg("Resolver dnssec authentication failed")
			return nil, totalDuration, fmt.Errorf("resolver dnssec authentication failed")
		}

		//---

		if e := log.Debug(); e.Enabled() {
			logger.Debug().Dur("latency", duration).Str("nameserver", nameserver.String()).
				Bool("authenticated-data-flag", result.AuthenticatedData).
				Int("number-of-answers", len(result.Answer)).
				Strs("answers", rrsetToStrings(result.Answer)).
				Msg("Answer to query found")
		} else {
			logger.Info().Dur("latency", duration).Str("nameserver", nameserver.String()).
				Bool("authenticated-data-flag", result.AuthenticatedData).
				Int("number-of-answers", len(result.Answer)).
				Msg("Answer to query found")
		}

		return result, totalDuration, err
	}

	//---

	err := fmt.Errorf("no answer found on any configured nameserver")
	logger.Warn().Dur("latency", totalDuration).Msg("No answer found on any configured nameserver")

	return nil, totalDuration, err
}

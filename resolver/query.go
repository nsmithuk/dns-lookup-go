package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"math/rand"
	"time"
)

type Resolver struct {
	logger                   zerolog.Logger
	nameservers              []NameServer
	RootDNSSECRecords        []*dns.DS
	LocallyAuthenticateData  bool
	RemotelyAuthenticateData bool
	RandomNameserver         bool
	maxAuthenticationDepth   uint8
	Trace                    *AuthenticationTrace
	EnableTrace              bool
}

func NewResolver(nameservers []NameServer) *Resolver {
	return &Resolver{
		logger:                   zerolog.New(io.Discard),
		nameservers:              nameservers,
		LocallyAuthenticateData:  true,
		RemotelyAuthenticateData: true,
		RandomNameserver:         true,
		maxAuthenticationDepth:   10,
		RootDNSSECRecords:        anchors.GetAllFromEmbedded(),
		EnableTrace:              false,
	}
}

func (d *Resolver) getNameservers() []NameServer {
	if d.RandomNameserver && len(d.nameservers) > 1 {
		rand.Shuffle(len(d.nameservers), func(i, j int) {
			d.nameservers[i], d.nameservers[j] = d.nameservers[j], d.nameservers[i]
		})
	}
	return d.nameservers
}

func (d *Resolver) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	ctx := context.Background()

	if d.EnableTrace {
		d.Trace = new(AuthenticationTrace)
		ctx = context.WithValue(ctx, contextTrace, d.Trace)
	}

	msg, latency, err := d.query(name, rrtype, ctx)
	if err != nil {
		return nil, latency, err
	}

	if d.LocallyAuthenticateData {
		err = d.Authenticate(msg, ctx)
		if err != nil {
			return nil, latency, err
		}
	}

	return msg, latency, err
}

func (d *Resolver) query(name string, rrtype uint16, ctx context.Context) (*dns.Msg, time.Duration, error) {
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

		if d.RemotelyAuthenticateData && !result.AuthenticatedData {
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

		//---

		if trace, ok := ctx.Value(contextTrace).(*AuthenticationTrace); ok {
			trace.Add(newAuthenticationTraceLookup(name, rrtype, nameserver.String(), duration, result.Answer))
		}

		//--

		return result, totalDuration, err
	}

	//---

	err := fmt.Errorf("no answer found on any configured nameserver")
	logger.Warn().Dur("latency", totalDuration).Msg("No answer found on any configured nameserver")

	return nil, totalDuration, err
}

//-----

// extractRecordsOfType Given a slice of RR, returns all instances within it of type T, cast to type T.
func extractRecordsOfType[T dns.RR](rr []dns.RR) []T {
	var result []T
	for _, record := range rr {
		if typedRecord, ok := record.(T); ok {
			result = append(result, typedRecord)
		}
	}
	return result
}

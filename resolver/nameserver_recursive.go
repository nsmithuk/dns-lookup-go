package resolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

//-------------------------------------------------------------------------------------
// RecursiveNameserver

type RecursiveNameserver struct {
	rootZoneResolver *zoneResolver
	maxQueryCount    uint8
	Trace            *RecursiveQueryTrace
	EnableTrace      bool
	factory          func(address, port string) NameServer
}

func NewRecursiveNameserver() *RecursiveNameserver {
	rns := &RecursiveNameserver{
		rootZoneResolver: newRootZoneResolver(),
		maxQueryCount:    30,
		EnableTrace:      false,
		factory: func(address, port string) NameServer {
			return NewUdpNameserver(address, port)
		},
	}
	rns.rootZoneResolver.server = rns
	return rns
}

func (n *RecursiveNameserver) String() string {
	return "Local Recursive Nameserver"
}

func (n *RecursiveNameserver) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	start := time.Now()
	ctx := context.Background()

	if n.EnableTrace {
		n.Trace = new(RecursiveQueryTrace)
		ctx = context.WithValue(ctx, contextTrace, n.Trace)
	}

	var queryCounter uint8

	msg, err := n.rootZoneResolver.query(name, rrtype, ctx, &queryCounter)

	return msg, time.Since(start), err
}

//-------------------------------------------------------------------------------------
// Error Setup

var ErrMaxDepth = NewHardError("max allowed recursion depth reached")

// HardError implies that we should stop all attempts to continue.
// 'Normal' errors may result in more nameservers being tried.
type HardError struct {
	s string
}

func NewHardError(s string) error {
	return &HardError{s: s}
}

func (e *HardError) Error() string {
	return e.s
}

// An instance of a HardError to be referenced
var hardError *HardError

//-------------------------------------------------------------------------------------
// zoneResolver

type zoneResolver struct {
	server *RecursiveNameserver // set only on the root

	nsA map[string]NameServer
	//nsAAAA    map[string]NameServer // TODO: Add IPv6 support.

	records []dns.RR // TODO: We're recording these, but not using them. Can we get rid of this?

	parent   *zoneResolver // nil on the root
	children map[string]*zoneResolver
}

func newZoneResolver() *zoneResolver {
	return &zoneResolver{
		nsA:      make(map[string]NameServer),
		records:  make([]dns.RR, 0),
		children: make(map[string]*zoneResolver),
	}
}

func newRootZoneResolver() *zoneResolver {
	root := newZoneResolver()

	root.nsA["a.root-servers.net."] = NewUdpNameserver("198.41.0.4", "53")
	root.nsA["b.root-servers.net."] = NewUdpNameserver("170.247.170.2", "53")
	root.nsA["c.root-servers.net."] = NewUdpNameserver("192.33.4.12", "53")
	root.nsA["d.root-servers.net."] = NewUdpNameserver("199.7.91.13", "53")
	root.nsA["e.root-servers.net."] = NewUdpNameserver("192.203.230.10", "53")
	root.nsA["f.root-servers.net."] = NewUdpNameserver("192.5.5.241", "53")
	root.nsA["g.root-servers.net."] = NewUdpNameserver("192.112.36.4", "53")
	root.nsA["h.root-servers.net."] = NewUdpNameserver("198.97.190.53", "53")
	root.nsA["i.root-servers.net."] = NewUdpNameserver("192.36.148.17", "53")
	root.nsA["j.root-servers.net."] = NewUdpNameserver("192.58.128.30", "53")
	root.nsA["k.root-servers.net."] = NewUdpNameserver("193.0.14.129", "53")
	root.nsA["l.root-servers.net."] = NewUdpNameserver("199.7.83.42", "53")
	root.nsA["m.root-servers.net."] = NewUdpNameserver("202.12.27.33", "53")

	return root
}

func (z *zoneResolver) getRootZoneResolver() *zoneResolver {
	// root's parent will always be nil
	if z.parent == nil {
		return z
	}
	return z.parent.getRootZoneResolver()
}

func (z *zoneResolver) getRecursiveNameserver() *RecursiveNameserver {
	// The RecursiveNameserver is referenced in the root zone resolver.
	return z.getRootZoneResolver().server
}

func (z *zoneResolver) query(name string, rrtype uint16, ctx context.Context, queryCount *uint8) (*dns.Msg, error) {
	name = strings.TrimRight(name, ".") + "." // Always ensure the name ends with a dot.

	// First we try all nameservers that we already know the IP address of.
	for hostname, ns := range z.nsA {
		if ns != nil {
			msg, err := z.queryNameserver(hostname, ns, name, rrtype, ctx, queryCount)
			if err == nil && len(msg.Answer) > 0 {
				// If we found an answer, return
				return msg, nil
			} else if errors.As(err, &hardError) {
				return nil, err
			}
		}
	}

	//---

	// Otherwise we'll have to go and lookup the IP address of other nameservers.
	for hostname, ns := range z.nsA {
		if ns == nil {
			// Resolve NS IP
			msg, err := z.getRootZoneResolver().query(hostname, dns.TypeA, ctx, queryCount)
			if err != nil || len(msg.Answer) == 0 {
				// We return on a max error depth
				if errors.As(err, &hardError) {
					return nil, err
				}
				// Otherwise we continue to try the next nameserver
				continue
			}
			// TODO: what to do if more than one IP address is returned?
			z.nsA[hostname] = NewUdpNameserver(msg.Answer[0].(*dns.A).A.String(), "53")
			//---
			msg, err = z.queryNameserver(hostname, z.nsA[hostname], name, rrtype, ctx, queryCount)
			if err == nil && len(msg.Answer) > 0 {
				// If we found an answer, return
				return msg, nil
			} else if errors.As(err, &hardError) {
				return nil, err
			}
		}
	}

	//---

	// We only end up here if we've run out of nameservers to ask.
	return nil, fmt.Errorf("unable to find answer")
}

func (z *zoneResolver) queryNameserver(nsHostname string, ns NameServer, name string, rrtype uint16, ctx context.Context, queryCount *uint8) (*dns.Msg, error) {
	depth, _ := ctx.Value(contextDepth).(uint8)

	// Safety check to make sure we don't get into some silly loops.
	if *queryCount > z.getRecursiveNameserver().maxQueryCount {
		return nil, NewHardError(fmt.Sprintf("max allowed query count of %d reached. somthing has likely gone wrong", *queryCount))
	}
	*queryCount++

	//---

	msg, duration, err := ns.Query(name, rrtype)
	if err != nil {
		return nil, err
	}

	//---

	if trace, ok := ctx.Value(contextTrace).(*RecursiveQueryTrace); ok {
		trace.Add(newRecursiveQueryTraceLookup(depth, name, rrtype, nsHostname, ns.String(), duration, msg))
	}

	//---

	if len(msg.Answer) > 0 {
		// If we found an answer, return
		return msg, nil
	}

	//---

	// If the answer is authoritative, but contained no records, then the desired record does not exist.
	if msg.Authoritative {
		return nil, NewHardError("record does not exist")
	}

	//---

	// First we find a record the hostname for all nameservers
	for _, record := range msg.Ns {
		var ok bool
		var child *zoneResolver
		if child, ok = z.children[record.Header().Name]; !ok {
			child = newZoneResolver()
			child.parent = z
			z.children[record.Header().Name] = child
		}

		// Records all responses in this
		switch r := record.(type) {
		case *dns.NS:
			// If we don't already know it, add it.
			if _, ok := child.nsA[r.Hdr.Name]; !ok {
				child.nsA[r.Ns] = nil
			}
		default:
			// Ends up with things like RRSIG records in.
			// TODO: we don't use these, can we stop storing them.
			//child.records = append(child.records, r)
		}
	}

	// We try and find the glue IP address records for any of the hostnames found above.
	for _, record := range msg.Extra {
		for _, child := range z.children {
			switch r := record.(type) {
			case *dns.A:
				if _, ok := child.nsA[r.Hdr.Name]; ok {
					child.nsA[r.Hdr.Name] = z.getRecursiveNameserver().factory(r.A.String(), "53")
				}
			}
		}
	}

	//---

	// We only look at children that align with the correct suffix
	// TODO: this should always works, but might not always pick the best child first.
	for childZoneName, child := range z.children {
		if strings.HasSuffix(name, childZoneName) {
			msg, err := child.query(name, rrtype, context.WithValue(ctx, contextDepth, depth+1), queryCount)
			if err == nil && len(msg.Answer) > 0 {
				// If we found an answer, return
				return msg, nil
			} else if errors.As(err, &hardError) {
				return nil, err
			}
		}
	}

	return nil, fmt.Errorf("unable to find answer")
}

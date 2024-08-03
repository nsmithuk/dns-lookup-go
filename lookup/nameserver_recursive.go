package lookup

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

type RecursiveNameserver struct {
	rootZoneResolver  *ZoneResolver
	maxRecursionDepth uint8
}

func NewRecursiveNameserver() *RecursiveNameserver {
	return &RecursiveNameserver{
		rootZoneResolver:  newRootZoneResolver(),
		maxRecursionDepth: 20,
	}
}

func (n *RecursiveNameserver) String() string {
	return "Local Recursive Nameserver"
}

func (n *RecursiveNameserver) Query(name string, rrtype uint16) (*dns.Msg, time.Duration, error) {
	start := time.Now()
	msg, err := n.rootZoneResolver.query(
		name,
		rrtype,
		context.WithValue(context.Background(), contextDepthMax, n.maxRecursionDepth),
	)
	elapsed := time.Since(start)
	return msg, elapsed, err
}

//---

var ErrMaxDepth = errors.New("max allowed recursion depth reached")

type ZoneResolver struct {
	//name string

	nsA map[string]NameServer // maybe a net.Addr?
	//nsAAAA    map[string]NameServer // TODO: Add IPv6 support.

	records []dns.RR

	parent   *ZoneResolver
	children map[string]*ZoneResolver
}

func newZoneResolver(name string) *ZoneResolver {
	return &ZoneResolver{
		//name: name,

		nsA: make(map[string]NameServer),

		records:  make([]dns.RR, 0),
		children: make(map[string]*ZoneResolver),
	}
}

func newRootZoneResolver() *ZoneResolver {
	root := newZoneResolver(".")

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

func (z *ZoneResolver) getRootZoneResolver() *ZoneResolver {
	// root's parent will always be nil
	if z.parent == nil {
		return z
	}
	return z.parent.getRootZoneResolver()
}

func (z *ZoneResolver) query(name string, rrtype uint16, ctx context.Context) (*dns.Msg, error) {
	// Retrieve the depth from the context, default to 0 if not found
	depth, _ := ctx.Value(contextDepth).(uint8)
	depthMax, ok := ctx.Value(contextDepthMax).(uint8)
	if !ok {
		depthMax = 20 // Use a default for it this isn't passed
	}

	if depth > depthMax {
		return nil, ErrMaxDepth
	}

	// Bump the depth by one for the next call.
	ctx = context.WithValue(ctx, contextDepth, depth+1)

	//---

	name = strings.TrimRight(name, ".") + "." // Always ensure the name ends with a dot.

	// First we try all nameservers that we already know the IP address of.
	for _, ns := range z.nsA {
		if ns != nil {
			msg, err := z.queryNameserver(ns.(*NameServerConcrete), name, rrtype, ctx)
			if err == nil && len(msg.Answer) > 0 {
				// If we found an answer, return
				return msg, nil
			} else if errors.Is(err, ErrMaxDepth) {
				return nil, err
			}
		}
	}

	//---

	// Otherwise we'll have to go and lookup the IP address of other nameservers.
	for hostname, ns := range z.nsA {
		if ns == nil {
			// Resolve NS IP
			msg, err := z.getRootZoneResolver().query(hostname, dns.TypeA, ctx)
			if err != nil || len(msg.Answer) == 0 {
				// We return on a max error depth
				if errors.Is(err, ErrMaxDepth) {
					return nil, err
				}
				// Otherwise we continue to try the next nameserver
				continue
			}
			// TODO: what to do if more than one IP address is returned?
			z.nsA[hostname] = NewUdpNameserver(msg.Answer[0].(*dns.A).A.String(), "53")
			//---
			msg, err = z.queryNameserver(z.nsA[hostname].(*NameServerConcrete), name, rrtype, ctx)
			if err == nil && len(msg.Answer) > 0 {
				// If we found an answer, return
				return msg, nil
			} else if errors.Is(err, ErrMaxDepth) {
				return nil, err
			}
		}
	}

	//---

	// We only end up here if we've run out of nameservers to ask.
	return nil, fmt.Errorf("unable to find answer")
}

func (z *ZoneResolver) queryNameserver(ns *NameServerConcrete, name string, rrtype uint16, ctx context.Context) (*dns.Msg, error) {
	msg, _, err := ns.Query(name, rrtype)
	if err != nil {
		return nil, err
	}

	//---

	if len(msg.Answer) > 0 {
		// If we found an answer, return
		return msg, nil
	}

	//---

	// First we find a record the hostname for all nameservers
	for _, record := range msg.Ns {
		var ok bool
		var child *ZoneResolver
		if child, ok = z.children[record.Header().Name]; !ok {
			child = newZoneResolver(record.Header().Name)
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
			child.records = append(child.records, r)
		}
	}

	// We try and find the glue IP address records for any of the hostnames found above.
	for _, record := range msg.Extra {
		for _, child := range z.children {
			switch r := record.(type) {
			case *dns.A:
				if _, ok := child.nsA[r.Hdr.Name]; ok {
					child.nsA[r.Hdr.Name] = NewUdpNameserver(r.A.String(), "53")
				}
			}
		}
	}

	//---

	// We only look at children that align with the correct suffix
	// TODO: this should always works, but might not always pick the best child first.
	for childZoneName, child := range z.children {
		if strings.HasSuffix(name, childZoneName) {
			msg, err := child.query(name, rrtype, ctx)
			if err == nil && len(msg.Answer) > 0 {
				// If we found an answer, return
				return msg, nil
			} else if errors.Is(err, ErrMaxDepth) {
				return nil, err
			}
		}
	}

	return nil, fmt.Errorf("unable to find answer")
}

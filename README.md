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

## Enable Validation Tracing
Validation tracing allows you to examine the steps that DNS Lookup took to authenticate a given query.

You enable tracing by calling `client.EnableTrace = true`. Once a query is complete, you can access the trace via `client.Trace`. Note - enabling and using tracing is not thread safe.

You're able to examine the returned object yourself. Or you can make use of the [nsmithuk/dns-lookup-go-trace](https://github.com/nsmithuk/dns-lookup-go-trace)
package which supports pretty printing.

### Example
```go
package main

import (
    "fmt"
    "github.com/nsmithuk/dns-lookup-go-trace/trace"
    "github.com/nsmithuk/dns-lookup-go/lookup"
    "log"
)

func main() {

    client := lookup.NewDnsLookup([]lookup.NameServer{
        lookup.NewTlsNameserver("1.1.1.1", "853", "one.one.one.one"),
    })
    
    //---
    
    // Enable validation tracing on the client
    client.EnableTrace = true
    
    answers, err := client.QueryA("nsmith.net")
    if err != nil {
        // If DNSSEC validation fails, an error is returned.
        log.Fatalln(err)
    }
    
    fmt.Printf("%d answers found\n", len(answers))
    for i, answer := range answers {
        fmt.Printf("answer %d: %s\n", i, answer.String())
    }
    
    //---
    
    // Return the trace from the client
    // You can manually inspect its properties to see what happened.
    t := client.Trace
    
    // And/or you can use the `trace` package to pretty print it to the console.
    fmt.Println(trace.GetConsoleTree(t))
}

```

Gives
```console
3 answers found
answer 0: nsmith.net.	60	IN	A	3.9.215.101
answer 1: nsmith.net.	60	IN	A	18.133.128.244
answer 2: nsmith.net.	60	IN	A	18.175.11.59
╭─ DNS Lookup
│  ├─ for: A nsmith.net
│  ├─ on: tcp-tls://1.1.1.1:853#one.one.one.one
│  ├─ taking: 35.586917ms
│  ╰─ answers:
│     ├─ nsmith.net. 60 IN A 3.9.215.101
│     ├─ nsmith.net. 60 IN A 18.133.128.244
│     ├─ nsmith.net. 60 IN A 18.175.11.59
│     ╰─ nsmith.net. 60 IN RRSIG A 13 2 60 20240731072243 20240731052143 61242 nsmith.net. tlJazshvdB6ZBL4JR5j5igxt9nR9UpWLZTffvfNAhoKYm72wZAybVTGvA9stGlyokI8oiPZAsCeG0JANEFgWLw==
╰─ DNS Lookup
   ├─ for: DNSKEY nsmith.net.
   ├─ on: tcp-tls://1.1.1.1:853#one.one.one.one
   ├─ taking: 27.536916ms
   ├─ answers:
   │  ├─ nsmith.net. 3600 IN DNSKEY 256 3 13 C2MsRO02xuP6gI2BeariU73QaRU7AyDjcRevGaEN/vdnoKYAa1ch5CAe8G81hfPcyjN3ch6j7Yvqqz3uKII+Sg==
   │  ├─ nsmith.net. 3600 IN DNSKEY 256 3 13 /vEMemVp7s837XBbaQtCL9cNVMtT5/4vdzNjQrZQR5KG2C5C0IvieIlzTYW8HjU35bd7iGW/pZ8eXOB9uneLXA==
   │  ├─ nsmith.net. 3600 IN DNSKEY 257 3 13 3Bjd/yf3x8Hh3TSx9kzPrrDbKu4Y81TTQqJ5m0pvl4WcTcgMoMcF2eTDrxA3+xLStQSCRoIZ8yTDPbKNi8ws/A==
   │  ╰─ nsmith.net. 3600 IN RRSIG DNSKEY 13 2 3600 20240731100000 20240730230000 14056 nsmith.net. YAzvPGSChmSUCnzZLcU2kVTeZiUhZ5R4I8/hOiKxjG6I87xs2oepl/Lx9Qfp57o+an2LwVo/dfSFWmfhCwiduw==
   ├─ Signature Validation
   │  ├─ type: zsk
   │  ├─ for: nsmith.net.
   │  ├─ in: nsmith.net.
   │  ├─ key: nsmith.net. 3600 IN DNSKEY 256 3 13 /vEMemVp7s837XBbaQtCL9cNVMtT5/4vdzNjQrZQR5KG2C5C0IvieIlzTYW8HjU35bd7iGW/pZ8eXOB9uneLXA==
   │  ├─ signature: nsmith.net. 60 IN RRSIG A 13 2 60 20240731072243 20240731052143 61242 nsmith.net. tlJazshvdB6ZBL4JR5j5igxt9nR9UpWLZTffvfNAhoKYm72wZAybVTGvA9stGlyokI8oiPZAsCeG0JANEFgWLw==
   │  ├─ hash: 1a7e271bde371cf98eb38f00ffe550f74a9d3cbd2e639a9e67f60757c2063fb3
   │  ╰─ records:
   │     ├─ nsmith.net. 60 IN A 3.9.215.101
   │     ├─ nsmith.net. 60 IN A 18.133.128.244
   │     ╰─ nsmith.net. 60 IN A 18.175.11.59
   ├─ Signature Validation
   │  ├─ type: ksk
   │  ├─ for: nsmith.net.
   │  ├─ in: nsmith.net.
   │  ├─ key: nsmith.net. 3600 IN DNSKEY 257 3 13 3Bjd/yf3x8Hh3TSx9kzPrrDbKu4Y81TTQqJ5m0pvl4WcTcgMoMcF2eTDrxA3+xLStQSCRoIZ8yTDPbKNi8ws/A==
   │  ├─ signature: nsmith.net. 3600 IN RRSIG DNSKEY 13 2 3600 20240731100000 20240730230000 14056 nsmith.net. YAzvPGSChmSUCnzZLcU2kVTeZiUhZ5R4I8/hOiKxjG6I87xs2oepl/Lx9Qfp57o+an2LwVo/dfSFWmfhCwiduw==
   │  ├─ hash: 757c69a00f8a91db120f1841669b8d91766bfc7704ebaaae6003280d7d335f9b
   │  ╰─ records:
   │     ├─ nsmith.net. 3600 IN DNSKEY 256 3 13 C2MsRO02xuP6gI2BeariU73QaRU7AyDjcRevGaEN/vdnoKYAa1ch5CAe8G81hfPcyjN3ch6j7Yvqqz3uKII+Sg==
   │     ├─ nsmith.net. 3600 IN DNSKEY 256 3 13 /vEMemVp7s837XBbaQtCL9cNVMtT5/4vdzNjQrZQR5KG2C5C0IvieIlzTYW8HjU35bd7iGW/pZ8eXOB9uneLXA==
   │     ╰─ nsmith.net. 3600 IN DNSKEY 257 3 13 3Bjd/yf3x8Hh3TSx9kzPrrDbKu4Y81TTQqJ5m0pvl4WcTcgMoMcF2eTDrxA3+xLStQSCRoIZ8yTDPbKNi8ws/A==
   ╰─ DNS Lookup
      ├─ for: DS nsmith.net.
      ├─ on: tcp-tls://1.1.1.1:853#one.one.one.one
      ├─ taking: 38.790917ms
      ├─ answers:
      │  ├─ nsmith.net. 86400 IN DS 14056 13 2 757C69A00F8A91DB120F1841669B8D91766BFC7704EBAAAE6003280D7D335F9B
      │  ╰─ nsmith.net. 86400 IN RRSIG DS 13 2 86400 20240806024842 20240730013842 42924 net. ok+b4MrnRzeJv4F3Kijf3MDWs2vl+OaKbvWGVeJloWI18ly6yKDVoJT28byFXZrHZa8+5fdlU+ZAEH5c2TFzNw==
      ├─ Delegation Signer Check
      │  ├─ child: nsmith.net.
      │  ├─ parent: nsmith.net.
      │  ╰─ hash: 757c69a00f8a91db120f1841669b8d91766bfc7704ebaaae6003280d7d335f9b
      ╰─ DNS Lookup
         ├─ for: DNSKEY net.
         ├─ on: tcp-tls://1.1.1.1:853#one.one.one.one
         ├─ taking: 5.627916ms
         ├─ answers:
         │  ├─ net. 6376 IN DNSKEY 256 3 13 GUEoqWueUrWorK7wnPbhVlFIz52mbdrzleuCl3s2oPbWNj/Ych940L9vwUPFRnjzK3Q0J894RxfVkT4cgCYskg==
         │  ├─ net. 6376 IN DNSKEY 257 3 13 HiBoGpzDRAgrDmUXXTSnl7jCX6Hx5bzkU2jSxMbVI01yS+13EyOghnCidBXU0bH2gi2w9GhYGacpU6CrtwoFNg==
         │  ╰─ net. 6376 IN RRSIG DNSKEY 13 1 86400 20240810141035 20240726140535 37331 net. WgNhcNkwiJIDXiJ2xKN5YBr/iQfBBHojB0VLrIvB5fdmfYN/E2BQuS069LYnLmO25eeFJzB/WoXBFcl6uZu4WQ==
         ├─ Signature Validation
         │  ├─ type: zsk
         │  ├─ for: nsmith.net.
         │  ├─ in: net.
         │  ├─ key: net. 6376 IN DNSKEY 256 3 13 GUEoqWueUrWorK7wnPbhVlFIz52mbdrzleuCl3s2oPbWNj/Ych940L9vwUPFRnjzK3Q0J894RxfVkT4cgCYskg==
         │  ├─ signature: nsmith.net. 86400 IN RRSIG DS 13 2 86400 20240806024842 20240730013842 42924 net. ok+b4MrnRzeJv4F3Kijf3MDWs2vl+OaKbvWGVeJloWI18ly6yKDVoJT28byFXZrHZa8+5fdlU+ZAEH5c2TFzNw==
         │  ├─ hash: f1f7517e93de7a428bd378e027ccb47c881b3b4c2b948cbaf54883f15997fa8a
         │  ╰─ records:
         │     ╰─ nsmith.net. 86400 IN DS 14056 13 2 757C69A00F8A91DB120F1841669B8D91766BFC7704EBAAAE6003280D7D335F9B
         ├─ Signature Validation
         │  ├─ type: ksk
         │  ├─ for: nsmith.net.
         │  ├─ in: net.
         │  ├─ key: net. 6376 IN DNSKEY 257 3 13 HiBoGpzDRAgrDmUXXTSnl7jCX6Hx5bzkU2jSxMbVI01yS+13EyOghnCidBXU0bH2gi2w9GhYGacpU6CrtwoFNg==
         │  ├─ signature: net. 6376 IN RRSIG DNSKEY 13 1 86400 20240810141035 20240726140535 37331 net. WgNhcNkwiJIDXiJ2xKN5YBr/iQfBBHojB0VLrIvB5fdmfYN/E2BQuS069LYnLmO25eeFJzB/WoXBFcl6uZu4WQ==
         │  ├─ hash: 2f0bec2d6f79dfbd1d08fd21a3af92d0e39a4b9ef1e3f4111fff282490da453b
         │  ╰─ records:
         │     ├─ net. 6376 IN DNSKEY 256 3 13 GUEoqWueUrWorK7wnPbhVlFIz52mbdrzleuCl3s2oPbWNj/Ych940L9vwUPFRnjzK3Q0J894RxfVkT4cgCYskg==
         │     ╰─ net. 6376 IN DNSKEY 257 3 13 HiBoGpzDRAgrDmUXXTSnl7jCX6Hx5bzkU2jSxMbVI01yS+13EyOghnCidBXU0bH2gi2w9GhYGacpU6CrtwoFNg==
         ╰─ DNS Lookup
            ├─ for: DS net.
            ├─ on: tcp-tls://1.1.1.1:853#one.one.one.one
            ├─ taking: 5.879625ms
            ├─ answers:
            │  ├─ net. 84021 IN DS 37331 13 2 2F0BEC2D6F79DFBD1D08FD21A3AF92D0E39A4B9EF1E3F4111FFF282490DA453B
            │  ╰─ net. 84021 IN RRSIG DS 8 1 86400 20240812210000 20240730200000 20038 . h9/Uf4GNb/gfbLRQJe+1K0KzTjt0XdUBO5jcA40fNiJhgONXISxdmfkU1WazgeKO0895iwZoeK3davMQ+CqynwuIyprgQB2cHc9aWS5cYYJinqKu0lVprJK76pTVbjTqOiYWls2ydfPyCvZwWCth0u2dI+72/8srtrF4hphPz8BKGGuT2ThxWbBYZAy9/GH5iEjCFN4d7oZw5TlALTRzSxAJlILF1fwndyIKQyymPV1SEBV6t4Tt1lHcw6yDTi9CYyAMjKAXCJjosguiMdmtplq050MdW2XNzS336iGaEmO+Vedkwhkh/SIIWaQ9uUGROLYx6Q4lX4Wsase1CtADJA==
            ├─ Delegation Signer Check
            │  ├─ child: nsmith.net.
            │  ├─ parent: net.
            │  ╰─ hash: 2f0bec2d6f79dfbd1d08fd21a3af92d0e39a4b9ef1e3f4111fff282490da453b
            ╰─ DNS Lookup
               ├─ for: DNSKEY .
               ├─ on: tcp-tls://1.1.1.1:853#one.one.one.one
               ├─ taking: 4.61025ms
               ├─ answers:
               │  ├─ . 3058 IN DNSKEY 256 3 8 AwEAAdSiy6sslYrcZSGcuMEK4DtE8DZZY1A08kAsviAD49tocYO5m37AvIOyzeiKBWuPuJ4m9u5HonCM/ntxklZKYFyMftv8XoRwbiXdpSjfdpNHiMYTTV2oDUNMjdLFnF6HYSY48xrPbevQOYbAFGHpxqcXAQT0+BaBiAx3Ls6lXBQ3/hSVOprvDWJCQiI2OT+9+saKLddSIX6DwTVy0S5T4YY4EGg5R3c/eKUb2/8XgKWUzlOIZsVAZZUSTKW0tX54ccAALO7Grvsx/NW62jc1xv6wWAXocOEVgB7+4Lzb7q9p5o30+sYoGpOsKgFvMSy4oCZTQMQx2Sjd/NG2bMMw6nM=
               │  ├─ . 3058 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
               │  ╰─ . 3058 IN RRSIG DNSKEY 8 0 172800 20240821000000 20240731000000 20326 . nHDuf7nmTPAArgH6GxJh+0CAcNGGE1HHuhyChRZ+eWA27Bz4nYrOaUTpMfMP0jfj0m55OqzO9duKE1lz3SubXXUa0pINMRv5GOngAsL9YVJ7UgK+aCnDycWszawA5zuhgaZC7Z0QT/cqKkGr0nA34BrGeFQFhASD+T9ZzD4xsZXvFHiXDAvYRacPf+ITTB5FhATEFgWLjgAMXrOTkDl8x5x/b4qaVkQRg2AUVnjW/Sgsln4depa02M9qdKNYhb1JmcvfYTI1sx5ILRvnxL2t6DiuFIbzXW4iGx6oXM2tYZPFdRJv+V/ujR4nfiAxSNJ0YiaoDlnR72B6oZCAoHfmJA==
               ├─ Signature Validation
               │  ├─ type: zsk
               │  ├─ for: net.
               │  ├─ in: .
               │  ├─ key: . 3058 IN DNSKEY 256 3 8 AwEAAdSiy6sslYrcZSGcuMEK4DtE8DZZY1A08kAsviAD49tocYO5m37AvIOyzeiKBWuPuJ4m9u5HonCM/ntxklZKYFyMftv8XoRwbiXdpSjfdpNHiMYTTV2oDUNMjdLFnF6HYSY48xrPbevQOYbAFGHpxqcXAQT0+BaBiAx3Ls6lXBQ3/hSVOprvDWJCQiI2OT+9+saKLddSIX6DwTVy0S5T4YY4EGg5R3c/eKUb2/8XgKWUzlOIZsVAZZUSTKW0tX54ccAALO7Grvsx/NW62jc1xv6wWAXocOEVgB7+4Lzb7q9p5o30+sYoGpOsKgFvMSy4oCZTQMQx2Sjd/NG2bMMw6nM=
               │  ├─ signature: net. 84021 IN RRSIG DS 8 1 86400 20240812210000 20240730200000 20038 . h9/Uf4GNb/gfbLRQJe+1K0KzTjt0XdUBO5jcA40fNiJhgONXISxdmfkU1WazgeKO0895iwZoeK3davMQ+CqynwuIyprgQB2cHc9aWS5cYYJinqKu0lVprJK76pTVbjTqOiYWls2ydfPyCvZwWCth0u2dI+72/8srtrF4hphPz8BKGGuT2ThxWbBYZAy9/GH5iEjCFN4d7oZw5TlALTRzSxAJlILF1fwndyIKQyymPV1SEBV6t4Tt1lHcw6yDTi9CYyAMjKAXCJjosguiMdmtplq050MdW2XNzS336iGaEmO+Vedkwhkh/SIIWaQ9uUGROLYx6Q4lX4Wsase1CtADJA==
               │  ├─ hash: e71cf24011b8d9db82e2b57e42a9439209f43609ab4d1afa74f186a1d8ab0ae6
               │  ╰─ records:
               │     ╰─ net. 84021 IN DS 37331 13 2 2F0BEC2D6F79DFBD1D08FD21A3AF92D0E39A4B9EF1E3F4111FFF282490DA453B
               ╰─ Signature Validation
                  ├─ type: ksk
                  ├─ for: net.
                  ├─ in: .
                  ├─ key: . 3058 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
                  ├─ signature: . 3058 IN RRSIG DNSKEY 8 0 172800 20240821000000 20240731000000 20326 . nHDuf7nmTPAArgH6GxJh+0CAcNGGE1HHuhyChRZ+eWA27Bz4nYrOaUTpMfMP0jfj0m55OqzO9duKE1lz3SubXXUa0pINMRv5GOngAsL9YVJ7UgK+aCnDycWszawA5zuhgaZC7Z0QT/cqKkGr0nA34BrGeFQFhASD+T9ZzD4xsZXvFHiXDAvYRacPf+ITTB5FhATEFgWLjgAMXrOTkDl8x5x/b4qaVkQRg2AUVnjW/Sgsln4depa02M9qdKNYhb1JmcvfYTI1sx5ILRvnxL2t6DiuFIbzXW4iGx6oXM2tYZPFdRJv+V/ujR4nfiAxSNJ0YiaoDlnR72B6oZCAoHfmJA==
                  ├─ hash: e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
                  ├─ records:
                  │  ├─ . 3058 IN DNSKEY 256 3 8 AwEAAdSiy6sslYrcZSGcuMEK4DtE8DZZY1A08kAsviAD49tocYO5m37AvIOyzeiKBWuPuJ4m9u5HonCM/ntxklZKYFyMftv8XoRwbiXdpSjfdpNHiMYTTV2oDUNMjdLFnF6HYSY48xrPbevQOYbAFGHpxqcXAQT0+BaBiAx3Ls6lXBQ3/hSVOprvDWJCQiI2OT+9+saKLddSIX6DwTVy0S5T4YY4EGg5R3c/eKUb2/8XgKWUzlOIZsVAZZUSTKW0tX54ccAALO7Grvsx/NW62jc1xv6wWAXocOEVgB7+4Lzb7q9p5o30+sYoGpOsKgFvMSy4oCZTQMQx2Sjd/NG2bMMw6nM=
                  │  ╰─ . 3058 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
                  ╰─ Delegation Signer Check
                     ├─ child: net.
                     ├─ parent: .
                     ╰─ hash: e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
- [github.com/nsmithuk/dns-anchors-go license](https://github.com/nsmithuk/dns-anchors-go/blob/main/LICENSE)
- [github.com/rs/zerolog license](https://github.com/rs/zerolog/blob/master/LICENSE)
- [github.com/stretchr/testify license](https://github.com/stretchr/testify/blob/master/LICENSE)

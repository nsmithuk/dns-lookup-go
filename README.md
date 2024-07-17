# dns-lookup-go

A high-level API for [github.com/miekg/dns](https://github.com/miekg/dns).

A simple interface for performing DNS lookup against a resolving nameserver.

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
        log.Fatalf(err)
    }
    
    fmt.Printf("%d answers found\n", len(answers))
    for i, answer := range answers {
        fmt.Printf("answer %d: %s\n", i, answer.String())
    }
}

```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


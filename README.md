# Go-pg Adapter

Go-pg Adapter is the [Go-pg](https://github.com/go-pg/pg) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from PostgreSQL or save policy to it.

## Installation

    go get github.com/pckhoi/casbin-pg-adapter

## Simple Postgres Example

```go
package main

import (
	"os"

	pgadapter "github.com/pckhoi/casbin-pg-adapter"
	"github.com/casbin/casbin"
)

func main() {
	// Initialize a Go-pg adapter and use it in a Casbin enforcer:
	// The adapter will use the Postgres database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	a, _ := pgadapter.NewAdapter(os.Getenv("PG_CONN")) // Your driver and data source.

	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.

	e := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Getting Help

-   [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.

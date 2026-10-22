# Service Mesh Security

A service mesh moves the transport security of a microservice application
out of the application code and into a sidecar proxy. Every pod gets an
Envoy or Linkerd2-proxy container, the mesh control plane configures those
proxies, and mutual TLS between sidecars becomes the default identity
model.

That shift is powerful, but it creates a new control plane inside the
cluster. If the mesh control plane is compromised, every proxy in the mesh
trusts the attacker. If mTLS is configured with permissive mode, the mesh
provides no real boundary. If a sidecar is bypassed, the application is
still exposed on the pod network.

## 1. Overview

Two dominant implementations:

- **Istio** - control plane `istiod` (formerly pilot, citadel, galley),
  data plane is Envoy sidecars. Configures mTLS, authorization policy,
  ingress and egress gateways.
- **Linkerd** - control plane is a small set of components
  (`linkerd-destination`, `linkerd-identity`, `linkerd-proxy-injector`),
  data plane is the Rust `linkerd2-proxy`.

Both share the same logical model:

- **Identity** - a workload gets a SPIFFE identity (e.g.
  `spiffe://cluster.local/ns/default/sa/web`).
- **Data plane** - every connection passes through a sidecar, which
  enforces mTLS and policy.
- **Control plane** - issues certificates, pushes config, and manages
  sidecar injection.

The mesh is only as strong as its control plane and its injection webhook.

## 2. Reconnaissance / Enumeration

Indicators of a mesh in a Kubernetes cluster:

- Every pod has a second container named `istio-proxy` or
  `linkerd-proxy`.
- The `istio-system` or `linkerd` namespace exists.
- Envoy admin port 15000 or 15001 is open on the pod network.
- The service account token can call `istiod` for xDS (usually it cannot,
  by design).
- A `sidecar.istio.io/inject: "true"` annotation on the namespace or pod.

From inside a pod, inspect the injected proxy:

```bash
kubectl get pod web-0 -o jsonpath='{.spec.containers[*].name}'
```

Expected output:

```text
web istio-proxy
```

The mesh is present. The next question is whether it is in permissive or
strict mTLS mode.

## 3. Common Attack Vectors

- **Permissive mTLS** - the mesh accepts plaintext in addition to mTLS,
  so an attacker on the pod network can talk to services directly.
- **Sidecar bypass** - hostNetwork pods and raw TCP from the node escape
  the mesh entirely.
- **Control-plane compromise** - if `istiod` or `linkerd-identity` is
  compromised, the attacker can issue any certificate the mesh trusts.
- **Injection webhook abuse** - a compromised `MutatingWebhookConfiguration`
  can inject an attacker-controlled sidecar into every new pod.
- **Ingress gateway misconfiguration** - a permissive gateway exposes
  internal services without authorization policy.
- **Trust domain weakness** - a shared trust domain across clusters means
  a compromise in one cluster is trusted by the others.

## 4. Exploitation Recipes

Confirm mTLS mode for a service:

```bash
istioctl x describe pod web-0
```

Expected output (trimmed):

```text
Pod: web-0
  Pod is STRICT
  Service: web.default.svc.cluster.local
    Port 80: STRICT
```

If the output says `PERMISSIVE`, plaintext traffic from the pod network is
accepted. That is a direct bypass of the mesh's identity model.

Test sidecar bypass from a hostNetwork pod:

```bash
curl -s http://web.default.svc.cluster.local:80/health
```

Expected output:

```text
ok
```

If the curl succeeds from a hostNetwork pod, the mesh does not protect the
service against that source.

## 5. Post-Exploitation

Once inside the mesh control plane:

- Issue a certificate for any SPIFFE identity and impersonate any service.
- Push an authorization policy that allows the attacker's namespace.
- Modify the injector webhook to add an attacker sidecar to every pod.
- Disable mTLS globally to make future traffic capture easier.

Once inside a compromised ingress gateway:

- Read the full request stream for every service behind it.
- Redirect traffic to an attacker-controlled backend.

## 6. Risk Context (Offensive)

A service mesh is a cluster-wide man-in-the-middle by design. That is the
point: it lets operators enforce identity and policy on every connection.
If the mesh is compromised or misconfigured, the same position makes it a
perfect interception point.

Realistic paths:

- Pod network -> permissive mTLS -> service capture.
- Host network -> sidecar bypass -> direct service access.
- Compromised control plane -> issue any identity -> cluster-wide
  impersonation.
- Compromised injector -> sidecar in every new pod.

## 7. Root Causes (Defensive)

- mTLS is deployed in permissive mode "for compatibility" and never
  flipped to strict.
- The control plane is treated as infrastructure and not hardened.
- The injector webhook is not protected with a proper trust bundle.
- Trust domain is not segmented between clusters or environments.
- Ingress gateways use authorization policies that allow all paths.

## 8. Preventive Controls (Defensive)

- Set mTLS to STRICT in every namespace that does not need plaintext.
- Harden the mesh control plane with the same RBAC and audit controls as
  the Kubernetes API server.
- Restrict who can modify the injector webhook, and validate its
  configuration in CI.
- Use separate trust domains per cluster and per environment.
- Enforce AuthorizationPolicy (Istio) or ServerAuthorization (Linkerd)
  on every service, not just the ingress gateway.
- Deny hostNetwork pods in namespaces that should be mesh-protected.

## 9. Detection Controls (Defensive)

- Alert on any change to mTLS mode or `PeerAuthentication` resources.
- Alert on changes to `MutatingWebhookConfiguration` and the injector
  certificate.
- Detect pods with `hostNetwork: true` in mesh-protected namespaces.
- Monitor for connections from outside the mesh (plaintext on port 80).
- Log `AuthorizationPolicy` denials and alert on a spike from one
  identity.

## 10. Verification (Defensive)

- Run `istioctl x describe pod <pod>` on a sample of workloads and
  confirm STRICT mode.
- Confirm a hostNetwork pod cannot reach the service directly.
- Confirm AuthorizationPolicy denies requests from an unlisted
  namespace.
- Confirm the injector webhook certificate is rotated and its
  configuration is version-controlled.
- Confirm trust domain separation between clusters.

## Certification Alignment

- **CKA / CKS** - workload isolation, admission control, certificate
  management.
- **Istio Certified Associate (ICA)** - traffic management, security,
  observability.
- **NIST SP 800-204A** - service mesh security architecture.

## References

- Istio security concepts - https://istio.io/latest/docs/concepts/security/
- Istio authentication policy - https://istio.io/latest/docs/reference/config/security/peer_authentication/
- Linkerd mutual TLS - https://linkerd.io/2.16/features/automatic-mtls/
- NIST SP 800-204A, Building Secure Microservices-based Applications Using Service-Mesh Architecture - https://csrc.nist.gov/pubs/sp/800/204/a/final
- SPIFFE and SPIRE - https://spiffe.io/docs/latest/
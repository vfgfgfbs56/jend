# Jend multi-region / multi-server deployment direction

Jend should not depend on one public server or one region. The intended
production direction is a multi-region system in which the latency-sensitive
data path is local or regional, while strongly consistent account/security
mutations are kept off the hot message path.

## Invariants

- Local AI inference stays on the device; no remote inference dependency is
  introduced merely to obtain global availability.
- Gateways are replaceable/stateless wherever possible and do not hold message
  plaintext or model plaintext.
- Clients can discover multiple independently hosted regional gateways and
  select a healthy low-latency endpoint, with automatic failover.
- A global DNS/Anycast front door may be used as an optimization, but clients
  must not depend on a single front-door provider for reachability.
- Strongly consistent security mutations (DeviceSet transitions, replay
  barriers, entitlement/authorization changes) remain serialized through an
  authoritative control-plane writer or an equivalently reviewed consensus
  system. Do not use eventual consistency for security state.
- Regional read replicas/caches may serve non-authoritative reads only when the
  protocol can tolerate bounded staleness.
- OPAQUE/server root secrets are not copied to every edge gateway. Authentication
  authority can be fewer, hardened nodes; an occasional cross-region login RTT
  is preferable to placing high-value auth secrets on every edge.
- Encrypted sync objects may be replicated between regions because servers do
  not possess plaintext keys, subject to metadata/privacy and retention policy.
- Static model manifests/source maps can be distributed through multiple
  mirrors/CDNs because clients verify signatures and content hashes.

## Failure model

A client keeps a signed/validated set of gateway endpoints and races or ranks
healthy candidates. Loss of one gateway, one provider, or one region must not
invalidate local data or local inference. Stateful operations use idempotency /
replay protections and are safe to retry against a surviving gateway.

For an initial small deployment, two regional stateless gateways plus a
primary/standby control-plane database is simpler and safer than premature
multi-master writes. A third lightweight witness/health location can later
improve failover decisions. As load grows, more gateways can be added without
changing the cryptographic client protocol.

## Latency reality

No architecture can make a physically distant server have zero network
latency. Jend minimizes perceived latency by keeping inference local, using the
nearest healthy gateway for relay/sync traffic, removing distant database
round-trips from the hot path, caching signed immutable metadata near users,
and later allowing direct peer-to-peer sync when connectivity permits.

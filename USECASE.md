# Mercury Business Use Case

Mercury is a Linux host security runtime for AI agents and automation that need real machine access but should not be fully trusted.

## Core Problem

Many AI workflows start inside sandbox containers, which solves part of the security problem. That works well when the workload can stay fully isolated and does not need meaningful access to the host, private network, local credentials, or shared operational tooling.

The problem appears when teams need agents to do real work on real Linux machines:

- read and modify checked-out repositories
- run local build tools and package managers
- use SSH, cloud CLIs, `kubectl`, Docker, VPN-only services, or internal package mirrors
- operate on long-lived workstations, dev boxes, bastions, or self-hosted runners

At that point, container isolation is often weakened with bind mounts, host networking, secrets injection, and privileged capabilities until the agent can function. The security boundary becomes much weaker, while audit and policy remain coarse.

Mercury is for that gap.

## Business Value

Mercury lets an organization enable semi-trusted AI automation on Linux hosts while preserving control over what those workloads can do.

Its value is:

- enforce file, process, and network policy on host-executed agent workflows
- require explicit policy instead of broad host trust
- produce audit evidence for what an agent attempted, what was allowed, and what was denied
- make self-hosted or host-integrated agent workflows acceptable to security and platform teams

In simple terms: Mercury is useful when "run this in a container" is too limiting, but "just trust the agent on the host" is unacceptable.

## Best-Fit Environments

Mercury is strongest in environments where agents need meaningful host access:

- self-hosted CI/CD runners
- remote development boxes
- shared engineering workstations
- GPU and ML compute hosts
- internal automation VMs
- bastion or operations hosts
- customer-managed Linux machines running vendor-supplied automation

## Ideal Customers

The most likely initial buyers or internal champions are:

- platform engineering teams enabling agent workflows on internal infrastructure
- security teams that need enforcement and audit before approving host-level AI automation
- DevOps or infrastructure teams running semi-autonomous operational tooling
- enterprises with sensitive internal networks or credentials that cannot rely on "best effort" guardrails

## When Mercury Is Better Than Containers Alone

Mercury is not a replacement for sandbox containers. It is useful when containers alone are not enough.

Examples:

- A coding agent must access a real monorepo checkout, local caches, internal Git hosts, and enterprise build tools on a persistent dev box.
- A CI job must run on a self-hosted runner with access to internal package mirrors, artifact stores, and deployment credentials.
- An ops agent must use `kubectl`, cloud CLIs, and internal APIs from a controlled Linux machine.
- A research or ML workflow must run on a shared GPU host where users want policy and audit around what the agent can access.

In these cases, Mercury provides a finer control plane than "inside container" or "outside container."

## Where Mercury Is Weak

Mercury is a poor fit when:

- workloads are already fully satisfied by ephemeral sandbox containers
- the organization does not need host access, fine-grained policy, or audit
- existing isolation is already strong enough and operationally acceptable

If a fully sandboxed container solves the workflow without exception sprawl, Mercury adds much less value.

## Product Positioning

Mercury should be positioned as:

- policy enforcement and audit for AI agents running on Linux hosts
- an enablement layer for semi-trusted automation
- a way to make host-integrated agent workflows acceptable in enterprise environments

It should not be positioned as:

- a generic container runtime
- a Kubernetes security product
- a replacement for all existing sandboxing approaches

## Short Positioning Statement

Mercury enables AI agents to run on real Linux infrastructure with enforceable file, process, and network policy plus audit trails, so organizations can use host-integrated automation without granting unrestricted machine trust.

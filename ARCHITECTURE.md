# Architecture Notes

This repository follows DDD + Onion style boundaries for a Connect RPC service.

## Layer Responsibilities

- `domain/`
  - Entity, Value Object, Repository interface
  - No concrete infra dependencies
- `application/`
  - Command/Query use cases
  - Depends on domain interfaces
- `infra/`
  - Implements domain interfaces (DB/authz adapters)
- `handler/`
  - Connect handler
  - Proto <-> Value Object conversion
  - Facade delegation

## Data Flow

1. `.proto` defines request/response schema
2. generated code is consumed by handler/frontend
3. handler validates by constructing VOs
4. facade performs authorization
5. command/query service executes use case
6. repository interface is fulfilled by infra

## Review Checklist (Per Layer)

- `domain/`
  - Are invariants enforced in VO constructors?
  - Is there any dependency on infra packages?
- `application/`
  - Are command and query concerns separated?
  - Does it depend only on domain interfaces?
- `infra/`
  - Is ORM/SQL leaking outside infra?
  - Does implementation satisfy domain interfaces at compile time?
- `handler/`
  - Is proto converted to VO before use case execution?
  - Is logic mostly delegation (no business rule duplication)?

## AI Collaboration Rule

Use AI for repetitive implementation only after boundaries are defined.
Type constraints and layer boundaries are the guardrails.

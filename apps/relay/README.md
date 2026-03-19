# AgentPay Relay

This relay is legacy code kept in-repo for compatibility work. It is unsupported in this
release and is not part of the supported AgentPay SDK install or approval flow.

Supported manual approval operations in this release are local-only:

- `agentpay admin list-manual-approval-requests`
- `agentpay admin approve-manual-approval-request --approval-request-id <UUID>`
- `agentpay admin reject-manual-approval-request --approval-request-id <UUID> --rejection-reason "<TEXT>"`
- `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`

The source code remains here only so future compatibility or migration work can be done
without recovering deleted relay history.

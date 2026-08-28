# NICo — NVIDIA Infra Controller Documentation

<Note title="Repository move notice">
On September 4, 2026, the NICo repository will move from the NVIDIA GitHub organization to `dsx-ai-factory`. Existing repository URLs and standard Git operations are expected to continue working through GitHub redirects. No action is needed for most users. If you maintain automation or integrations that reference `NVIDIA/infra-controller`, such as GitHub Actions, webhooks, or pinned repository URLs, please update them to `dsx-ai-factory/infra-controller` after the move.
</Note>

NICo is an open source suite of microservices for site-local, zero-trust bare-metal lifecycle management. It automates hardware discovery, firmware validation, DPU provisioning, network isolation, and tenant sanitization — enabling NVIDIA Cloud Partners (NCPs) and infrastructure operators to stand up and operate AI factory-scale infrastructure.

NICo is open source under the Apache 2.0 license.

## Where do you want to start?

| | **Deploy & Operate NICo** | **Integrate with NICo** | **Evaluate NICo** |
|---|---|---|---|
| **Who** | NCP infrastructure operators deploying and managing bare-metal fleets | ISV developers and platform engineers building on NICo's APIs | Architects and decision-makers evaluating NICo for their stack |
| **Start here** | [Prerequisites](getting-started/prerequisites/hardware.md) | [Architecture Overview](architecture/overview.md) | [What is NICo?](overview/what-is-nico.md) |
| **Then** | [Quick Start Guide](getting-started/quick-start.md) | [Redfish Workflow](architecture/redfish_workflow.md) | [Key Capabilities](overview/capabilities.md) |
| **Then** | [Ingesting Hosts](provisioning/ingesting-hosts.md) | [Redfish Endpoints Reference](architecture/redfish/endpoints_reference.md) | [Day 0/1/2 Lifecycle](overview/lifecycle.md) |
| **Then** | [Reference Installation](getting-started/installation-options/reference-install.md) | REST API Reference | [HCL](hcl.md) + [FAQs](faq.md) |

## Quick Links

- [Hardware Compatibility List](hcl.md) — Supported servers and DPUs
{/* <!-- rumdl-disable-next-line --> */}
- [Release Notes](release-notes) — What's new in each version
- [FAQs](faq.md) — Common questions answered
- [GitHub](https://github.com/NVIDIA/infra-controller)

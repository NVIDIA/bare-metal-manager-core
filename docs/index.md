# NICo — NVIDIA Infra Controller Documentation

NICo is an open source suite of microservices for site-local, zero-trust bare-metal lifecycle management. It automates hardware discovery, firmware validation, DPU provisioning, network isolation, and tenant sanitization — enabling NVIDIA Cloud Partners (NCPs) and infrastructure operators to stand up and operate AI factory-scale infrastructure.

NICo is open source under the Apache 2.0 license.

## Where do you want to start?

| | **Deploy & Operate NICo** | **Integrate with NICo** | **Evaluate NICo** |
|---|---|---|---|
| **Who** | NCP infrastructure operators deploying and managing bare-metal fleets | ISV developers and platform engineers building on NICo's APIs | Architects and decision-makers evaluating NICo for their stack |
| **Start here** | [Site Reference Architecture](manuals/site-reference-arch.md) | [Architecture Overview](architecture/overview.md) | [What is NICo?](overview/what-is-nico.md) |
| **Then** | [Site Setup](manuals/site-setup.md) | [Redfish Workflow](architecture/redfish_workflow.md) | [Key Capabilities](overview/capabilities.md) |
| **Then** | [Networking Requirements](manuals/networking_requirements.md) | [Redfish Endpoints Reference](architecture/redfish/endpoints_reference.md) | [Day 0/1/2 Lifecycle](overview/lifecycle.md) |
| **Then** | [Ingesting Hosts](manuals/ingesting_machines.md) | [REST API Reference](#api) | [HCL](hcl.md) + [FAQs](faq.md) |

## Quick Links

- [Hardware Compatibility List](hcl.md) — Supported servers and DPUs
- [Release Notes](release-notes.md) — What's new in each version
- [FAQs](faq.md) — Common questions answered
- [GitHub: NICo Core](https://github.com/NVIDIA/ncx-infra-controller-core) | [NICo REST](https://github.com/NVIDIA/ncx-infra-controller-rest)

# Documentation Summary

This page summarizes the documentation for Bare Metal Manager (BMM). Use the links below to navigate to each section.

## Overview

- [Overview](overview.md) — Introduction to BMM: operational principles, responsibilities, components and services, and dependencies.

## Architecture

Architecture pages describe the design of the system:

- [Architecture Diagram](architecture/arch_diagram.md) — High-level overview of the BMM architecture
- [State Handling](architecture/state_handling.md) — How BMM handles the lifecycle of resources
- [DPU Configuration](architecture/dpu_configuration.md) — How BMM configures DPUs

## Installation

The Installation Guide covers site reference architecture, site setup, and building containers:

- [Site Reference Architecture](installation/site-reference-arch.md) — Hardware and configuration guidelines for BMM-managed sites
- [Site Setup](installation/site-setup.md) — Setting up site dependencies for a Kubernetes-based install
- [NCP](installation/ncp.md) — Building the BMM containers

## Additional Topics

- [Host Ingestion](host-ingestion.md) — Ingesting managed hosts into BMM
- [NVIDIA NVLink](nvlink.md) — Using NVIDIA NVLink to partition GPUs
- [Building BMM Containers](build.md) — Building the BMM containers on a host or VM
- [Release Notes](release-notes.md) — Release notes for BMM

# Vaporlock

> **Autonomous Cloud Governance & Cost Optimization for AWS**

**Vaporlock** is a serverless governance suite designed to prevent "infrastructure stall." It deploys lightweight, event-driven Python agents into AWS accounts to enforce security best practices, maintain tagging standards, and eliminate cost-leaking "ghost" resources.

Unlike centralized AMIs, Vaporlock lives natively as Lambda functions within user accounts for maximum scalability and zero management overhead.

---

## 🚀 Core Capabilities

### 🛡️ The Security Group Auditor

* **The Problem:** Over-permissive rules (0.0.0.0/0), "spaghetti" circular dependencies, and unmanaged SSH/RDP ports.
* **The Solution:** Continuously audits VPC Security Groups. It identifies transitive trust loops and flags rules that violate the principle of least privilege.

### 🏷️ The Tagging Enforcer

* **The Problem:** "Shadow IT" resources without owners, leading to impossible-to-manage bills.
* **The Solution:** Monitors resource creation in real-time. It automatically applies standardized tags (Owner, Project, Environment) or alerts for remediation.

### 👻 The Ghost Snapshot Reaper

* **The Problem:** Forgotten EBS snapshots costing thousands after their parent volumes have been deleted.
* **The Solution:** Scans for orphaned snapshots and handles safe archiving or deletion based on configurable retention policies.

---

## 🛠️ Tech Stack

* **Language:** Python 3.12+ (Optimized with `yield` generators for high-performance resource streaming).
* **SDK:** AWS Boto3.
* **Deployment:** AWS SAM / CloudFormation.
* **Architecture:** Multi-tenant Lambda-based execution.

---

## 📈 Roadmap

* [ ] **Phase 1:** Core Security Group Auditor (In Progress)
* [ ] **Phase 2:** Tagging Automation Engine
* [ ] **Phase 3:** Cost Optimization (Snapshot Reaper)

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

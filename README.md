<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# SuiteCRM MCP Server

**Connect ChatGPT to SuiteCRM with individual access permissions and human-controlled workflows.**

Bring customer information into the conversations where your team works. SuiteCRM MCP Server connects your existing CRM to ChatGPT through the Model Context Protocol (MCP), so people can explore permitted CRM records, understand customer relationships, and prepare next steps without giving an AI assistant unrestricted permission to change business data.

## What it enables

- **Customer context on demand.** Look up accounts, opportunities, and other permitted SuiteCRM records from a conversation instead of switching between applications.
- **Access that follows the user.** Each person signs in with their own SuiteCRM account; the integration respects individual CRM permissions rather than relying on a shared administrator.
- **Proposals before changes.** Prepare CRM updates for human review. Execution of commercial changes is disabled by default. When explicitly enabled, changes require a separate SuiteCRM browser sign-in and human review of each exact proposal.
- **Deployment under your control.** Keep your existing SuiteCRM installation and connect through a private MCP tunnel, without publishing the MCP endpoint on the internet.

This makes the project relevant to sales and account teams looking for faster access to customer context, operations teams evaluating assisted workflows, and IT teams integrating conversational AI with an existing open-source CRM.

## Professional services from LibreCode

**LibreCode Coop** develops, integrates, and supports open-source systems for organizations that want solutions tailored to their operations.

If you are planning a SuiteCRM and AI integration, LibreCode can help with architecture and security reviews, deployment, customization, workflow integration, training, and ongoing technical support.

**[Discuss your project with LibreCode](mailto:contact@librecode.coop?subject=SuiteCRM%20MCP%20integration)** · [Explore LibreCode's services](https://librecode.coop/)

The project can also be deployed and adapted independently; contracting LibreCode's services is optional.

## Documentation

- [Technical architecture and authentication](docs/AUTH.md)
- [Deployment and configuration](docs/DEPLOY.md)
- [Connecting ChatGPT](docs/PLUGIN.md)
- [Security and authorization model](docs/SECURITY.md)
- [Development, testing, and dependency management](docs/QUALITY.md)
- [Project status and validation requirements](docs/STATUS.md)
- [Contributing](CONTRIBUTING.md)

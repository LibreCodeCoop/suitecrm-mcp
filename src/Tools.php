<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use Mcp\Server\RequestContext;
use RuntimeException;

final class Tools
{
    public function __construct(
        private readonly CrmGateway $crm,
        private readonly ApprovalGate $approvals,
    ) {
    }

    private function subject(RequestContext $context): string
    {
        $token = $context->getAccessToken();
        $subject = $token?->getSubject();
        if (!is_string($subject) || $subject === '') {
            throw new RuntimeException('Individual OAuth authentication required');
        }
        return TokenVault::subject($subject);
    }

    /** Identify the current user and whether their personal SuiteCRM account is linked. */
    public function crmWhoami(RequestContext $context): array
    {
        $subject = $this->subject($context);
        return [
            'authenticated' => true,
            'subject' => $subject,
            'suitecrm_personal_account_linked' => $this->crm->linked($subject),
            'write_execution_default' => 'disabled',
        ];
    }

    /** Return business modules available through the current user's SuiteCRM token. */
    public function crmListModules(RequestContext $context): array
    {
        $subject = $this->subject($context);
        return ['modules' => $this->crm->modules($subject)];
    }

    /** Return safe field-definition metadata for a SuiteCRM business module. */
    public function crmModuleSchema(RequestContext $context, string $module): array
    {
        $subject = $this->subject($context);
        return ['module' => Policy::module($module),
                'fields' => $this->crm->schema($subject, $module)];
    }

    /** List 1-20 records from a business module, with server-side field allowlists. */
    public function crmListRecords(
        RequestContext $context,
        string $module,
        int $page = 1,
        int $pageSize = 10
    ): array {
        $subject = $this->subject($context);
        return $this->crm->listRecords($subject, $module, [], $page, $pageSize);
    }

    /** Fetch one record; user-level SuiteCRM ACL and MCP field policy both apply. */
    public function crmGetRecord(
        RequestContext $context,
        string $module,
        string $recordId
    ): array {
        $subject = $this->subject($context);
        return $this->crm->getRecord($subject, $module, $recordId);
    }

    /** Prepare EXACTLY ONE individual change. NO SuiteCRM record is modified. */
    public function crmPrepareChange(
        RequestContext $context,
        string $operation,
        string $module,
        string $changesJson,
        string $reason,
        ?string $recordId = null,
    ): array {
        $subject = $this->subject($context);
        if (strlen($changesJson) > 12000) {
            throw new RuntimeException('The proposed change is too large');
        }
        $changes = json_decode($changesJson, true, 10, JSON_THROW_ON_ERROR);
        if (!is_array($changes) || array_is_list($changes)) {
            throw new RuntimeException('Changes must be a JSON object');
        }
        return $this->approvals->prepare($subject, $operation, $module, $recordId, $changes, $reason);
    }

    /** Display exact before/after values for a pending proposal, without executing. */
    public function crmGetProposal(RequestContext $context, string $proposalId): array
    {
        return $this->approvals->status($this->subject($context), $proposalId);
    }

    /** Suggest improvements to forms, fields, workflows and relationships; DRAFT ONLY. */
    public function crmPrepareDesign(
        RequestContext $context,
        string $module,
        string $changeType,
        string $specificationJson
    ): array {
        $this->subject($context);
        Policy::module($module);
        if (!in_array($changeType, ['form_layout','field_definition','dropdown',
                                    'workflow_review','relationship'], true) ||
            strlen($specificationJson) > 6000) {
            throw new RuntimeException('Invalid configuration proposal');
        }
        $spec = json_decode($specificationJson, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($spec)) {
            throw new RuntimeException('Configuration proposal must be a JSON value');
        }
        return [
            'state' => 'draft_only',
            'module' => $module,
            'change_type' => $changeType,
            'specification' => $spec,
            'changed_suitecrm' => false,
            'review_required' => 'Administrator and management approval required; manual or staged application.',
        ];
    }

    /** Execute one independently signed human-approved change; disabled in Compose. */
    public function crmApplyApprovedChange(
        RequestContext $context,
        string $proposalId,
        string $approvalSignature
    ): array {
        return $this->approvals->apply(
            $this->subject($context),
            $proposalId,
            $approvalSignature
        );
    }
}

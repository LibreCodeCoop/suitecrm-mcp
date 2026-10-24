<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use InvalidArgumentException;

final class Policy
{
    private const ALLOWED_MODULES = [
        'Accounts', 'Contacts', 'Leads', 'Opportunities', 'Notes', 'Tasks',
        'Meetings', 'Calls', 'AOS_Quotes', 'AOS_Contracts', 'Documents',
        'FP_events', 'Cases', 'Project',
    ];
    private const ALLOWED_FIELDS = [
        'id','name','first_name','last_name','title','date_entered','date_modified',
        'status','description','account_id','account_name','contact_id','contact_name',
        'opportunity_id','parent_id','parent_type','assigned_user_id','assigned_user_name',
        'date_start','date_due','date_closed','sales_stage','next_step','probability',
        'amount','lead_source','email1','phone_work','phone_mobile','industry','website',
        'canaldeorigem_c','segmento_c','status_cliente_c','list_porte_c',
    ];
    private const MUTABLE_MODULES = ['Accounts','Contacts','Leads','Opportunities','Tasks','Notes'];
    private const IMMUTABLE_FIELDS = ['id','date_entered','date_modified','assigned_user_name','account_name','contact_name','deleted','created_by'];
    private const SENSITIVE_REGEX = '/(?:^|_)(?:bank|banco|pix|checking|cpf|cnpj|rg|password|secret|token|oauth|salario|salary|backup|private|nit|pis|data_nascimento|nome_mae|nome_pai)(?:_|$)/i';

    public static function module(string $module): string
    {
        if (!preg_match('/^[A-Za-z][A-Za-z0-9_]{0,79}$/D', $module) ||
            !in_array($module, self::ALLOWED_MODULES, true)) {
            throw new InvalidArgumentException('This SuiteCRM module is not allowed');
        }
        return $module;
    }

    public static function fields(string $module, array $requested = []): array
    {
        self::module($module);
        $fields = $requested ?: ['id','name','date_modified'];
        if (count($fields) > 20) {
            throw new InvalidArgumentException('Maximum 20 selected fields');
        }
        $out = [];
        foreach ($fields as $field) {
            if (!is_string($field) ||
                !preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,99}$/D', $field) ||
                preg_match(self::SENSITIVE_REGEX, $field) ||
                !in_array($field, self::ALLOWED_FIELDS, true)) {
                throw new InvalidArgumentException('Requested field is not allowed');
            }
            $out[$field] = true;
        }
        return array_keys($out);
    }

    public static function changes(string $module, array $attrs, string $operation): array
    {
        self::module($module);
        if (!in_array($module, self::MUTABLE_MODULES, true) ||
            !in_array($operation, ['create','update'], true) ||
            ($operation === 'update' && $module === 'Notes')) {
            throw new InvalidArgumentException('This change is not supported');
        }
        if (count($attrs) < 1 || count($attrs) > 10) {
            throw new InvalidArgumentException('Provide 1-10 changed fields');
        }
        self::fields($module, array_keys($attrs));
        if ($operation === 'create' && in_array($module, ['Notes', 'Tasks'], true)) {
            foreach (['name','parent_id','parent_type'] as $required) {
                if (!isset($attrs[$required])) {
                    throw new InvalidArgumentException('Notes/Tasks require a name and related CRM record');
                }
            }
        }
        foreach ($attrs as $field => $value) {
            if (in_array($field, ['parent_id','account_id','contact_id',
                                  'opportunity_id','assigned_user_id'], true)) {
                self::recordId(is_string($value) ? $value : '');
            }
            if ($field === 'parent_type') {
                self::module(is_string($value) ? $value : '');
            }
            if (in_array($field, self::IMMUTABLE_FIELDS, true) ||
                !(is_string($value) || is_int($value) || is_bool($value) || is_float($value)) ||
                (is_string($value) && (strlen($value) > 6000 || str_contains($value, "\0"))) ||
                is_float($value) && !is_finite($value)) {
                throw new InvalidArgumentException('Field value cannot be modified via MCP');
            }
        }
        return $attrs;
    }

    public static function recordId(string $recordId): string
    {
        if (!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iD', $recordId)) {
            throw new InvalidArgumentException('Invalid SuiteCRM record ID');
        }
        return strtolower($recordId);
    }

    public static function project(array $attributes, array $fields): array
    {
        return array_intersect_key($attributes, array_fill_keys($fields, true));
    }
}

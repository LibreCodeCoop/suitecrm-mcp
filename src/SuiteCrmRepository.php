<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use RuntimeException;

final class SuiteCrmRepository implements CrmGateway
{
    public function __construct(
        private readonly ApiClient $http,
        private readonly TokenVault $vault,
    ) {
    }

    /** Fetch a bearer owned by the current SuiteCRM OAuth subject, never from admin .env. */
    private function userToken(string $subject): string
    {
        $tokens = $this->vault->currentCredentials($subject, $this->http);
        // Verifying the upstream session ensures a user's ACL is enforced by SuiteCRM
        // and catches accidentally mis-linked personal credentials.
        $realUser = $this->http->currentUserId($tokens['access_token']);
        if (!hash_equals($tokens['crm_user_id'], $realUser)) {
            throw new RuntimeException('SuiteCRM identity mismatch: account requires relinking');
        }
        return $tokens['access_token'];
    }

    public function linked(string $subject): bool
    {
        return $this->vault->linked($subject);
    }

    public function modules(string $subject): array
    {
        $data = $this->http->request('GET', '/Api/V8/meta/modules', $this->userToken($subject));
        $attrs = $data['data']['attributes'] ?? [];
        if (!is_array($attrs)) {
            return [];
        }
        return array_values(array_filter(array_keys($attrs), static function ($key): bool {
            try {
                Policy::module($key);
                return true;
            } catch (\InvalidArgumentException) {
                return false;
            }
        }));
    }

    public function schema(string $subject, string $module): array
    {
        Policy::module($module);
        $data = $this->http->request(
            'GET',
            '/Api/V8/meta/fields/'.$module,
            $this->userToken($subject)
        );
        $attrs = $data['data']['attributes'] ?? [];
        if (!is_array($attrs)) {
            return [];
        }
        $schema = [];
        foreach ($attrs as $field => $definition) {
            if (!is_string($field)) {
                continue;
            }
            try {
                Policy::fields($module, [$field]);
                $schema[$field] = [
                    'name' => $field,
                    'type' => is_array($definition) ? ($definition['type'] ?? '') : '',
                    'required' => is_array($definition) && ($definition['required'] ?? false) === true,
                ];
            } catch (\InvalidArgumentException) {
                continue;
            }
        }
        return array_values($schema);
    }

    public function listRecords(
        string $subject,
        string $module,
        array $fields = [],
        int $page = 1,
        int $pageSize = 10
    ): array {
        Policy::module($module);
        if ($page < 1 || $page > 1000 || $pageSize < 1 || $pageSize > 20) {
            throw new \InvalidArgumentException('Pagination must be between 1-1000 and 1-20');
        }
        $selected = Policy::fields($module, $fields);
        $records = $this->http->request(
            'GET',
            '/Api/V8/module/'.$module,
            $this->userToken($subject),
            query: [
                'page[number]' => $page,
                'page[size]' => $pageSize,
                'fields['.$module.']' => implode(',', $selected),
            ]
        );
        return [
            'module' => $module,
            'page' => $page,
            'page_size' => $pageSize,
            'records' => $this->sanitize($records, $selected),
        ];
    }

    public function getRecord(
        string $subject,
        string $module,
        string $recordId,
        array $fields = []
    ): array {
        Policy::module($module);
        $id = Policy::recordId($recordId);
        $selected = Policy::fields($module, $fields);
        $record = $this->http->request(
            'GET',
            '/Api/V8/module/'.$module.'/'.$id,
            $this->userToken($subject),
            query: ['fields['.$module.']' => implode(',', $selected)]
        );
        $rows = $this->sanitize($record, $selected);
        if ($rows === []) {
            throw new RuntimeException('SuiteCRM record not found or not authorized');
        }
        return $rows[0];
    }

    private function sanitize(array $response, array $fields): array
    {
        $rows = $response['data'] ?? [];
        if (isset($rows['attributes'])) {
            $rows = [$rows];
        }
        if (!is_array($rows)) {
            return [];
        }
        $result = [];
        foreach (array_slice($rows, 0, 20) as $row) {
            if (!is_array($row) || !is_array($row['attributes'] ?? null)) {
                continue;
            }
            $result[] = [
                'id' => is_string($row['id'] ?? null) ? $row['id'] : null,
                'type' => is_string($row['type'] ?? null) ? $row['type'] : null,
                'attributes' => Policy::project($row['attributes'], $fields),
            ];
        }
        return $result;
    }

    public function getRawForDiff(string $subject, string $module, string $id, array $fields): array
    {
        return $this->getRecord($subject, $module, $id, $fields);
    }

    public function writeApproved(
        string $subject,
        string $method,
        string $module,
        array $attrs,
        ?string $id
    ): array {
        if ($method !== 'create' && $method !== 'update') {
            throw new RuntimeException('Unsupported write operation');
        }
        Policy::changes($module, $attrs, $method);
        $data = ['type' => $module, 'attributes' => $attrs];
        if ($method === 'update') {
            $data['id'] = Policy::recordId($id ?? '');
        }
        $result = $this->http->request(
            $method === 'create' ? 'POST' : 'PATCH',
            '/Api/V8/module',
            $this->userToken($subject),
            payload: ['data' => $data]
        );
        $returned = $result['data']['id'] ?? $id;
        return ['record_id' => is_string($returned) ? $returned : $id];
    }
}

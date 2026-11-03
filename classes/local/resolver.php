<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace tool_mailhealth\local;

/**
 * Looks up DNS records, keeping "no record" separate from "the lookup failed".
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class resolver {
    /**
     * Returns the TXT records for a name.
     *
     * @param string $name The DNS name.
     * @return string[]|null The record values, an empty array if there are none, or null if the lookup failed.
     */
    public function txt(string $name): ?array {
        $records = $this->lookup($name, DNS_TXT);
        if ($records === null) {
            return null;
        }
        return array_values(array_map(fn(array $record): string => (string) ($record['txt'] ?? ''), $records));
    }

    /**
     * Returns the MX hosts for a name.
     *
     * @param string $name The DNS name.
     * @return string[]|null The hosts, an empty array if there are none, or null if the lookup failed.
     */
    public function mx(string $name): ?array {
        $records = $this->lookup($name, DNS_MX);
        if ($records === null) {
            return null;
        }
        return array_values(array_map(fn(array $record): string => (string) ($record['target'] ?? ''), $records));
    }

    /**
     * Runs a DNS query.
     *
     * @param string $name The DNS name.
     * @param int $type A DNS_* record type constant.
     * @return array|null The records, or null if the lookup failed.
     */
    protected function lookup(string $name, int $type): ?array {
        if (!self::is_valid_name($name)) {
            return null;
        }
        // PHP raises a warning for temporary DNS failures, which are reported to the admin as a finding instead.
        // phpcs:ignore Generic.PHP.NoSilencedErrors.Discouraged
        $records = @dns_get_record($name, $type);
        return $records === false ? null : $records;
    }

    /**
     * Checks that a string is safe to use as a DNS name.
     *
     * @param string $name The name to check.
     * @return bool
     */
    public static function is_valid_name(string $name): bool {
        return strlen($name) <= 253
            && preg_match('/^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/i', $name) === 1;
    }
}

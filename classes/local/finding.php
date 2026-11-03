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
 * One result from a mail check.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class finding {
    /**
     * Creates a finding.
     *
     * @param string $status One of the \core\check\result status constants.
     * @param string $identifier The language string identifier, without its finding_ prefix.
     * @param array $params Values for the language string. These can come from DNS, so treat them as untrusted.
     */
    public function __construct(
        /** @var string One of the \core\check\result status constants. */
        public readonly string $status,
        /** @var string The language string identifier, without its finding_ prefix. */
        public readonly string $identifier,
        /** @var array Values for the language string. */
        public readonly array $params = [],
    ) {
    }

    /**
     * Returns the message for this finding.
     *
     * @return string Plain text that still needs escaping for output.
     */
    public function get_message(): string {
        return get_string('finding_' . $this->identifier, 'tool_mailhealth', (object) $this->params);
    }
}

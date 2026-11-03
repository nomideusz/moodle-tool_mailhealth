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

namespace tool_mailhealth\check;

use core\check\check;
use core\check\result;
use tool_mailhealth\local\report;

/**
 * Reports the overall mail health on the system status page.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class mailhealth extends check {
    /**
     * Links to the full report.
     *
     * @return \action_link|null
     */
    public function get_action_link(): ?\action_link {
        return new \action_link(
            new \moodle_url('/admin/tool/mailhealth/index.php'),
            get_string('pluginname', 'tool_mailhealth')
        );
    }

    /**
     * Returns the worst status found, using a cached summary when one is available.
     *
     * @return result
     */
    public function get_result(): result {
        $cache = \cache::make('tool_mailhealth', 'summary');
        $summary = $cache->get('latest');
        if ($summary === false) {
            $summary = report::run()->get_summary();
            $cache->set('latest', $summary);
        }
        return new result(
            $summary['status'],
            get_string('checksummary', 'tool_mailhealth', (object) $summary['counts'])
        );
    }
}

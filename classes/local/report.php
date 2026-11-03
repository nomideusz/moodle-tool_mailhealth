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

use core\check\result;

/**
 * Runs all mail checks for the site and prepares the results for display.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class report {
    /** @var string[] Statuses from least to most serious. */
    public const SEVERITY = [
        result::NA,
        result::OK,
        result::INFO,
        result::UNKNOWN,
        result::WARNING,
        result::ERROR,
        result::CRITICAL,
    ];

    /**
     * Creates a report.
     *
     * @param string|null $domain The sending domain, or null if there is no usable one.
     * @param array $sections Findings keyed by section name.
     */
    public function __construct(
        /** @var string|null The sending domain, or null if there is no usable one. */
        public readonly ?string $domain,
        /** @var array Findings keyed by section name. */
        public readonly array $sections,
    ) {
    }

    /**
     * Runs the checks for this site and refreshes the summary shown on the status page.
     *
     * @param resolver|null $resolver The DNS resolver, or null for the system one.
     * @return self
     */
    public static function run(?resolver $resolver = null): self {
        global $CFG;

        $analyser = new analyser($resolver ?? new resolver());
        $sections = ['settings' => $analyser->check_settings($CFG)];

        $address = (string) ($CFG->noreplyaddress ?? '');
        $domain = analyser::sending_domain($address);
        if ($domain === null) {
            $sections['settings'][] = new finding(result::ERROR, 'noreply_unusable', ['address' => $address]);
        } else {
            $sections['spf'] = $analyser->check_spf($domain);
            $sections['dkim'] = $analyser->check_dkim($domain, (string) ($CFG->emaildkimselector ?? ''), $CFG->dataroot);
            $sections['dmarc'] = $analyser->check_dmarc($domain);
            $sections['mx'] = $analyser->check_mx($domain);
        }

        $report = new self($domain, $sections);
        \cache::make('tool_mailhealth', 'summary')->set('latest', $report->get_summary());
        return $report;
    }

    /**
     * Returns the worst status in the report and the number of problems.
     *
     * @return array With keys status and counts.
     */
    public function get_summary(): array {
        $worst = 0;
        $counts = ['errors' => 0, 'warnings' => 0];
        foreach ($this->sections as $findings) {
            foreach ($findings as $finding) {
                $worst = max($worst, (int) array_search($finding->status, self::SEVERITY, true));
                if ($finding->status === result::ERROR) {
                    $counts['errors']++;
                } else if ($finding->status === result::WARNING) {
                    $counts['warnings']++;
                }
            }
        }
        return ['status' => self::SEVERITY[$worst], 'counts' => $counts];
    }

    /**
     * Builds the context for the report template.
     *
     * @param \core_renderer $output The renderer.
     * @return array
     */
    public function export_for_template(\core_renderer $output): array {
        $sections = [];
        foreach ($this->sections as $name => $findings) {
            $sections[] = [
                'heading' => get_string('section_' . $name, 'tool_mailhealth'),
                'findings' => array_map(fn(finding $finding): array => [
                    'badge' => $output->check_result(new result($finding->status, '')),
                    'message' => $finding->get_message(),
                ], $findings),
            ];
        }
        $summary = $this->get_summary();
        return [
            'intro' => $this->domain === null
                ? get_string('intro_nodomain', 'tool_mailhealth')
                : get_string('intro', 'tool_mailhealth', $this->domain),
            'summary' => get_string('checksummary', 'tool_mailhealth', (object) $summary['counts']),
            'sections' => $sections,
            'testurl' => (new \moodle_url('/admin/testoutgoingmailconf.php'))->out(false),
        ];
    }
}

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

namespace tool_mailhealth;

use core\check\result;
use tool_mailhealth\check\mailhealth;
use tool_mailhealth\local\finding;
use tool_mailhealth\local\report;
use tool_mailhealth\local\resolver;

#[\PHPUnit\Framework\Attributes\CoversClass(report::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(mailhealth::class)]
/**
 * Tests for the report and the status check.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \tool_mailhealth\local\report
 * @covers     \tool_mailhealth\check\mailhealth
 */
final class report_test extends \advanced_testcase {
    /**
     * Creates a resolver that finds no records and counts its lookups.
     *
     * @return resolver
     */
    private function resolver(): resolver {
        return new class extends resolver {
            /** @var int The number of lookups made. */
            public int $lookups = 0;

            /**
             * Returns no TXT records.
             *
             * @param string $name The DNS name.
             * @return array|null
             */
            public function txt(string $name): ?array {
                $this->lookups++;
                return [];
            }

            /**
             * Returns no MX hosts.
             *
             * @param string $name The DNS name.
             * @return array|null
             */
            public function mx(string $name): ?array {
                $this->lookups++;
                return [];
            }
        };
    }

    /**
     * Tests that text from DNS is escaped when the report is displayed.
     */
    public function test_dns_text_is_escaped(): void {
        global $PAGE;
        $this->resetAfterTest();
        $PAGE->set_url('/admin/tool/mailhealth/index.php');
        $PAGE->set_context(\context_system::instance());
        $output = $PAGE->get_renderer('core');

        $report = new report('a.org', ['spf' => [
            new finding(result::ERROR, 'spf_brokeninclude', ['names' => '<script>alert(1)</script>']),
        ]]);
        $html = $output->render_from_template('tool_mailhealth/report', $report->export_for_template($output));

        $this->assertStringNotContainsString('<script>alert', $html);
        $this->assertStringContainsString('&lt;script&gt;alert', $html);
    }

    /**
     * Tests that the summary reports the worst status and counts problems.
     */
    public function test_summary(): void {
        $report = new report('a.org', ['spf' => [
            new finding(result::OK, 'spf_redirect'),
            new finding(result::WARNING, 'spf_neutral'),
            new finding(result::ERROR, 'spf_passall'),
            new finding(result::WARNING, 'spf_noall'),
        ]]);
        $this->assertSame(
            ['status' => result::ERROR, 'counts' => ['errors' => 1, 'warnings' => 2]],
            $report->get_summary()
        );

        $clean = new report('a.org', ['spf' => [new finding(result::OK, 'spf_redirect')]]);
        $this->assertSame(result::OK, $clean->get_summary()['status']);
    }

    /**
     * Tests that an unusable no-reply address is reported, and that no DNS lookups are made for it.
     */
    public function test_unusable_address_skips_dns(): void {
        global $CFG;
        $this->resetAfterTest();
        $CFG->noreplyaddress = 'noreply@localhost';

        $resolver = $this->resolver();
        $report = report::run($resolver);

        $this->assertSame(0, $resolver->lookups);
        $this->assertNull($report->domain);
        $this->assertSame(['settings'], array_keys($report->sections));
        $identifiers = array_map(fn(finding $f): string => $f->identifier, $report->sections['settings']);
        $this->assertContains('noreply_unusable', $identifiers);
    }

    /**
     * Tests that the status check uses the summary saved by the last report.
     */
    public function test_status_check_uses_cached_summary(): void {
        global $CFG;
        $this->resetAfterTest();
        $CFG->noreplyaddress = 'noreply@a.org';

        report::run($this->resolver());

        $check = new mailhealth();
        $result = $check->get_result();
        $this->assertSame(result::ERROR, $result->get_status());
        $this->assertSame('Errors: 1. Warnings: 3.', $result->get_summary());
        $this->assertSame('Mail health', $check->get_name());
    }
}

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
use tool_mailhealth\local\analyser;
use tool_mailhealth\local\finding;
use tool_mailhealth\local\resolver;

/**
 * Tests for the mail checks.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \tool_mailhealth\local\analyser
 */
#[\PHPUnit\Framework\Attributes\CoversClass(analyser::class)]
final class analyser_test extends \basic_testcase {
    /**
     * Creates an analyser that answers from fixed records.
     *
     * @param array $txt TXT records by name. A null value means the lookup failed.
     * @param array $mx MX hosts by name. A null value means the lookup failed.
     * @return analyser
     */
    private function analyser(array $txt = [], array $mx = []): analyser {
        return new analyser(new class ($txt, $mx) extends resolver {
            /**
             * Stores the fixed records.
             *
             * @param array $txtrecords TXT records by name.
             * @param array $mxrecords MX hosts by name.
             */
            public function __construct(
                /** @var array TXT records by name. */
                private array $txtrecords,
                /** @var array MX hosts by name. */
                private array $mxrecords,
            ) {
            }

            /**
             * Returns fixed TXT records.
             *
             * @param string $name The DNS name.
             * @return array|null
             */
            public function txt(string $name): ?array {
                return array_key_exists($name, $this->txtrecords) ? $this->txtrecords[$name] : [];
            }

            /**
             * Returns fixed MX hosts.
             *
             * @param string $name The DNS name.
             * @return array|null
             */
            public function mx(string $name): ?array {
                return array_key_exists($name, $this->mxrecords) ? $this->mxrecords[$name] : [];
            }
        });
    }

    /**
     * Reduces findings to "status:identifier" strings.
     *
     * @param finding[] $findings The findings.
     * @return string[]
     */
    private function codes(array $findings): array {
        return array_map(fn(finding $f): string => $f->status . ':' . $f->identifier, $findings);
    }

    /**
     * Tests how the SPF policy is judged.
     *
     * @dataProvider spf_policy_provider
     * @param string $record The SPF record.
     * @param string $expected The expected first finding.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('spf_policy_provider')]
    public function test_spf_policy(string $record, string $expected): void {
        $findings = $this->analyser(['a.org' => [$record]])->check_spf('a.org');
        $this->assertSame($expected, $this->codes($findings)[0]);
    }

    /**
     * Provides SPF records and the expected policy finding.
     *
     * @return array
     */
    public static function spf_policy_provider(): array {
        return [
            'hard fail' => ['v=spf1 mx -all', result::OK . ':spf_ok'],
            'soft fail' => ['v=spf1 mx ~all', result::OK . ':spf_ok'],
            'neutral' => ['v=spf1 mx ?all', result::WARNING . ':spf_neutral'],
            'pass all' => ['v=spf1 +all', result::ERROR . ':spf_passall'],
            'implicit pass all' => ['v=spf1 all', result::ERROR . ':spf_passall'],
            'no all' => ['v=spf1 mx', result::WARNING . ':spf_noall'],
            'redirect' => ['v=spf1 redirect=b.org', result::OK . ':spf_redirect'],
            'upper case' => ['V=SPF1 MX -ALL', result::OK . ':spf_ok'],
        ];
    }

    /**
     * Tests missing, duplicate and failed SPF lookups, ignoring unrelated TXT records.
     */
    public function test_spf_record_presence(): void {
        $this->assertSame(
            [result::ERROR . ':spf_missing'],
            $this->codes($this->analyser(['a.org' => ['google-site-verification=x']])->check_spf('a.org'))
        );
        $this->assertSame(
            [result::ERROR . ':spf_multiple'],
            $this->codes($this->analyser(['a.org' => ['v=spf1 -all', 'v=spf1 mx -all']])->check_spf('a.org'))
        );
        $this->assertSame(
            [result::UNKNOWN . ':spf_lookupfailed'],
            $this->codes($this->analyser(['a.org' => null])->check_spf('a.org'))
        );
    }

    /**
     * Tests that a prefix of a mechanism name is not counted as a lookup.
     */
    public function test_spf_counts_only_real_mechanisms(): void {
        $record = 'v=spf1 ip4:192.0.2.1 a mx/24 a:b.org exists:c.org ptr -all';
        $findings = $this->analyser(['a.org' => [$record]])->check_spf('a.org');
        $this->assertSame(5, $findings[1]->params['count']);
    }

    /**
     * Tests that includes are followed when counting, across several levels.
     */
    public function test_spf_lookups_follow_includes(): void {
        $findings = $this->analyser([
            'a.org' => ['v=spf1 include:b.org -all'],
            'b.org' => ['v=spf1 include:c.org a mx ~all'],
            'c.org' => ['v=spf1 a ~all'],
        ])->check_spf('a.org');
        $this->assertSame(result::OK . ':spf_lookups', $this->codes($findings)[1]);
        $this->assertSame(5, $findings[1]->params['count']);
    }

    /**
     * Tests that more than ten lookups is an error.
     */
    public function test_spf_too_many_lookups(): void {
        $record = 'v=spf1 ' . str_repeat('a ', 11) . '-all';
        $findings = $this->analyser(['a.org' => [$record]])->check_spf('a.org');
        $this->assertContains(result::ERROR . ':spf_toomanylookups', $this->codes($findings));
    }

    /**
     * Tests that an include loop ends and doesn't count forever.
     */
    public function test_spf_include_loop(): void {
        $findings = $this->analyser([
            'a.org' => ['v=spf1 include:b.org -all'],
            'b.org' => ['v=spf1 include:a.org -all'],
        ])->check_spf('a.org');
        $this->assertSame(2, $findings[1]->params['count']);
    }

    /**
     * Tests that broken and unresolvable includes are told apart.
     */
    public function test_spf_include_problems(): void {
        $broken = $this->analyser(['a.org' => ['v=spf1 include:gone.org -all']])->check_spf('a.org');
        $this->assertContains(result::ERROR . ':spf_brokeninclude', $this->codes($broken));

        $failed = $this->analyser(['a.org' => ['v=spf1 include:b.org -all'], 'b.org' => null])->check_spf('a.org');
        $this->assertContains(result::UNKNOWN . ':spf_countincomplete', $this->codes($failed));
    }

    /**
     * Tests how DMARC records are judged.
     *
     * @dataProvider dmarc_provider
     * @param array $txt The TXT records.
     * @param string $domain The sending domain.
     * @param string $expected The expected finding.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('dmarc_provider')]
    public function test_dmarc(array $txt, string $domain, string $expected): void {
        $this->assertSame([$expected], $this->codes($this->analyser($txt)->check_dmarc($domain)));
    }

    /**
     * Provides DMARC records and the expected finding.
     *
     * @return array
     */
    public static function dmarc_provider(): array {
        return [
            'reject' => [['_dmarc.a.org' => ['v=DMARC1; p=reject']], 'a.org', result::OK . ':dmarc_ok'],
            'quarantine' => [['_dmarc.a.org' => ['v=DMARC1; p=quarantine;']], 'a.org', result::OK . ':dmarc_ok'],
            'none' => [['_dmarc.a.org' => ['v=DMARC1; p=none']], 'a.org', result::INFO . ':dmarc_none'],
            'bad policy' => [['_dmarc.a.org' => ['v=DMARC1; p=maybe']], 'a.org', result::ERROR . ':dmarc_invalid'],
            'no policy' => [['_dmarc.a.org' => ['v=DMARC1; rua=mailto:x@a.org']], 'a.org', result::ERROR . ':dmarc_invalid'],
            'missing' => [[], 'a.org', result::WARNING . ':dmarc_missing'],
            'other txt' => [['_dmarc.a.org' => ['hello']], 'a.org', result::WARNING . ':dmarc_missing'],
            'multiple' => [
                ['_dmarc.a.org' => ['v=DMARC1; p=none', 'v=DMARC1; p=reject']],
                'a.org',
                result::ERROR . ':dmarc_multiple',
            ],
            'failed' => [['_dmarc.a.org' => null], 'a.org', result::UNKNOWN . ':dmarc_lookupfailed'],
            'inherits parent' => [['_dmarc.a.org' => ['v=DMARC1; p=reject']], 'mail.a.org', result::OK . ':dmarc_ok'],
            'parent sp wins' => [
                ['_dmarc.a.org' => ['v=DMARC1; p=reject; sp=none']],
                'mail.a.org',
                result::INFO . ':dmarc_none',
            ],
            'sp ignored on the domain itself' => [
                ['_dmarc.a.org' => ['v=DMARC1; p=reject; sp=none']],
                'a.org',
                result::OK . ':dmarc_ok',
            ],
        ];
    }

    /**
     * Tests DKIM checks against a real key pair.
     */
    public function test_dkim(): void {
        $dataroot = make_request_directory();
        $this->assertSame(
            [result::INFO . ':dkim_noselector'],
            $this->codes($this->analyser()->check_dkim('a.org', '', $dataroot))
        );
        $this->assertSame(
            [result::ERROR . ':dkim_keymissing', result::ERROR . ':dkim_dnsmissing'],
            $this->codes($this->analyser()->check_dkim('a.org', 's1', $dataroot))
        );

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        mkdir("{$dataroot}/dkim/a.org", 0777, true);
        file_put_contents("{$dataroot}/dkim/a.org/s1.private", $pem);
        $public = preg_replace('/-----[^-]+-----|\s+/', '', openssl_pkey_get_details($key)['key']);

        $name = 's1._domainkey.a.org';
        $check = fn(array $txt): array => $this->codes($this->analyser($txt)->check_dkim('a.org', 's1', $dataroot));

        $this->assertSame([result::OK . ':dkim_ok'], $check([$name => ["v=DKIM1; k=rsa; p={$public}"]]));
        $this->assertSame([result::OK . ':dkim_ok'], $check([$name => ["v=DKIM1; p={$public}; t=s"]]));
        $this->assertSame([result::ERROR . ':dkim_mismatch'], $check([$name => ['v=DKIM1; k=rsa; p=QUJD']]));
        $this->assertSame([result::ERROR . ':dkim_revoked'], $check([$name => ['v=DKIM1; p=']]));
        $this->assertSame([result::ERROR . ':dkim_dnsmissing'], $check([$name => []]));
        $this->assertSame([result::UNKNOWN . ':dkim_lookupfailed'], $check([$name => null]));
    }

    /**
     * Tests that a short DKIM key is flagged.
     */
    public function test_dkim_weak_key(): void {
        $dataroot = make_request_directory();
        $key = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        mkdir("{$dataroot}/dkim/a.org", 0777, true);
        file_put_contents("{$dataroot}/dkim/a.org/s1.private", $pem);
        $codes = $this->codes($this->analyser()->check_dkim('a.org', 's1', $dataroot));
        $this->assertContains(result::WARNING . ':dkim_weakkey', $codes);
    }

    /**
     * Tests the MX check.
     */
    public function test_mx(): void {
        $this->assertSame(
            [result::OK . ':mx_ok'],
            $this->codes($this->analyser([], ['a.org' => ['mail.a.org']])->check_mx('a.org'))
        );
        $this->assertSame([result::WARNING . ':mx_missing'], $this->codes($this->analyser()->check_mx('a.org')));
        $this->assertSame(
            [result::UNKNOWN . ':mx_lookupfailed'],
            $this->codes($this->analyser([], ['a.org' => null])->check_mx('a.org'))
        );
    }

    /**
     * Tests which no-reply addresses have a usable domain.
     *
     * @dataProvider sending_domain_provider
     * @param string $address The address.
     * @param string|null $expected The expected domain.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('sending_domain_provider')]
    public function test_sending_domain(string $address, ?string $expected): void {
        $this->assertSame($expected, analyser::sending_domain($address));
    }

    /**
     * Provides no-reply addresses and the expected domain.
     *
     * @return array
     */
    public static function sending_domain_provider(): array {
        return [
            'normal' => ['noreply@Mail.Example-School.org', 'mail.example-school.org'],
            'reserved example' => ['noreply@example.com', null],
            'localhost' => ['noreply@localhost', null],
            'local suffix' => ['noreply@moodle.local', null],
            'ip address' => ['noreply@192.0.2.1', null],
            'no at sign' => ['noreply', null],
            'empty' => ['', null],
            'dns injection' => ['noreply@a.org; rm -rf', null],
        ];
    }

    /**
     * Tests the settings checks, including that no password appears in any finding.
     */
    public function test_settings(): void {
        $analyser = $this->analyser();
        $secret = 'hunter2-secret';

        $plaintext = $analyser->check_settings((object) [
            'smtphosts' => 'smtp.a.org:587',
            'smtpuser' => 'moodle',
            'smtppass' => $secret,
            'smtpsecure' => '',
            'handlebounces' => 1,
        ]);
        $this->assertSame([result::ERROR . ':smtp_plaintext'], $this->codes($plaintext));
        $this->assertStringNotContainsString($secret, json_encode($plaintext));

        $this->assertSame(
            [result::OK . ':smtp_ok'],
            $this->codes($analyser->check_settings((object) [
                'smtphosts' => 'smtp.a.org:587',
                'smtpuser' => 'moodle',
                'smtpsecure' => 'tls',
                'handlebounces' => 1,
            ]))
        );

        $this->assertSame(
            [
                result::ERROR . ':noemailever',
                result::WARNING . ':diverted',
                result::WARNING . ':smtp_none',
                result::INFO . ':bounces_off',
                result::INFO . ':alloweddomains',
            ],
            $this->codes($analyser->check_settings((object) [
                'noemailever' => true,
                'divertallemailsto' => 'dev@a.org',
                'allowedemaildomains' => "a.org\n",
            ]))
        );
    }
}

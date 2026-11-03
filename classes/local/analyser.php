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
 * Checks mail settings and the sending domain's DNS records.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class analyser {
    /** @var int The most DNS lookups an SPF check may need (RFC 7208, section 4.6.4). */
    public const SPF_MAX_LOOKUPS = 10;

    /** @var int The key length below which a DKIM key is flagged as weak. */
    public const DKIM_MIN_BITS = 2048;

    /**
     * Creates the analyser.
     *
     * @param resolver $resolver The DNS resolver.
     */
    public function __construct(
        /** @var resolver The DNS resolver. */
        private readonly resolver $resolver,
    ) {
    }

    /**
     * Checks whether Moodle's settings allow mail to be sent and delivered.
     *
     * @param object $cfg Moodle's configuration object.
     * @return finding[]
     */
    public function check_settings(object $cfg): array {
        $findings = [];
        if (!empty($cfg->noemailever)) {
            $findings[] = new finding(result::ERROR, 'noemailever');
        }
        if (!empty($cfg->divertallemailsto)) {
            $findings[] = new finding(result::WARNING, 'diverted');
        }

        if (empty($cfg->smtphosts)) {
            $findings[] = new finding(result::WARNING, 'smtp_none');
        } else if (!empty($cfg->smtpuser) && empty($cfg->smtpsecure)) {
            $findings[] = new finding(result::ERROR, 'smtp_plaintext');
        } else if (empty($cfg->smtpsecure)) {
            $findings[] = new finding(result::INFO, 'smtp_noencryption');
        } else {
            $findings[] = new finding(result::OK, 'smtp_ok');
        }

        if (empty($cfg->handlebounces)) {
            $findings[] = new finding(result::INFO, 'bounces_off');
        }
        if (trim((string) ($cfg->allowedemaildomains ?? '')) !== '') {
            $findings[] = new finding(result::INFO, 'alloweddomains');
        }
        return $findings;
    }

    /**
     * Returns the domain of the no-reply address, if it is one mail can really be sent from.
     *
     * @param string $address The no-reply address.
     * @return string|null The domain in lower case, or null if it cannot receive replies or pass authentication.
     */
    public static function sending_domain(string $address): ?string {
        $at = strrpos($address, '@');
        if ($at === false) {
            return null;
        }
        $domain = strtolower(trim(substr($address, $at + 1)));
        if (function_exists('idn_to_ascii') && preg_match('/[^\x00-\x7f]/', $domain)) {
            $domain = (string) idn_to_ascii($domain);
        }
        if (!resolver::is_valid_name($domain) || filter_var($domain, FILTER_VALIDATE_IP)) {
            return null;
        }
        $reserved = '/(^|\.)(example\.(com|net|org)|localhost|local|localdomain|internal|invalid|test|example)$/';
        return preg_match($reserved, $domain) ? null : $domain;
    }

    /**
     * Checks the SPF record of a domain.
     *
     * @param string $domain The sending domain.
     * @return finding[]
     */
    public function check_spf(string $domain): array {
        $txt = $this->resolver->txt($domain);
        if ($txt === null) {
            return [new finding(result::UNKNOWN, 'spf_lookupfailed', ['domain' => $domain])];
        }
        $records = self::spf_records($txt);
        if (!$records) {
            return [new finding(result::ERROR, 'spf_missing', ['domain' => $domain])];
        }
        if (count($records) > 1) {
            return [new finding(result::ERROR, 'spf_multiple', ['domain' => $domain, 'count' => count($records)])];
        }

        $findings = [self::spf_policy_finding($records[0])];

        $state = (object) ['lookups' => 0, 'broken' => [], 'failed' => false, 'seen' => [$domain => true]];
        $this->count_spf_lookups($records[0], $state);
        if ($state->broken) {
            $findings[] = new finding(result::ERROR, 'spf_brokeninclude', ['names' => implode(', ', $state->broken)]);
        }
        if ($state->lookups > self::SPF_MAX_LOOKUPS) {
            $findings[] = new finding(result::ERROR, 'spf_toomanylookups', [
                'count' => $state->lookups,
                'max' => self::SPF_MAX_LOOKUPS,
            ]);
        } else if ($state->failed) {
            $findings[] = new finding(result::UNKNOWN, 'spf_countincomplete', ['count' => $state->lookups]);
        } else {
            $findings[] = new finding(result::OK, 'spf_lookups', [
                'count' => $state->lookups,
                'max' => self::SPF_MAX_LOOKUPS,
            ]);
        }
        return $findings;
    }

    /**
     * Picks the SPF records from a list of TXT records.
     *
     * @param string[] $txt The TXT records.
     * @return string[]
     */
    private static function spf_records(array $txt): array {
        return array_values(array_filter($txt, fn(string $value): bool => preg_match('/^v=spf1(\s|$)/i', $value) === 1));
    }

    /**
     * Judges how an SPF record treats servers it does not list.
     *
     * @param string $record The SPF record.
     * @return finding
     */
    private static function spf_policy_finding(string $record): finding {
        if (preg_match('/\sredirect=/i', $record) && !preg_match('/\s[-~?+]?all(\s|$)/i', $record)) {
            return new finding(result::OK, 'spf_redirect');
        }
        if (!preg_match('/\s([-~?+]?)all(\s|$)/i', $record, $match)) {
            return new finding(result::WARNING, 'spf_noall');
        }
        return match ($match[1]) {
            '-', '~' => new finding(result::OK, 'spf_ok', ['policy' => $match[1] . 'all']),
            '?' => new finding(result::WARNING, 'spf_neutral'),
            default => new finding(result::ERROR, 'spf_passall'),
        };
    }

    /**
     * Counts the DNS lookups an SPF record needs, following includes and redirects.
     *
     * @param string $record The SPF record.
     * @param \stdClass $state The running totals.
     */
    private function count_spf_lookups(string $record, \stdClass $state): void {
        foreach (preg_split('/\s+/', trim($record)) as $term) {
            if (!preg_match('/^[-~?+]?(include:|redirect=|a(?=$|[:\/])|mx(?=$|[:\/])|ptr(?=$|:)|exists:)(.*)$/i', $term, $match)) {
                continue;
            }
            $state->lookups++;
            $mechanism = strtolower($match[1]);
            if ($mechanism !== 'include:' && $mechanism !== 'redirect=') {
                continue;
            }
            $target = strtolower($match[2]);
            if (isset($state->seen[$target]) || str_contains($target, '%') || $state->lookups > self::SPF_MAX_LOOKUPS) {
                // Macros can't be expanded here, and a record already over the limit needs no further counting.
                continue;
            }
            $state->seen[$target] = true;
            $txt = $this->resolver->txt($target);
            if ($txt === null) {
                $state->failed = true;
                continue;
            }
            $records = self::spf_records($txt);
            if (count($records) !== 1) {
                $state->broken[] = $target;
                continue;
            }
            $this->count_spf_lookups($records[0], $state);
        }
    }

    /**
     * Checks the DMARC policy that applies to a domain.
     *
     * Without a record on the domain itself, parent domains are tried. Receivers use the organisational
     * domain for this, and querying a public suffix such as co.uk simply finds nothing.
     *
     * @param string $domain The sending domain.
     * @return finding[]
     */
    public function check_dmarc(string $domain): array {
        $labels = explode('.', $domain);
        while (count($labels) >= 2) {
            $name = implode('.', $labels);
            $txt = $this->resolver->txt('_dmarc.' . $name);
            if ($txt === null) {
                return [new finding(result::UNKNOWN, 'dmarc_lookupfailed', ['domain' => $name])];
            }
            $records = array_values(array_filter(
                $txt,
                fn(string $value): bool => preg_match('/^v\s*=\s*DMARC1\s*(;|$)/i', $value) === 1
            ));
            if (count($records) > 1) {
                return [new finding(result::ERROR, 'dmarc_multiple', ['domain' => $name, 'count' => count($records)])];
            }
            if ($records) {
                return [self::dmarc_policy_finding($records[0], $name, $name !== $domain)];
            }
            array_shift($labels);
        }
        return [new finding(result::WARNING, 'dmarc_missing', ['domain' => $domain])];
    }

    /**
     * Judges a DMARC record.
     *
     * @param string $record The DMARC record.
     * @param string $name The domain the record was found on.
     * @param bool $inherited Whether the record comes from a parent of the sending domain.
     * @return finding
     */
    private static function dmarc_policy_finding(string $record, string $name, bool $inherited): finding {
        $tags = [];
        foreach (explode(';', $record) as $part) {
            if (str_contains($part, '=')) {
                [$key, $value] = explode('=', $part, 2);
                $tags[strtolower(trim($key))] = strtolower(trim($value));
            }
        }
        $policy = $tags['p'] ?? '';
        if ($inherited && isset($tags['sp'])) {
            $policy = $tags['sp'];
        }
        $params = ['domain' => $name, 'policy' => $policy];
        return match ($policy) {
            'reject', 'quarantine' => new finding(result::OK, 'dmarc_ok', $params),
            'none' => new finding(result::INFO, 'dmarc_none', $params),
            default => new finding(result::ERROR, 'dmarc_invalid', $params),
        };
    }

    /**
     * Checks DKIM signing as Moodle does it.
     *
     * Core only logs a developer debugging message when a key is missing, then sends the mail unsigned.
     *
     * @param string $domain The sending domain.
     * @param string $selector The value of $CFG->emaildkimselector.
     * @param string $dataroot The value of $CFG->dataroot.
     * @return finding[]
     */
    public function check_dkim(string $domain, string $selector, string $dataroot): array {
        if ($selector === '') {
            return [new finding(result::INFO, 'dkim_noselector')];
        }
        $name = $selector . '._domainkey.' . $domain;
        $path = "{$dataroot}/dkim/{$domain}/{$selector}.private";
        $findings = [];

        $publickey = null;
        if (!is_readable($path)) {
            $findings[] = new finding(result::ERROR, 'dkim_keymissing', ['domain' => $domain, 'selector' => $selector]);
        } else {
            $key = openssl_pkey_get_private((string) file_get_contents($path));
            $details = $key === false ? false : openssl_pkey_get_details($key);
            if ($details === false || empty($details['key'])) {
                $findings[] = new finding(result::WARNING, 'dkim_keyunreadable');
            } else {
                $publickey = preg_replace('/-----[^-]+-----|\s+/', '', $details['key']);
                if ((int) ($details['bits'] ?? 0) < self::DKIM_MIN_BITS) {
                    $findings[] = new finding(result::WARNING, 'dkim_weakkey', ['bits' => (int) ($details['bits'] ?? 0)]);
                }
            }
        }

        $txt = $this->resolver->txt($name);
        if ($txt === null) {
            $findings[] = new finding(result::UNKNOWN, 'dkim_lookupfailed', ['name' => $name]);
            return $findings;
        }
        $published = null;
        foreach ($txt as $value) {
            if (preg_match('/(?:^|;)\s*p\s*=\s*([^;]*)/i', $value, $match)) {
                $published = preg_replace('/\s+/', '', $match[1]);
                break;
            }
        }
        if ($published === null) {
            $findings[] = new finding(result::ERROR, 'dkim_dnsmissing', ['name' => $name]);
        } else if ($published === '') {
            $findings[] = new finding(result::ERROR, 'dkim_revoked', ['name' => $name]);
        } else if ($publickey !== null && $publickey !== $published) {
            $findings[] = new finding(result::ERROR, 'dkim_mismatch', ['name' => $name]);
        } else if ($publickey !== null) {
            $findings[] = new finding(result::OK, 'dkim_ok', ['name' => $name]);
        } else {
            $findings[] = new finding(result::INFO, 'dkim_dnsonly', ['name' => $name]);
        }
        return $findings;
    }

    /**
     * Checks that a domain can receive bounces and replies.
     *
     * @param string $domain The sending domain.
     * @return finding[]
     */
    public function check_mx(string $domain): array {
        $hosts = $this->resolver->mx($domain);
        if ($hosts === null) {
            return [new finding(result::UNKNOWN, 'mx_lookupfailed', ['domain' => $domain])];
        }
        if (!$hosts) {
            return [new finding(result::WARNING, 'mx_missing', ['domain' => $domain])];
        }
        return [new finding(result::OK, 'mx_ok', ['domain' => $domain])];
    }
}

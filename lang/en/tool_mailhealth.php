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

/**
 * English strings for the mail health tool.
 *
 * @package    tool_mailhealth
 * @copyright  2026 Dymet
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['cachedef_summary'] = 'Latest mail health summary';
$string['checkmailhealth'] = 'Mail health';
$string['checksummary'] = 'Errors: {$a->errors}. Warnings: {$a->warnings}.';
$string['finding_alloweddomains'] = 'Allowed email domains are set, so some mail is sent from those domains. This report only checks the no-reply domain, so check their DNS records too.';
$string['finding_bounces_off'] = 'Bounce handling is off, so Moodle won\'t notice addresses that keep rejecting mail.';
$string['finding_diverted'] = 'All mail is being diverted by $CFG->divertallemailsto, so users are not receiving it.';
$string['finding_dkim_dnsmissing'] = 'No DKIM key is published at {$a->name}, so receivers can\'t verify messages signed by Moodle.';
$string['finding_dkim_dnsonly'] = 'A DKIM key is published at {$a->name}, but it couldn\'t be compared with the private key.';
$string['finding_dkim_keymissing'] = 'A DKIM selector is set, but the private key is missing or unreadable at dkim/{$a->domain}/{$a->selector}.private in the data directory. Moodle is sending this domain\'s mail unsigned.';
$string['finding_dkim_keyunreadable'] = 'The DKIM private key couldn\'t be read. It may be invalid or protected by a passphrase.';
$string['finding_dkim_lookupfailed'] = 'The DNS lookup for {$a->name} failed, so DKIM couldn\'t be checked.';
$string['finding_dkim_mismatch'] = 'The key published at {$a->name} doesn\'t match Moodle\'s private key, so signatures will fail.';
$string['finding_dkim_noselector'] = 'Moodle isn\'t signing mail because no DKIM selector is set. Your mail server may sign it instead. To confirm, send a test message and check its headers.';
$string['finding_dkim_ok'] = 'The key published at {$a->name} matches Moodle\'s private key.';
$string['finding_dkim_revoked'] = 'The DKIM key at {$a->name} has been revoked because its value is empty.';
$string['finding_dkim_weakkey'] = 'The DKIM key is only {$a->bits} bits. Use at least 2048 bits, as some receivers reject shorter keys.';
$string['finding_dmarc_invalid'] = 'The DMARC record on {$a->domain} has a missing or invalid policy.';
$string['finding_dmarc_lookupfailed'] = 'The DNS lookup for the DMARC record of {$a->domain} failed.';
$string['finding_dmarc_missing'] = 'No DMARC record was found for {$a->domain}. Large mailbox providers require one from bulk senders.';
$string['finding_dmarc_multiple'] = '{$a->domain} has {$a->count} DMARC records. Receivers ignore DMARC when there is more than one.';
$string['finding_dmarc_none'] = 'The DMARC record on {$a->domain} only monitors (policy: none). It meets bulk sender rules, but doesn\'t stop spoofing.';
$string['finding_dmarc_ok'] = 'The DMARC record on {$a->domain} has an enforcing policy ({$a->policy}).';
$string['finding_mx_lookupfailed'] = 'The DNS lookup for the MX records of {$a->domain} failed.';
$string['finding_mx_missing'] = '{$a->domain} has no MX records, so replies and bounces may not be delivered, and some receivers reject mail from such domains.';
$string['finding_mx_ok'] = '{$a->domain} has MX records and can receive replies and bounces.';
$string['finding_noemailever'] = 'Moodle won\'t send any mail because $CFG->noemailever is set in config.php.';
$string['finding_noreply_unusable'] = 'The no-reply address "{$a->address}" doesn\'t use a public domain, so its DNS can\'t be checked and many receivers will reject the mail.';
$string['finding_smtp_noencryption'] = 'Moodle connects to the SMTP server without encryption. This is only safe if the server is on the same machine or a private network.';
$string['finding_smtp_none'] = 'No SMTP server is set, so mail goes through PHP\'s mail function. Deliverability is usually better through an authenticated SMTP server.';
$string['finding_smtp_ok'] = 'Moodle connects to the SMTP server with encryption.';
$string['finding_smtp_plaintext'] = 'An SMTP username is set but encryption is off, so the password can be sent unencrypted. Set the SMTP security option to TLS or SSL.';
$string['finding_spf_brokeninclude'] = 'SPF points to names without exactly one valid SPF record: {$a->names}. Receivers can treat this as a permanent SPF error.';
$string['finding_spf_countincomplete'] = 'SPF uses at least {$a->count} DNS lookups, but a DNS failure stopped the full count.';
$string['finding_spf_lookupfailed'] = 'The DNS lookup for the SPF record of {$a->domain} failed.';
$string['finding_spf_lookups'] = 'SPF uses {$a->count} of the {$a->max} DNS lookups allowed.';
$string['finding_spf_missing'] = 'No SPF record was found for {$a->domain}. Many receivers will reject or junk this mail.';
$string['finding_spf_multiple'] = '{$a->domain} has {$a->count} SPF records. Only one is allowed, so SPF fails until they are merged.';
$string['finding_spf_neutral'] = 'SPF ends in ?all, which says nothing about servers it doesn\'t list. Use ~all or -all.';
$string['finding_spf_noall'] = 'SPF has no "all" rule, so it says nothing about servers it doesn\'t list. Add ~all or -all.';
$string['finding_spf_ok'] = 'SPF has a policy for servers it doesn\'t list ({$a->policy}).';
$string['finding_spf_passall'] = 'SPF ends in +all or all, which lets any server send as this domain. Use ~all or -all.';
$string['finding_spf_redirect'] = 'SPF redirects to another domain\'s record.';
$string['finding_spf_toomanylookups'] = 'SPF needs {$a->count} DNS lookups, but the limit is {$a->max}. Receivers can treat this as a permanent SPF error.';
$string['intro'] = 'Checking Moodle\'s mail settings and the DNS records of {$a}, the domain of the no-reply address.';
$string['intro_nodomain'] = 'Checking Moodle\'s mail settings. DNS checks need a no-reply address on a public domain.';
$string['pluginname'] = 'Mail health';
$string['privacy:metadata'] = 'The mail health tool only reads site settings and public DNS records. It doesn\'t store personal data.';
$string['section_dkim'] = 'DKIM';
$string['section_dmarc'] = 'DMARC';
$string['section_mx'] = 'Replies and bounces';
$string['section_settings'] = 'Moodle settings';
$string['section_spf'] = 'SPF';
$string['sendtest'] = 'Send a test message';

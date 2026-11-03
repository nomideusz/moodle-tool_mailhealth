# Mail health

Finds out why Moodle's email goes to spam or never arrives. It checks your mail settings and your sending domain's SPF, DKIM, DMARC and MX records, then explains each problem in plain language.

## What it checks

- **Moodle settings:** mail switched off or diverted, no SMTP server, passwords sent without encryption, a no-reply address on a domain that can't work, and bounce handling.
- **SPF:** missing or duplicate records, rules that let any server send as you, the 10-lookup limit (following includes), and broken includes.
- **DKIM:** when Moodle signs mail itself, a missing private key, a key that doesn't match DNS, revoked keys and short keys. Moodle only logs a developer debugging message when a key is missing, then sends mail unsigned.
- **DMARC:** missing, duplicate or invalid records and the policy in force, including a policy inherited from a parent domain.
- **MX:** whether the domain can receive replies and bounces.

The overall result also appears under **Site administration > Reports > System status**. That summary is cached for up to an hour, and opening the report refreshes it.

## Limits

- It only checks the domain of the no-reply address. If you use allowed email domains, check those separately.
- If your mail server signs messages, it can't confirm DKIM from Moodle's side. Send a test message and check the headers.
- It doesn't check that your SMTP server is listed in SPF.
- A clean report means the setup looks right. It doesn't guarantee that mail reaches the inbox.

## Installation

1. Go to **Site administration > Plugins > Install plugins** and upload the ZIP file, or unzip it to `admin/tool/mailhealth` (`public/admin/tool/mailhealth` on Moodle 5.1 or later).
2. Complete the upgrade.
3. Open **Site administration > Server > Email > Mail health**.

There are no settings and no extra setup. The server must be allowed to make DNS lookups.

## Requirements

Moodle 4.5 to 5.3.

## Privacy and external services

It stores no personal data and uses no external service. The only things it sends out are DNS queries for your sending domain and the names its SPF record refers to, through your server's normal DNS resolver.

The report page opens the DKIM private key to compare it with DNS. The key is never shown or stored. Like all site settings, the page requires the `moodle/site:config` capability.

## Licence

GNU GPL v3 or later. See [LICENSE](LICENSE).

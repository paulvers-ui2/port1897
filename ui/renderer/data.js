// DNS servers the Android app ships with, from its prefilled database
// (assets/database/rethink_v22.db in AuroraVPN v1.11.1). Generated.
'use strict';

const DNS_LISTS = {
 "doh": [
  {
   "name": "Cloudflare",
   "url": "https://cloudflare-dns.com/dns-query",
   "desc": "Does not block any DNS requests. Uses Cloudflare\\'s 1.1.1.1 DNS endpoint.",
   "ips": "1.1.1.1,1.0.0.1"
  },
  {
   "name": "Cloudflare Family",
   "url": "https://family.cloudflare-dns.com/dns-query",
   "desc": "Blocks malware and adult content. Uses Cloudflare\\'s 1.1.1.3 DNS endpoint.",
   "ips": "1.1.1.3,1.0.0.3"
  },
  {
   "name": "Cloudflare Security",
   "url": "https://security.cloudflare-dns.com/dns-query",
   "desc": "Blocks malicious content. Uses Cloudflare\\'s 1.1.1.2 DNS endpoint.",
   "ips": "1.1.1.2,1.0.0.2"
  },
  {
   "name": "Google",
   "url": "https://dns.google/dns-query",
   "desc": "Does not block any DNS requests. Uses Google\\'s DNS endpoint.",
   "ips": "8.8.8.8,8.8.4.4"
  },
  {
   "name": "CleanBrowsing Family",
   "url": "https://doh.cleanbrowsing.org/doh/family-filter/",
   "desc": "Family filter blocks access to all adult, pornographic and explicit sites. It also blocks proxy and VPN domains that could be used to bypass our filters. Mixed content sites (like Reddit) are also blocked. Google, Bing and Youtube are set to the Safe Mode.",
   "ips": ""
  },
  {
   "name": "CleanBrowsing Adult",
   "url": "https://doh.cleanbrowsing.org/doh/adult-filter/",
   "desc": "Adult filter blocks access to all adult, pornographic and explicit sites. It does not block proxy or VPNs, nor mixed-content sites. Sites like Reddit are allowed. Google and Bing are set to the Safe Mode.",
   "ips": ""
  },
  {
   "name": "Quad9 Secure",
   "url": "https://dns.quad9.net/dns-query",
   "desc": "Quad9 routes your DNS queries through a secure network of servers around the globe.",
   "ips": "9.9.9.9,149.112.112.112"
  }
 ],
 "rdns": [
  {
   "name": "RDNS Default",
   "url": "https://sky.rethinkdns.com/rec",
   "desc": "Blocks over 100,000+ phishing, malvertising, malware, spyware, ransomware, cryptojacking and other threats.",
   "ips": ""
  },
  {
   "name": "RDNS Adult",
   "url": "https://sky.rethinkdns.com/pec",
   "desc": "Blocks over 30,000 adult websites.",
   "ips": ""
  },
  {
   "name": "RDNS Piracy",
   "url": "https://sky.rethinkdns.com/1:EID-BwCB",
   "desc": "Blocks torrent, dubious video streaming and file sharing websites.",
   "ips": ""
  },
  {
   "name": "RDNS Social Media",
   "url": "https://sky.rethinkdns.com/1:AEAAEA==",
   "desc": "Blocks popular social media including Facebook, Instagram, and WhatsApp.",
   "ips": ""
  },
  {
   "name": "RDNS Security",
   "url": "https://sky.rethinkdns.com/sec",
   "desc": "Blocks over 150,000 malware, ransomware, phishing and other threats.",
   "ips": ""
  },
  {
   "name": "RDNS Privacy",
   "url": "https://sky.rethinkdns.com/1:QAcCAIAcAhCkAg==",
   "desc": "Blocks over 100,000+ adware, spyware, and trackers through some of the most extensive blocklists.",
   "ips": ""
  }
 ],
 "dot": [
  {
   "name": "Cloudflare",
   "url": "tls://1dot1dot1dot1.cloudflare-dns.com",
   "desc": "Cloudflare’s DNS over TLS. No blocking."
  },
  {
   "name": "Cloudflare family",
   "url": "tls://family.cloudflare-dns.com",
   "desc": "Cloudflare’s DNS over TLS. Blocks Malware and Adult content."
  },
  {
   "name": "Adguard",
   "url": "tls://dns.adguard-dns.com",
   "desc": "Adguard’s DNS over TLS. Block ads, tracking, and phishing."
  },
  {
   "name": "Mullvad Ad-block",
   "url": "tls://adblock.dns.mullvad.net",
   "desc": "Mullvad’s DNS over TLS. Includes ad-blocking and tracker blocking."
  },
  {
   "name": "Mullvad Extended",
   "url": "tls://extended.dns.mullvad.net",
   "desc": "Mullvad’s DNS over TLS. Includes ad-blocking, tracker, malware and social media blocking."
  }
 ],
 "dnscrypt": [
  {
   "name": "Cleanbrowsing Family",
   "url": "sdns://AQMAAAAAAAAAFDE4NS4yMjguMTY4LjE2ODo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn",
   "desc": "Blocks access to all adult, pornographic and explicit sites. It also blocks proxy and VPN domains that are used to bypass the filters. Mixed content sites (like Reddit) are also blocked. Google, Bing and Youtube are set to the Safe Mode."
  },
  {
   "name": "Adguard",
   "url": "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
   "desc": "Protects your device from malware and more."
  },
  {
   "name": "Adguard Family",
   "url": "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
   "desc": "Adguard DNS with safe-search and adult content blocking."
  },
  {
   "name": "Quad9 Security",
   "url": "sdns://AQMAAAAAAAAAEjE0OS4xMTIuMTEyLjk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
   "desc": "Quad9 (anycast) dnssec/no–log/filter 9.9.9.9 – 149.112.112.9 – 149.112.112.112"
  },
  {
   "name": "Quad9",
   "url": "sdns://AQYAAAAAAAAADTkuOS45LjEyOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA",
   "desc": "Quad9 (anycast) no–dnssec/no–log/no–filter/ecs 9.9.9.12 – 149.112.112.12"
  }
 ],
 "odoh": [
  {
   "name": "Cloudflare",
   "url": "https://odoh.cloudflare-dns.com/dns-query",
   "relay": "",
   "desc": "Cloudflare ODoH server"
  },
  {
   "name": "ODoH Crypto",
   "url": "https://odoh.crypto.sx/dns-query",
   "relay": "",
   "desc": "ODoH target server. Anycast, no logs. Backend hosted by Scaleway. Maintained by Frank Denis."
  },
  {
   "name": "Ibksturm",
   "url": "https://ibksturm.synology.me/dns-query",
   "relay": "",
   "desc": "ODoH target server hosted by Ibksturm. No logs, No Filter, DNSSEC."
  }
 ],
 "proxy": [
  {
   "name": "Google",
   "url": "8.8.8.8:53",
   "desc": "Plain DNS (unencrypted) to Google"
  },
  {
   "name": "Cloudflare",
   "url": "1.1.1.1:53",
   "desc": "Plain DNS (unencrypted) to Cloudflare"
  },
  {
   "name": "Quad9",
   "url": "9.9.9.9:53",
   "desc": "Plain DNS (unencrypted) to Quad9"
  },
  {
   "name": "Tor DNSPort",
   "url": "127.0.0.1:5400",
   "desc": "Tor's DNS port on this PC (like Orbot on Android). Needs Tor running with DNSPort 5400."
  }
 ]
};

// DNSCrypt relays from the same database (Android: DNSCrypt relays dialog).
const DNSCRYPT_RELAYS = [
 {
  "name": "Netherlands",
  "url": "sdns://gRI1MS4xNS4xMjQuMjA4OjQzNDM"
 },
 {
  "name": "France",
  "url": "sdns://gREyMTIuMTI5LjQ2LjMyOjQ0Mw"
 },
 {
  "name": "Sweden",
  "url": "sdns://gRMxMjguMTI3LjEwNC4xMDg6NDQz"
 },
 {
  "name": "US - Los Angeles, CA",
  "url": "sdns://gRAyMy4xOS42Ny4xMTY6NDQz"
 },
 {
  "name": "Singapore",
  "url": "sdns://gRMxNzQuMTM4LjI5LjE3NToxNDQz"
 }
];

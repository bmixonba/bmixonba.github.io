# Overview

## tldr; 
The port shadow is a devastating attack against Virtual Private Networks (VPNs) that allow an attacker to port scan a target,
intercept their traffic and escalate from adjacent to in-path, reroute packets, and perform injections, completely pwning the
confidentiality, availability, and integrity of the channel established between the VPN Client (target) and server.

Read our [PETS 2025 paper, "Attacking Connection Tracking Frameworks as used by Virtual Private Networks"](https://breakpointingbad.com/2021/09/08/Port-Shadows-via-Network-Alchemy.html) for a full technical breakdown.

# Disclosure

1. https://www.openwall.com/lists/oss-security/2021/09/08/3
2. https://seclists.org/oss-sec/2021/q3/159

# Media

1. [https://citizenlab.ca/2024/07/vulnerabilities-in-vpns-paper-presented-at-the-privacy-enhancing-technologies-symposium-2024/](https://citizenlab.ca/2024/07/vulnerabilities-in-vpns-paper-presented-at-the-privacy-enhancing-technologies-symposium-2024/)
2. [https://pulse.internetsociety.org/blog/half-of-top-10-most-popular-vpns-are-vulnerable-to-port-shadow-interception-attack](https://pulse.internetsociety.org/blog/half-of-top-10-most-popular-vpns-are-vulnerable-to-port-shadow-interception-attack)
3. [https://www.csoonline.com/article/3476176/port-shadow-a-new-vpn-weakness.html](https://www.csoonline.com/article/3476176/port-shadow-a-new-vpn-weakness.html)
4. [https://www.pcmag.com/news/port-shadow-flaw-can-exploit-some-vpns-to-attack-users](https://www.pcmag.com/news/port-shadow-flaw-can-exploit-some-vpns-to-attack-users) 
5. [https://blog.torguard.net/unpacking-the-port-shadow-vpn-vulnerability/](https://blog.torguard.net/unpacking-the-port-shadow-vpn-vulnerability/)
6. [https://hide.me/en/blog/port-shadow-breaks-every-vpn-users-privacy/](https://hide.me/en/blog/port-shadow-breaks-every-vpn-users-privacy/)
7. [https://stackdiary.com/vpn-users-worldwide-vulnerable-to-port-shadow-attack/](https://stackdiary.com/vpn-users-worldwide-vulnerable-to-port-shadow-attack/)
8. [https://www.securityweek.com/port-shadow-attack-allows-vpn-traffic-interception-redirection/](https://www.securityweek.com/port-shadow-attack-allows-vpn-traffic-interception-redirection/)
9. [https://cyberinsider.com/port-shadow-attack-still-impacts-multiple-popular-vpn-products-on-linux/](https://cyberinsider.com/port-shadow-attack-still-impacts-multiple-popular-vpn-products-on-linux/)
10. [https://github.com/mullvad/mullvadvpn-app/issues/6482](https://github.com/mullvad/mullvadvpn-app/issues/6482)
11. [https://cyberpress.org/new-vpn-port-shadow-vulnerabilities/](https://cyberpress.org/new-vpn-port-shadow-vulnerabilities/)
12. [https://www.scworld.com/news/researchers-find-port-shadow-flaws-in-vpn-platforms](https://www.scworld.com/news/researchers-find-port-shadow-flaws-in-vpn-platforms)
13. [https://tech.yahoo.com/vpn/articles/port-shadow-vpn-attacks-whos-134916748.html](https://tech.yahoo.com/vpn/articles/port-shadow-vpn-attacks-whos-134916748.html)
14. [https://www.sos-vo.org/news/port-shadow-attack-allows-vpn-traffic-interception-redirection](https://www.sos-vo.org/news/port-shadow-attack-allows-vpn-traffic-interception-redirection)
15. [https://www.reddit.com/r/ProtonVPN/comments/1e5s43p/attacking_connection_tracking_frameworks_as_used/](https://www.reddit.com/r/ProtonVPN/comments/1e5s43p/attacking_connection_tracking_frameworks_as_used/)
16. [https://www.linkedin.com/posts/sean-eyre-477460192_port-shadow-attack-allows-vpn-traffic-interception-activity-7221992403468001280-XyNT/]()
17. [https://securityonline.info/new-research-exposes-vpn-vulnerability-port-shadow-attacks-undermine-user-privacy/](https://securityonline.info/new-research-exposes-vpn-vulnerability-port-shadow-attacks-undermine-user-privacy/)
18. [https://airvpn.org/forums/topic/60593-port-shadow-attacks-fail-against-airvpn/](https://airvpn.org/forums/topic/60593-port-shadow-attacks-fail-against-airvpn/)
19. [https://www.linkedin.com/posts/freddymacho_connection-tracking-frameworks-activity-7223692502015315968-boiA/](https://www.linkedin.com/posts/freddymacho_connection-tracking-frameworks-activity-7223692502015315968-boiA/)
20. [https://x.com/Dinosn/status/1813770754120355940](https://x.com/Dinosn/status/1813770754120355940)
21. [https://cybersecuritynews.com/vpn-port-shadow-traffic-interception/](https://cybersecuritynews.com/vpn-port-shadow-traffic-interception/)
22. [https://malware.news/t/researchers-find-port-shadow-flaws-in-vpn-platforms/84322](https://malware.news/t/researchers-find-port-shadow-flaws-in-vpn-platforms/84322)
22. [https://blog.desdelinux.net/en/port-shadow-an-attack-that-allows-intercepting-or-redirecting-encrypted-traffic-on-VPN-servers/](https://blog.desdelinux.net/en/port-shadow-an-attack-that-allows-intercepting-or-redirecting-encrypted-traffic-on-VPN-servers/)
23. [https://github.com/d0rb/CVE-2021-3773](https://github.com/d0rb/CVE-2021-3773)
24. [https://x.com/PCMag/status/1813721610152509700](https://x.com/PCMag/status/1813721610152509700)
25. [https://x.com/citizenlab/status/1813304525496950786](https://x.com/citizenlab/status/1813304525496950786)
26. [https://www.technadu.com/port-shadow-vpn-flaw-allows-hackers-to-spy-redirect-user-traffic/540473/](https://www.technadu.com/port-shadow-vpn-flaw-allows-hackers-to-spy-redirect-user-traffic/540473/)
27. [https://www.security.nl/posting/850144/Vpn-gebruikers+wereldwijd+kwetsbaar+voor+port+shadow-aanval](https://www.security.nl/posting/850144/Vpn-gebruikers+wereldwijd+kwetsbaar+voor+port+shadow-aanval)

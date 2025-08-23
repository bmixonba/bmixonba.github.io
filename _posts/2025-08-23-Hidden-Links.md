# Hidden Links: Analyzing Secret Families of VPN Apps

[Breakpointing Bad](https://breakpointingbad.com/) recently lead research
efforts along with [The Center for Biocomputing, Security and Sociity at ASU](https://biodesign.asu.edu/biocomputing-security-and-society/) and [Citizen Lab](citizenlab.ca) 
to uncover hidden relationships between VPN apps popular on [Google Play](https://play.google.com/) and Apple App store.
Our study focused on [Google Play](https://play.google.com/) store, though many of the VPNs we investigated were also available
on Apple App Store. The tldr; is:

1. Two families of VPNs claim to be based out of Singapore but are run by a Chinese National
2. One family is is owned by Qihoo360, a major Chinese cyber security firm that
contracts for the People's Liberation Army.
3. Both families offer Shadowsocks for tunnel building
4. Both families contain hard-coded Shadowsocks passwords and these can be extracted and used 
by an in or on-path attacker to remove the tunnel encryption
5. The also covertly collect the user's zip code by calling ip-api.com and uploading this information
to Firebase, Huawei Analytics, and Yandex Analytics

# In the Media

For more information, read the following links, including our original publication at FOCI 2025 (#1):

1. [FOCI](https://www.petsymposium.org/foci/2025/foci-2025-0008.pdf)
2. [Citizen Lab](https://citizenlab.ca/2025/08/hidden-links-analyzing-secret-families-of-vpn-apps/)
3. [Forbes](https://www.forbes.com/sites/zakdoffman/2025/08/20/delete-every-app-thats-on-this-list-your-phone-will-be-tracked/)
4. [Hackreader](https://hackread.com/citizen-lab-vpn-networks-sharing-ownership-security-flaws/) 
5. [Helpnet](https://www.helpnetsecurity.com/2025/08/19/android-vpn-apps-used-by-millions-are-covertly-connected-and-insecure/) 

# To Journalists 

Please don't forget to give [Breakpointing Bad](https://breakpointingbad.com/) and [The Center for Biocomputing, Security and Sociity at ASU](https://biodesign.asu.edu/biocomputing-security-and-society/)
credit as for this work as well. No shade on [Citizen Lab](citizenlab.ca), they do
great work, but small organizations like [Breakpointing Bad](https://breakpointingbad.com/)
really benefit from the coverage and it helps ASU's research centers like BSS as well. 
[Breakpointing Bad](https://breakpointingbad.com/) isn't a big fancy organization like 
[Citizen Lab](citizenlab.ca) (yet... ;})

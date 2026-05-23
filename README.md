# 🔍 NetIntel - Domain & IP Intelligence

📦 **Open source · MIT:** [github.com/AnshumanAtrey/netintel](https://github.com/AnshumanAtrey/netintel)


Get instant security and technical information about any domain or IP address. Perfect for security teams, website owners, and IT professionals.

[![Apify Actor](https://img.shields.io/badge/Apify-Actor-blue)](https://apify.com/store)

## 🎯 What You Can Check

Enter a domain (google.com) or IP address (8.8.8.8) and instantly get:

- 📋 **Owner & Registration** - Who owns it? When does it expire?
- 🌐 **DNS & IP Info** - What IP? Where does email go?
- 🔒 **SSL Certificate** - When does it expire? Is it valid?
- 📧 **Email Health** - Will emails reach inbox or spam?
- 📍 **Location & ISP** - Where is it? Who hosts it?
- 🛡️ **Security Check** - Is it safe? Any threats?
- 🔌 **Open Ports** - What services are running?

**Check one or check them all** - you choose what information you need.

## ⚡ Quick Start

1. Enter a domain or IP address
2. Select what information you need
3. Get instant results

That's it! No technical knowledge required.

## 💡 Common Use Cases

**Website Owner:** "Is my SSL certificate about to expire?"  
→ Check SSL Certificate

**Security Team:** "Is this IP address safe?"  
→ Check Security + Location

**Email Admin:** "Why are our emails going to spam?"  
→ Check Email Health

**IT Manager:** "Monitor 50 company domains"  
→ Use Batch Mode + Export to CSV

## 📊 What You Get

**Example: Checking google.com**

```
✅ Owner & Registration
   Google LLC, expires 2028-09-14

✅ SSL Certificate  
   Valid, expires in 56 days

✅ Email Health
   Score: 75/100 (Good)
   ⚠️ Missing SPF record

✅ Security Check
   Safe, no threats detected

✅ Location
   Mountain View, CA, USA
```

## 🎯 Pricing

**Pay per usage** - Simple and transparent.

Costs based on compute time and targets checked. Start small, scale as needed.


## 🔒 Privacy & Legal

- ✅ All information is publicly available
- ✅ No data stored permanently
- ✅ Legal for security research
- ⚠️ Always get permission before scanning targets you don't own


## FAQ

### How long does a check take?
Usually 5-30 seconds per target depending on which modules are enabled. Port scans add 20-60 seconds.

### Can I check multiple domains at once?
Yes. Pass an array of targets — batch mode handles up to 100+ in a single run.

### Does it work on IPv6?
Yes — both IPv4 and IPv6 supported throughout. WHOIS, DNS, GeoIP all handle v6.

### Why does my email-health score say "missing SPF"?
SPF records prevent spoofing of your domain. If a domain has no SPF record, anyone can send mail "from" that domain and it'll often land in inbox. NetIntel flags this so you can fix it before competitors abuse it.

### Is this legal?
Yes — all information is publicly available (WHOIS records, DNS records, public SSL certificates, GeoIP). Port scanning unowned hosts at scale is a different story; only port-scan targets you own or are authorized to test.

### Can I export results to CSV / Google Sheets?
Yes — every Apify actor's dataset can be downloaded as CSV, Excel, JSON, or XML. Most teams export to Google Sheets via the Apify-Sheets integration on Make/Zapier.

## Pairs nicely with

Bundle for richer recon workflows:

- **[Holehe Email OSINT](https://apify.com/anshumanatrey/holehe-email-osint)** — Check which sites an email is registered on (120+ platforms, no alerts sent)
- **[theHarvester](https://apify.com/anshumanatrey/theharvester-osint)** — Discover subdomains, emails, IPs from 54 OSINT sources (then enrich the IPs with NetIntel)
- **[nmap](https://apify.com/anshumanatrey/nmap-scanner)** — Deeper port scans + NSE scripts for the IPs NetIntel finds
- **[Bug Bounty Finder](https://apify.com/anshumanatrey/bug-bounty-finder)** — Check whether a domain you're scanning has an active bounty program
- **[Social Analyzer](https://apify.com/anshumanatrey/social-analyzer)** — Find a brand or username across 900+ social platforms
- **[Zomato Restaurant Scraper](https://apify.com/anshumanatrey/zomato-restaurant-scraper)** — Restaurant lead lists by city (phone, address, cuisines)

---

**Need help?** Check the `/docs` folder for detailed guides.

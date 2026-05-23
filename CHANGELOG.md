# Changelog

All notable changes to NetIntel will be documented in this file.

## [1.4.0] - 2025-11-09

### Added
- **Email Reputation Scoring** - Medium-high earning feature
  - MX record validation and redundancy checking
  - SPF (Sender Policy Framework) analysis with policy detection
  - DMARC (Domain-based Message Authentication) validation
  - Email blacklist checking (4 major lists)
  - Reputation scoring (0-100) with 5 levels
  - Security issue detection and recommendations
  - Authentication status summary
  - Zero external dependencies (uses Node.js built-in DNS)

### Changed
- Updated INPUT_SCHEMA with emailReputation analysis type
- Enhanced export utility to include email reputation fields
- Added email reputation to orchestrator

### Documentation
- Added `docs/EMAIL_REPUTATION_GUIDE.md` with complete reference
- Added `examples/email-reputation-example.js` with use cases
- Updated README and features comparison

## [1.3.0] - 2025-11-09

### Added
- **Bulk Export Feature** - Enterprise feature (2x base price)
  - CSV export for spreadsheets (Excel, Google Sheets)
  - JSON export with pretty printing and metadata
  - JSON Lines (JSONL) export for streaming/big data
  - Automatic file naming with timestamps
  - Flattened CSV structure with all analyzer data
  - Configurable export options (pretty print, metadata)
  - Zero external dependencies (uses Node.js built-in)

### Changed
- Updated INPUT_SCHEMA with export format options
- Enhanced main.js to handle export requests
- Added export integration with batch mode

### Documentation
- Added `docs/BULK_EXPORT_GUIDE.md` with complete field reference
- Added `examples/bulk-export-example.js` with all formats
- Updated README with export feature

## [1.2.0] - 2025-11-09

### Added
- **Enhanced SSL Certificate Monitoring** - Premium recurring revenue feature
  - Expiry alerts with severity levels (warning/critical)
  - Multi-domain coverage tracking (SAN)
  - Self-signed certificate detection
  - Detailed certificate chain information
  - Status tracking: valid, expiring_soon, expiring_critical, expired, not_yet_valid
  - Hours and days until expiry calculations
  - Comprehensive error handling
  - Zero external dependencies (uses Node.js built-in https/tls)

### Changed
- Completely rewrote SSL analyzer with standardized output format
- Added alert system for certificate issues
- Enhanced certificate data extraction
- Improved error messages and timeout handling

### Documentation
- Added `docs/SSL_MONITORING_GUIDE.md` with pricing strategies
- Added `examples/ssl-monitoring-example.js` for batch monitoring
- Updated README with SSL monitoring details

## [1.1.0] - 2025-11-09

### Added
- **Reverse DNS Lookup** - New high-value feature ($2/1k market rate)
  - PTR record resolution for IP addresses
  - Hostname discovery from IPs
  - Integrated with orchestrator
  - Automatic skipping for domain targets
  - Full error handling and timeout protection
  - Works with batch mode
  - Zero external dependencies (uses Node.js built-in DNS)

### Changed
- Updated INPUT_SCHEMA.json to include `reverseDns` analysis type
- Enhanced orchestrator to handle reverse DNS requests
- Updated README with reverse DNS documentation

### Documentation
- Added `docs/REVERSE_DNS_GUIDE.md` with usage examples
- Added `examples/reverse-dns-example.js` for demonstration
- Updated README feature list

## [1.0.0] - 2025-11-08

### Initial Release
- WHOIS lookup for IPs and domains
- DNS record resolution (A, AAAA, MX, TXT, NS, CNAME, SOA)
- GeoIP location lookup
- Reputation scoring
- Port scanning
- SSL certificate analysis
- Batch processing mode
- Confidence scoring
- Result correlation
- Threat indicator detection

/**
 * Configuration constants for NetIntel Actor
 */

export const COMMON_PORTS = [
    { port: 21, service: 'FTP' },
    { port: 22, service: 'SSH' },
    { port: 23, service: 'Telnet' },
    { port: 25, service: 'SMTP' },
    { port: 53, service: 'DNS' },
    { port: 80, service: 'HTTP' },
    { port: 443, service: 'HTTPS' },
    { port: 3306, service: 'MySQL' },
    { port: 3389, service: 'RDP' },
    { port: 5432, service: 'PostgreSQL' },
    { port: 8080, service: 'HTTP-Alt' },
    { port: 8443, service: 'HTTPS-Alt' }
];

export const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];

export const API_ENDPOINTS = {
    // Free GeoIP API (no key required for basic usage)
    geoip: 'http://ip-api.com/json',
    
    // Alternative GeoIP APIs (can be configured)
    geoipBackup: 'https://ipapi.co',
    
    // Reputation/Blacklist APIs
    abuseipdb: 'https://api.abuseipdb.com/api/v2/check',
    
    // SSL certificate info
    sslLabs: 'https://api.ssllabs.com/api/v3/analyze'
};

export const TIMEOUTS = {
    default: 30000, // 30 seconds
    whois: 10000,   // 10 seconds
    dns: 5000,      // 5 seconds
    port: 3000,     // 3 seconds per port
    api: 15000      // 15 seconds for external APIs
};

export const CONFIDENCE_WEIGHTS = {
    whois: 0.2,
    dns: 0.15,
    geolocation: 0.15,
    reputation: 0.3,
    ports: 0.1,
    ssl: 0.1
};

export const THREAT_INDICATORS = {
    suspiciousPorts: [23, 3389, 1433, 5900], // Telnet, RDP, MSSQL, VNC
    knownMaliciousTLDs: ['.tk', '.ml', '.ga', '.cf', '.gq'],
    vpnKeywords: ['vpn', 'proxy', 'hosting', 'datacenter']
};

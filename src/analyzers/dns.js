import { promises as dns } from 'dns';
import { TIMEOUTS } from '../config/constants.js';

/**
 * Performs comprehensive DNS lookups for a domain
 * @param {string} target - Domain to lookup
 * @param {string} targetType - 'ip' or 'domain'
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} DNS records in standardized format
 */
export async function analyzeDns(target, targetType, options = {}) {
    console.log(`[DNS] Analyzing domain: ${target}`);
    
    // DNS lookups only work for domains, not IPs
    if (targetType === 'ip') {
        console.log(`[DNS] Skipping DNS lookup for IP address (use reverse DNS instead)`);
        return {
            success: false,
            analyzer: 'dns',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            error: 'DNS lookup not applicable for IP addresses. Use reverse DNS for IPs.'
        };
    }
    
    try {
        const timeout = options.timeout || TIMEOUTS.dns;
        
        console.log(`[DNS] Resolving all record types for ${target}...`);
        
        // Lookup all DNS record types in parallel using Promise.allSettled
        // This ensures all lookups complete even if some fail
        const results = await Promise.allSettled([
            resolveWithTimeout(dns.resolve4(target), timeout, 'A'),
            resolveWithTimeout(dns.resolve6(target), timeout, 'AAAA'),
            resolveWithTimeout(dns.resolveMx(target), timeout, 'MX'),
            resolveWithTimeout(dns.resolveTxt(target), timeout, 'TXT'),
            resolveWithTimeout(dns.resolveNs(target), timeout, 'NS'),
            resolveWithTimeout(dns.resolveCname(target), timeout, 'CNAME'),
            resolveWithTimeout(dns.resolveSoa(target), timeout, 'SOA')
        ]);
        
        // Parse results from Promise.allSettled
        const dnsData = {
            a: getResult(results[0]),
            aaaa: getResult(results[1]),
            mx: getResult(results[2]),
            txt: flattenTxtRecords(getResult(results[3])), // TXT returns nested arrays
            ns: getResult(results[4]),
            cname: getResult(results[5]),
            soa: getResult(results[6])
        };
        
        // Count successful lookups
        const successCount = Object.values(dnsData).filter(v => v !== null).length;
        console.log(`[DNS] Successfully resolved ${successCount}/7 record types for ${target}`);
        
        // Log which records were found
        const foundRecords = Object.entries(dnsData)
            .filter(([_, value]) => value !== null)
            .map(([key]) => key.toUpperCase());
        console.log(`[DNS] Found records: ${foundRecords.join(', ')}`);
        
        return {
            success: true,
            analyzer: 'dns',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            data: dnsData,
            summary: {
                totalRecordTypes: 7,
                foundRecordTypes: successCount,
                recordTypes: foundRecords
            }
        };
        
    } catch (error) {
        console.error(`[DNS] Error for ${target}:`, error.message);
        
        // Provide helpful error messages
        let errorMessage = error.message;
        if (error.code === 'ENOTFOUND') {
            errorMessage = 'Domain not found - DNS resolution failed';
        } else if (error.code === 'ENODATA') {
            errorMessage = 'No DNS records found for this domain';
        } else if (error.message.includes('timeout')) {
            errorMessage = 'DNS lookup timeout - try increasing timeout value';
        }
        
        return {
            success: false,
            analyzer: 'dns',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            error: errorMessage
        };
    }
}

/**
 * Wraps a DNS promise with timeout protection
 * @param {Promise} promise - DNS resolution promise
 * @param {number} timeout - Timeout in milliseconds
 * @param {string} recordType - Type of DNS record (for logging)
 * @returns {Promise} Promise that rejects on timeout
 */
function resolveWithTimeout(promise, timeout, recordType) {
    return Promise.race([
        promise,
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error(`DNS ${recordType} lookup timeout`)), timeout)
        )
    ]);
}

/**
 * Extracts result from Promise.allSettled result
 * @param {Object} promiseResult - Result from Promise.allSettled
 * @returns {*} The resolved value or null if rejected
 */
function getResult(promiseResult) {
    if (promiseResult.status === 'fulfilled') {
        return promiseResult.value;
    }
    // Log rejection reason for debugging
    if (promiseResult.reason && !promiseResult.reason.message.includes('ENODATA')) {
        // Don't log ENODATA as it's expected for missing records
        console.log(`[DNS] Record not found: ${promiseResult.reason.message}`);
    }
    return null;
}

/**
 * Flattens TXT record arrays (DNS returns nested arrays)
 * @param {Array|null} txtRecords - TXT records from DNS
 * @returns {Array|null} Flattened array of TXT records
 */
function flattenTxtRecords(txtRecords) {
    if (!txtRecords || !Array.isArray(txtRecords)) {
        return null;
    }
    
    // TXT records come as array of arrays: [["v=spf1..."], ["google-site-verification=..."]]
    // Flatten and join each inner array
    return txtRecords.map(record => {
        if (Array.isArray(record)) {
            return record.join('');
        }
        return record;
    });
}

/**
 * Performs reverse DNS lookup for an IP address
 * @param {string} ip - IP address
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} Reverse DNS results
 */
export async function analyzeReverseDns(ip, options = {}) {
    console.log(`[DNS] Performing reverse DNS lookup for ${ip}`);
    
    try {
        const timeout = options.timeout || TIMEOUTS.dns;
        
        const hostnames = await Promise.race([
            dns.reverse(ip),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Reverse DNS timeout')), timeout)
            )
        ]);
        
        console.log(`[DNS] Reverse DNS found ${hostnames.length} hostname(s) for ${ip}`);
        
        return {
            success: true,
            analyzer: 'reverse-dns',
            target: ip,
            targetType: 'ip',
            timestamp: new Date().toISOString(),
            data: {
                hostnames,
                count: hostnames.length
            }
        };
        
    } catch (error) {
        console.error(`[DNS] Reverse DNS error for ${ip}:`, error.message);
        
        let errorMessage = error.message;
        if (error.code === 'ENOTFOUND') {
            errorMessage = 'No reverse DNS records found for this IP';
        }
        
        return {
            success: false,
            analyzer: 'reverse-dns',
            target: ip,
            targetType: 'ip',
            timestamp: new Date().toISOString(),
            error: errorMessage
        };
    }
}

import whoiser from 'whoiser';
import { TIMEOUTS } from '../config/constants.js';

/**
 * Performs WHOIS lookup for IP or domain
 * @param {string} target - IP or domain to lookup
 * @param {string} targetType - 'ip' or 'domain'
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} WHOIS data in standardized format
 */
export async function analyzeWhois(target, targetType, options = {}) {
    console.log(`[WHOIS] Analyzing ${targetType}: ${target}`);
    
    try {
        const timeout = options.timeout || TIMEOUTS.whois;
        const includeRaw = options.includeRawData || false;
        
        // Perform WHOIS lookup with timeout protection
        const whoisData = await Promise.race([
            whoiser(target, { timeout: TIMEOUTS.whois }),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('WHOIS timeout - server took too long to respond')), timeout)
            )
        ]);
        
        // Check if we got valid data
        if (!whoisData || Object.keys(whoisData).length === 0) {
            throw new Error('No WHOIS data returned - target may not exist or WHOIS server unavailable');
        }
        
        // Parse the WHOIS data based on target type
        const parsed = parseWhoisData(whoisData, targetType);
        
        console.log(`[WHOIS] Successfully retrieved data for ${target}`);
        
        return {
            success: true,
            analyzer: 'whois',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            data: parsed,
            ...(includeRaw && { rawData: whoisData })
        };
        
    } catch (error) {
        console.error(`[WHOIS] Error for ${target}:`, error.message);
        
        // Provide helpful error messages
        let errorMessage = error.message;
        if (error.message.includes('timeout')) {
            errorMessage = 'WHOIS lookup timeout - try increasing timeout value or retry later';
        } else if (error.message.includes('ENOTFOUND') || error.message.includes('not found')) {
            errorMessage = 'WHOIS server not found or target does not exist';
        } else if (error.message.includes('rate limit')) {
            errorMessage = 'WHOIS rate limit exceeded - please retry in a few minutes';
        }
        
        return {
            success: false,
            analyzer: 'whois',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            error: errorMessage
        };
    }
}

/**
 * Parses raw WHOIS data into structured format
 * @param {Object} rawData - Raw WHOIS response
 * @param {string} targetType - 'ip' or 'domain'
 * @returns {Object} Parsed WHOIS data
 */
function parseWhoisData(rawData, targetType) {
    // Get the first key (usually the WHOIS server or domain)
    const firstKey = Object.keys(rawData)[0];
    const data = rawData[firstKey];
    
    if (!data) {
        return { error: 'Unable to parse WHOIS data' };
    }
    
    if (targetType === 'domain') {
        return parseDomainWhois(data);
    } else {
        return parseIpWhois(data);
    }
}

/**
 * Parses WHOIS data for domains
 * @param {Object} data - WHOIS data object
 * @returns {Object} Structured domain WHOIS data
 */
function parseDomainWhois(data) {
    // Normalize field names (different WHOIS servers use different formats)
    const registrar = data['Registrar'] || data['registrar'] || data['Registrar Name'] || 'Unknown';
    
    const createdDate = data['Creation Date'] || data['created'] || data['Created Date'] || 
                       data['Registered on'] || data['Domain Registration Date'] || null;
    
    const expiryDate = data['Registry Expiry Date'] || data['Registrar Registration Expiration Date'] ||
                      data['expires'] || data['Expiry Date'] || data['Expiration Date'] || null;
    
    const updatedDate = data['Updated Date'] || data['changed'] || data['Last Updated'] || 
                       data['Modified Date'] || null;
    
    // Name servers can be array or single value
    let nameServers = data['Name Server'] || data['nserver'] || data['Nameservers'] || 
                     data['Name Servers'] || [];
    if (!Array.isArray(nameServers)) {
        nameServers = [nameServers];
    }
    nameServers = nameServers.filter(ns => ns); // Remove empty values
    
    // Status codes
    let status = data['Domain Status'] || data['status'] || data['Status'] || [];
    if (!Array.isArray(status)) {
        status = [status];
    }
    status = status.filter(s => s);
    
    // Registrant information (may not always be available due to privacy)
    const registrant = {
        name: data['Registrant Name'] || data['Registrant'] || null,
        organization: data['Registrant Organization'] || data['Registrant Org'] || null,
        email: data['Registrant Email'] || null,
        country: data['Registrant Country'] || null
    };
    
    return {
        domainName: data['Domain Name'] || data['domain'] || null,
        registrar,
        createdDate: normalizeDate(createdDate),
        expiryDate: normalizeDate(expiryDate),
        updatedDate: normalizeDate(updatedDate),
        nameServers,
        status,
        registrant: Object.values(registrant).some(v => v) ? registrant : null,
        dnssec: data['DNSSEC'] || data['dnssec'] || 'unsigned'
    };
}

/**
 * Parses WHOIS data for IP addresses
 * @param {Object} data - WHOIS data object
 * @returns {Object} Structured IP WHOIS data
 */
function parseIpWhois(data) {
    // IP WHOIS has different structure than domain WHOIS
    const netRange = data['NetRange'] || data['inetnum'] || data['route'] || null;
    const cidr = data['CIDR'] || data['route'] || null;
    
    const organization = data['Organization'] || data['OrgName'] || data['org-name'] || 
                        data['owner'] || data['descr'] || 'Unknown';
    
    const country = data['Country'] || data['country'] || null;
    
    const abuseContact = data['OrgAbuseEmail'] || data['abuse-mailbox'] || 
                        data['OrgTechEmail'] || null;
    
    const allocationDate = data['RegDate'] || data['created'] || data['last-modified'] || null;
    
    return {
        networkRange: netRange,
        cidr,
        organization,
        country,
        abuseContact,
        allocationDate: normalizeDate(allocationDate),
        netName: data['NetName'] || data['netname'] || null,
        netType: data['NetType'] || data['status'] || null,
        parentNetwork: data['Parent'] || null
    };
}

/**
 * Normalizes date strings to ISO format
 * @param {string|Date} date - Date to normalize
 * @returns {string|null} ISO date string or null
 */
function normalizeDate(date) {
    if (!date) return null;
    
    try {
        // If it's already a Date object
        if (date instanceof Date) {
            return date.toISOString();
        }
        
        // If it's a string, try to parse it
        if (typeof date === 'string') {
            const parsed = new Date(date);
            if (!isNaN(parsed.getTime())) {
                return parsed.toISOString();
            }
        }
        
        return date; // Return as-is if we can't parse
    } catch (error) {
        return date; // Return original if parsing fails
    }
}

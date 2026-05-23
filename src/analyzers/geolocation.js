import axios from 'axios';
import dns from 'dns/promises';
import { API_ENDPOINTS, TIMEOUTS } from '../config/constants.js';

/**
 * Gets geolocation data for an IP address
 * @param {string} target - IP or domain
 * @param {string} targetType - 'ip' or 'domain'
 * @param {number} timeout - Timeout in seconds
 * @returns {Promise<Object>} Geolocation data
 */
export async function analyzeGeolocation(target, targetType, timeout) {
    console.log(`Running geolocation lookup for ${target}`);
    
    let ipAddress = target;
    
    // If target is a domain, resolve to IP first
    if (targetType === 'domain') {
        try {
            const addresses = await dns.resolve4(target);
            ipAddress = addresses[0];
            console.log(`Resolved ${target} to ${ipAddress}`);
        } catch (error) {
            throw new Error(`Failed to resolve domain to IP: ${error.message}`);
        }
    }
    
    try {
        const timeoutMs = (timeout || 30) * 1000;
        
        // Use ip-api.com (free, no API key required)
        const response = await axios.get(`${API_ENDPOINTS.geoip}/${ipAddress}`, {
            timeout: TIMEOUTS.api,
            params: {
                fields: 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'
            }
        });
        
        if (response.data.status === 'fail') {
            throw new Error(response.data.message || 'Geolocation lookup failed');
        }
        
        console.log(`Geolocation lookup completed for ${ipAddress}`);

        return {
            success: true,
            analyzer: 'geolocation',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            data: {
                ip: response.data.query,
                country: response.data.country,
                countryCode: response.data.countryCode,
                region: response.data.regionName,
                city: response.data.city,
                zipCode: response.data.zip,
                latitude: response.data.lat,
                longitude: response.data.lon,
                timezone: response.data.timezone,
                isp: response.data.isp,
                organization: response.data.org,
                asn: response.data.as
            },
            rawData: response.data
        };

    } catch (error) {
        console.error(`Geolocation lookup failed:`, error.message);
        return {
            success: false,
            analyzer: 'geolocation',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            error: `Geolocation lookup failed: ${error.message}`
        };
    }
}

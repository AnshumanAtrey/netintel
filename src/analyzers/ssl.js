import https from 'https';
import tls from 'tls';
import { TIMEOUTS } from '../config/constants.js';

/**
 * Analyzes SSL/TLS certificate for a domain with expiry monitoring
 * @param {string} target - Domain name
 * @param {number} timeout - Timeout in milliseconds
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} SSL certificate data in standardized format
 */
export async function analyzeSSL(target, timeout = TIMEOUTS.api, options = {}) {
    console.log(`[SSL] Analyzing certificate for ${target}`);
    
    try {
        const certData = await getCertificateData(target, timeout);
        
        const now = new Date();
        const validFrom = new Date(certData.valid_from);
        const validTo = new Date(certData.valid_to);
        const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const hoursUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60));
        
        // Determine certificate status
        const expired = now > validTo;
        const notYetValid = now < validFrom;
        const expiringSoon = daysUntilExpiry <= 30 && daysUntilExpiry > 0;
        const expiringCritical = daysUntilExpiry <= 7 && daysUntilExpiry > 0;
        
        // Check if self-signed
        const selfSigned = certData.issuer.CN === certData.subject.CN;
        
        // Extract subject alternative names
        const subjectAltNames = certData.subjectaltname 
            ? certData.subjectaltname.split(', ').map(san => san.replace('DNS:', ''))
            : [];
        
        // Determine certificate authority
        const issuerOrg = certData.issuer.O || certData.issuer.CN || 'Unknown';
        
        // Build alerts array
        const alerts = [];
        if (expired) {
            alerts.push({
                severity: 'critical',
                type: 'expired',
                message: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`
            });
        } else if (notYetValid) {
            alerts.push({
                severity: 'warning',
                type: 'not_yet_valid',
                message: 'Certificate is not yet valid'
            });
        } else if (expiringCritical) {
            alerts.push({
                severity: 'critical',
                type: 'expiring_soon',
                message: `Certificate expires in ${daysUntilExpiry} days (${hoursUntilExpiry} hours)`
            });
        } else if (expiringSoon) {
            alerts.push({
                severity: 'warning',
                type: 'expiring_soon',
                message: `Certificate expires in ${daysUntilExpiry} days`
            });
        }
        
        if (selfSigned) {
            alerts.push({
                severity: 'warning',
                type: 'self_signed',
                message: 'Certificate is self-signed'
            });
        }
        
        // Determine overall status
        let status = 'valid';
        if (expired) status = 'expired';
        else if (notYetValid) status = 'not_yet_valid';
        else if (expiringCritical) status = 'expiring_critical';
        else if (expiringSoon) status = 'expiring_soon';
        
        const result = {
            success: true,
            analyzer: 'ssl',
            target,
            targetType: 'domain',
            timestamp: new Date().toISOString(),
            data: {
                status,
                subject: {
                    commonName: certData.subject.CN,
                    organization: certData.subject.O || null,
                    organizationalUnit: certData.subject.OU || null,
                    locality: certData.subject.L || null,
                    state: certData.subject.ST || null,
                    country: certData.subject.C || null
                },
                issuer: {
                    commonName: certData.issuer.CN,
                    organization: issuerOrg,
                    country: certData.issuer.C || null
                },
                validity: {
                    validFrom: certData.valid_from,
                    validTo: certData.valid_to,
                    daysUntilExpiry,
                    hoursUntilExpiry,
                    expired,
                    notYetValid,
                    expiringSoon,
                    expiringCritical
                },
                security: {
                    selfSigned,
                    serialNumber: certData.serialNumber,
                    fingerprint: certData.fingerprint,
                    fingerprint256: certData.fingerprint256
                },
                domains: {
                    primary: certData.subject.CN,
                    alternativeNames: subjectAltNames,
                    totalDomains: subjectAltNames.length
                },
                alerts
            }
        };
        
        // Add raw data if requested
        if (options.includeRawData) {
            result.rawData = certData;
        }
        
        console.log(`[SSL] Certificate analysis complete for ${target}`);
        console.log(`[SSL] Status: ${status}, Expires in ${daysUntilExpiry} days, Alerts: ${alerts.length}`);
        
        return result;
        
    } catch (error) {
        console.error(`[SSL] Error analyzing ${target}:`, error.message);
        
        let errorMessage = error.message;
        if (error.code === 'ENOTFOUND') {
            errorMessage = 'Domain not found - unable to resolve hostname';
        } else if (error.code === 'ECONNREFUSED') {
            errorMessage = 'Connection refused - no SSL/TLS service on port 443';
        } else if (error.code === 'ETIMEDOUT' || error.message.includes('timeout')) {
            errorMessage = 'SSL connection timeout - server not responding';
        } else if (error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
            errorMessage = 'Self-signed certificate detected';
        }
        
        return {
            success: false,
            analyzer: 'ssl',
            target,
            targetType: 'domain',
            timestamp: new Date().toISOString(),
            error: errorMessage
        };
    }
}

/**
 * Retrieves SSL certificate data from a domain
 * @param {string} host - Domain name
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<Object>} Raw certificate data
 */
function getCertificateData(host, timeout) {
    return new Promise((resolve, reject) => {
        const options = {
            host,
            port: 443,
            method: 'GET',
            rejectUnauthorized: false, // Allow self-signed and expired certs
            timeout
        };
        
        const req = https.request(options, (res) => {
            const cert = res.socket.getPeerCertificate(true);
            
            if (!cert || Object.keys(cert).length === 0) {
                reject(new Error('No SSL certificate found'));
                return;
            }
            
            resolve(cert);
            req.destroy();
        });
        
        req.on('error', (error) => {
            reject(error);
        });
        
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('SSL connection timeout'));
        });
        
        req.end();
    });
}

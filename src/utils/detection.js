import validator from 'validator';

/**
 * Auto-detects whether the target is an IP address or domain name
 * @param {string} target - The target to analyze
 * @returns {string} 'ip' or 'domain'
 * @throws {Error} If target cannot be detected
 */
export function detectTargetType(target) {
    const trimmedTarget = target.trim();
    
    console.log(`[DETECTION] Auto-detecting type for: ${trimmedTarget}`);
    
    // Check if it's a valid IP address (IPv4 or IPv6)
    if (validator.isIP(trimmedTarget)) {
        console.log(`[DETECTION] Detected as IP address`);
        return 'ip';
    }
    
    // Check if it's a valid fully qualified domain name
    if (validator.isFQDN(trimmedTarget)) {
        console.log(`[DETECTION] Detected as domain name`);
        return 'domain';
    }
    
    // If we can't detect, throw error
    throw new Error(`Cannot detect type for: ${trimmedTarget}. Must be valid IP or domain.`);
}

/**
 * Normalizes the target by removing protocols and trailing slashes
 * @param {string} target - The target to normalize
 * @returns {string} Normalized target
 */
export function normalizeTarget(target) {
    let normalized = target.trim();
    
    console.log(`[DETECTION] Normalizing target: ${normalized}`);
    
    // Remove protocol if present
    normalized = normalized.replace(/^https?:\/\//, '');
    normalized = normalized.replace(/^ftp:\/\//, '');
    
    // Remove trailing slash
    normalized = normalized.replace(/\/$/, '');
    
    // Remove path if present (do this before port removal)
    const pathIndex = normalized.indexOf('/');
    if (pathIndex > 0) {
        normalized = normalized.substring(0, pathIndex);
    }
    
    // Remove port if present (but be careful with IPv6)
    // IPv6 addresses have colons, so only remove port if it's at the end and numeric
    // For IPv6, ports would be like [2001:db8::1]:8080
    // Don't try to remove ports from IPv6 addresses (they have multiple colons)
    const colonCount = (normalized.match(/:/g) || []).length;
    if (colonCount <= 1) {
        // Only one colon, could be a port (not IPv6)
        const portIndex = normalized.lastIndexOf(':');
        if (portIndex > 0) {
            const afterColon = normalized.substring(portIndex + 1);
            // Only remove if what follows the colon is purely numeric (a port)
            if (/^\d+$/.test(afterColon)) {
                normalized = normalized.substring(0, portIndex);
            }
        }
    }
    
    // Remove IPv6 brackets if present
    if (normalized.startsWith('[') && normalized.endsWith(']')) {
        normalized = normalized.substring(1, normalized.length - 1);
    }
    
    console.log(`[DETECTION] Normalized to: ${normalized}`);
    
    return normalized;
}

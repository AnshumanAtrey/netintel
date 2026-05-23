import validator from 'validator';
import { log } from 'apify';

/**
 * Validates the input configuration from Apify
 * @param {Object} input - The input object from Actor.getInput()
 * @throws {Error} If validation fails
 */
export async function validateInput(input) {
    log.debug('[VALIDATION] Starting input validation...');
    
    if (!input) {
        throw new Error('Input is required');
    }
    
    // Check if batch mode or single target mode
    if (!input.batchMode) {
        // Single target mode - validate target field
        if (!input.target || typeof input.target !== 'string' || input.target.trim() === '') {
            throw new Error('Target is required (IP address or domain name)');
        }
        
        let target = input.target.trim();
        
        // Normalize target first (remove protocols, paths, etc.)
        // Remove protocol if present
        target = target.replace(/^https?:\/\//, '');
        target = target.replace(/^ftp:\/\//, '');
        
        // Remove trailing slash
        target = target.replace(/\/$/, '');
        
        // Remove path if present
        const pathIndex = target.indexOf('/');
        if (pathIndex > 0) {
            target = target.substring(0, pathIndex);
        }
        
        // Remove IPv6 brackets if present
        if (target.startsWith('[') && target.endsWith(']')) {
            target = target.substring(1, target.length - 1);
        }
        
        // Validate target format (must be valid IP or domain)
        const isValidIP = validator.isIP(target);
        const isValidDomain = validator.isFQDN(target);
        
        if (!isValidIP && !isValidDomain) {
            throw new Error(`Invalid target: "${input.target}". Must be a valid IP address or fully qualified domain name.`);
        }
        
        log.debug(`[VALIDATION] Target "${target}" is valid (${isValidIP ? 'IP' : 'domain'})`);
    } else {
        // Batch mode - validate batchTargets array
        if (!input.batchTargets || !Array.isArray(input.batchTargets)) {
            throw new Error('Batch mode requires batchTargets array');
        }
        
        if (input.batchTargets.length === 0) {
            throw new Error('batchTargets array cannot be empty');
        }
        
        if (input.batchTargets.length > 100) {
            throw new Error('Maximum 100 targets allowed in batch mode');
        }
        
        // Validate each batch target
        for (let i = 0; i < input.batchTargets.length; i++) {
            const batchTarget = input.batchTargets[i];
            
            if (!batchTarget || typeof batchTarget !== 'string') {
                throw new Error(`Invalid batch target at index ${i}: must be a string`);
            }
            
            const trimmedTarget = batchTarget.trim();
            const isValidBatchIP = validator.isIP(trimmedTarget);
            const isValidBatchDomain = validator.isFQDN(trimmedTarget);
            
            if (!isValidBatchIP && !isValidBatchDomain) {
                throw new Error(`Invalid batch target at index ${i}: "${batchTarget}". Must be a valid IP or domain.`);
            }
        }
        
        log.debug(`[VALIDATION] All ${input.batchTargets.length} batch targets are valid`);
    }
    
    // Validate targetType
    if (input.targetType && !['auto', 'ip', 'domain'].includes(input.targetType)) {
        throw new Error('targetType must be "auto", "ip", or "domain"');
    }
    
    // Validate analysisType
    if (!input.analysisType || !Array.isArray(input.analysisType) || input.analysisType.length === 0) {
        throw new Error('At least one analysis type must be selected');
    }
    
    const validAnalysisTypes = ['whois', 'dns', 'geolocation', 'reputation', 'ports', 'ssl'];
    const invalidTypes = input.analysisType.filter(type => !validAnalysisTypes.includes(type));
    
    if (invalidTypes.length > 0) {
        throw new Error(`Invalid analysis type(s): ${invalidTypes.join(', ')}. Valid types: ${validAnalysisTypes.join(', ')}`);
    }
    
    log.debug(`[VALIDATION] Analysis types: ${input.analysisType.join(', ')}`);
    
    // Validate timeout
    if (input.timeout !== undefined) {
        if (typeof input.timeout !== 'number' || input.timeout < 5 || input.timeout > 300) {
            throw new Error('Timeout must be a number between 5 and 300 seconds');
        }
    }
    
    // Validate concurrency (for batch mode)
    if (input.concurrency !== undefined) {
        if (typeof input.concurrency !== 'number' || input.concurrency < 1 || input.concurrency > 20) {
            throw new Error('Concurrency must be a number between 1 and 20');
        }
    }
    
    // Validate includeRawData
    if (input.includeRawData !== undefined && typeof input.includeRawData !== 'boolean') {
        throw new Error('includeRawData must be a boolean');
    }
    
    log.debug('[VALIDATION] Input validation successful ✓');
}

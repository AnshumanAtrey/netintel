/**
 * Export utilities for converting analysis results to various formats
 * Supports CSV, JSON, and JSONL (JSON Lines) formats
 */

/**
 * Exports analysis results to specified format
 * @param {Array|Object} results - Analysis results (single or array)
 * @param {string} format - Export format: 'csv', 'json', 'jsonl'
 * @param {Object} options - Export options
 * @returns {string} Formatted export data
 */
export function exportResults(results, format = 'json', options = {}) {
    console.log(`[EXPORT] Exporting results in ${format.toUpperCase()} format`);
    
    // Ensure results is an array
    const resultsArray = Array.isArray(results) ? results : [results];
    
    if (resultsArray.length === 0) {
        console.warn('[EXPORT] No results to export');
        return format === 'json' ? '[]' : '';
    }
    
    switch (format.toLowerCase()) {
        case 'csv':
            return exportToCSV(resultsArray, options);
        case 'json':
            return exportToJSON(resultsArray, options);
        case 'jsonl':
        case 'ndjson':
            return exportToJSONL(resultsArray, options);
        default:
            throw new Error(`Unsupported export format: ${format}. Use 'csv', 'json', or 'jsonl'`);
    }
}

/**
 * Exports results to JSON format
 * @param {Array} results - Analysis results
 * @param {Object} options - Export options
 * @returns {string} JSON string
 */
function exportToJSON(results, options = {}) {
    const { pretty = true, includeMetadata = true } = options;
    
    const exportData = {
        exportedAt: new Date().toISOString(),
        totalResults: results.length,
        format: 'json',
        results: results
    };
    
    const data = includeMetadata ? exportData : results;
    
    return pretty 
        ? JSON.stringify(data, null, 2)
        : JSON.stringify(data);
}

/**
 * Exports results to JSON Lines format (one JSON object per line)
 * @param {Array} results - Analysis results
 * @param {Object} options - Export options
 * @returns {string} JSONL string
 */
function exportToJSONL(results, options = {}) {
    return results.map(result => JSON.stringify(result)).join('\n');
}

/**
 * Exports results to CSV format
 * @param {Array} results - Analysis results
 * @param {Object} options - Export options
 * @returns {string} CSV string
 */
function exportToCSV(results, options = {}) {
    const { includeHeaders = true, delimiter = ',' } = options;
    
    // Flatten results for CSV
    const flatResults = results.map(result => flattenResult(result));
    
    if (flatResults.length === 0) {
        return '';
    }
    
    // Get all unique keys from all results
    const allKeys = new Set();
    flatResults.forEach(result => {
        Object.keys(result).forEach(key => allKeys.add(key));
    });
    
    const headers = Array.from(allKeys);
    const rows = [];
    
    // Add headers
    if (includeHeaders) {
        rows.push(headers.map(h => escapeCSVValue(h)).join(delimiter));
    }
    
    // Add data rows
    flatResults.forEach(result => {
        const row = headers.map(header => {
            const value = result[header];
            return escapeCSVValue(value);
        });
        rows.push(row.join(delimiter));
    });
    
    return rows.join('\n');
}

/**
 * Flattens nested result object for CSV export
 * @param {Object} result - Analysis result
 * @returns {Object} Flattened result
 */
function flattenResult(result) {
    const flat = {
        target: result.target || '',
        targetType: result.targetType || '',
        timestamp: result.timestamp || '',
        confidenceScore: result.confidenceScore || '',
        confidenceLevel: result.confidenceLevel || ''
    };
    
    // Flatten each analyzer's results
    if (result.analyses) {
        Object.entries(result.analyses).forEach(([analyzer, data]) => {
            if (!data || !data.success) {
                flat[`${analyzer}_status`] = 'failed';
                flat[`${analyzer}_error`] = data?.error || 'Unknown error';
                return;
            }
            
            flat[`${analyzer}_status`] = 'success';
            
            // Extract key data based on analyzer type
            switch (analyzer) {
                case 'whois':
                    flat.whois_organization = data.data?.organization || '';
                    flat.whois_registrar = data.data?.registrar || '';
                    flat.whois_createdDate = data.data?.createdDate || '';
                    flat.whois_expiryDate = data.data?.expiryDate || '';
                    break;
                    
                case 'dns':
                    flat.dns_a_records = data.data?.a ? data.data.a.join(';') : '';
                    flat.dns_mx_records = data.data?.mx ? data.data.mx.map(mx => mx.exchange).join(';') : '';
                    flat.dns_ns_records = data.data?.ns ? data.data.ns.join(';') : '';
                    break;
                    
                case 'reverseDns':
                    flat.reverseDns_hostnames = data.data?.hostnames ? data.data.hostnames.join(';') : '';
                    flat.reverseDns_count = data.data?.count || 0;
                    break;
                    
                case 'ssl':
                    flat.ssl_status = data.data?.status || '';
                    flat.ssl_issuer = data.data?.issuer?.organization || '';
                    flat.ssl_validTo = data.data?.validity?.validTo || '';
                    flat.ssl_daysUntilExpiry = data.data?.validity?.daysUntilExpiry || '';
                    flat.ssl_selfSigned = data.data?.security?.selfSigned || false;
                    flat.ssl_domains = data.data?.domains?.totalDomains || 0;
                    flat.ssl_alerts = data.data?.alerts?.length || 0;
                    break;
                    
                case 'geolocation':
                    flat.geo_country = data.data?.country || '';
                    flat.geo_city = data.data?.city || '';
                    flat.geo_isp = data.data?.isp || '';
                    flat.geo_asn = data.data?.as || '';
                    flat.geo_latitude = data.data?.lat || '';
                    flat.geo_longitude = data.data?.lon || '';
                    break;
                    
                case 'reputation':
                    flat.reputation_threatScore = data.data?.threatScore || 0;
                    flat.reputation_threatLevel = data.data?.threatLevel || '';
                    flat.reputation_blacklisted = data.data?.blacklisted || false;
                    break;
                    
                case 'emailReputation':
                    flat.email_score = data.data?.score || 0;
                    flat.email_reputationLevel = data.data?.reputationLevel || '';
                    flat.email_canSendEmail = data.data?.summary?.canSendEmail || false;
                    flat.email_hasAuthentication = data.data?.summary?.hasAuthentication || false;
                    flat.email_isBlacklisted = data.data?.summary?.isBlacklisted || false;
                    flat.email_mxCount = data.data?.mx?.count || 0;
                    flat.email_hasSPF = data.data?.spf?.valid || false;
                    flat.email_hasDMARC = data.data?.dmarc?.valid || false;
                    flat.email_issueCount = data.data?.issues?.length || 0;
                    break;
                    
                case 'ports':
                    const openPorts = data.data?.openPorts || [];
                    flat.ports_open = openPorts.map(p => p.port).join(';');
                    flat.ports_services = openPorts.map(p => p.service).join(';');
                    flat.ports_count = openPorts.length;
                    break;
            }
        });
    }
    
    // Add correlation data
    if (result.correlation) {
        flat.threat_indicators = result.correlation.threatIndicators?.length || 0;
        flat.anomalies = result.correlation.anomalies?.length || 0;
    }
    
    return flat;
}

/**
 * Escapes a value for CSV format
 * @param {*} value - Value to escape
 * @returns {string} Escaped value
 */
function escapeCSVValue(value) {
    if (value === null || value === undefined) {
        return '';
    }
    
    // Convert to string
    let str = String(value);
    
    // If contains comma, quote, or newline, wrap in quotes and escape quotes
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        str = '"' + str.replace(/"/g, '""') + '"';
    }
    
    return str;
}

/**
 * Generates a filename for export
 * @param {string} format - Export format
 * @param {string} prefix - Filename prefix
 * @returns {string} Filename
 */
export function generateExportFilename(format, prefix = 'netintel-export') {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const extension = format === 'jsonl' ? 'jsonl' : format;
    return `${prefix}-${timestamp}.${extension}`;
}

/**
 * Exports results and returns as a downloadable object
 * @param {Array|Object} results - Analysis results
 * @param {string} format - Export format
 * @param {Object} options - Export options
 * @returns {Object} Export object with data and metadata
 */
export function createExport(results, format = 'json', options = {}) {
    const data = exportResults(results, format, options);
    const filename = generateExportFilename(format, options.prefix);
    
    return {
        success: true,
        format,
        filename,
        data,
        size: Buffer.byteLength(data, 'utf8'),
        timestamp: new Date().toISOString(),
        recordCount: Array.isArray(results) ? results.length : 1
    };
}

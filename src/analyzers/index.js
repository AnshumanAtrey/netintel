import { log } from 'apify';
import { analyzeWhois } from './whois.js';
import { analyzeDns } from './dns.js';
import { analyzeGeolocation } from './geolocation.js';
import { analyzeReputation } from './reputation.js';
import { analyzePorts } from './ports.js';
import { analyzeSSL } from './ssl.js';
import { correlateResults } from '../utils/correlation.js';
import { calculateConfidenceScore, getConfidenceLevel } from '../utils/confidence.js';
import { detectTargetType, normalizeTarget } from '../utils/detection.js';

/**
 * Orchestrates all requested analyses and combines results
 * @param {Object} input - The input configuration from Apify
 * @returns {Promise<Object>} Combined analysis results
 */
export async function executeAnalysis(input) {
    log.debug('[ORCHESTRATOR] Starting analysis execution...');
    
    // Normalize and detect target type
    const target = normalizeTarget(input.target);
    const targetType = input.targetType === 'auto' 
        ? detectTargetType(target) 
        : input.targetType;
    
    const analysisTypes = input.analysisType || ['whois', 'dns'];
    const options = {
        timeout: (input.timeout || 30) * 1000, // Convert to milliseconds
        includeRawData: input.includeRawData || false
    };
    
    log.debug(`[ORCHESTRATOR] Target: ${target} (${targetType})`);
    log.debug(`[ORCHESTRATOR] Analysis types: ${analysisTypes.join(', ')}`);
    log.debug(`[ORCHESTRATOR] Timeout: ${options.timeout}ms`);
    
    const results = {
        target,
        targetType,
        timestamp: new Date().toISOString(),
        requestedAnalyses: analysisTypes,
        analyses: {}
    };
    
    // Build array of analysis promises
    const analysisPromises = [];
    
    // WHOIS Analysis
    if (analysisTypes.includes('whois')) {
        log.debug('[ORCHESTRATOR] Queuing WHOIS analysis...');
        analysisPromises.push(
            analyzeWhois(target, targetType, options)
                .then(data => ({ type: 'whois', data }))
                .catch(error => ({ 
                    type: 'whois', 
                    data: {
                        success: false,
                        analyzer: 'whois',
                        target,
                        targetType,
                        timestamp: new Date().toISOString(),
                        error: error.message
                    }
                }))
        );
    }
    
    // DNS Analysis
    if (analysisTypes.includes('dns')) {
        log.debug('[ORCHESTRATOR] Queuing DNS analysis...');
        analysisPromises.push(
            analyzeDns(target, targetType, options)
                .then(data => ({ type: 'dns', data }))
                .catch(error => ({ 
                    type: 'dns', 
                    data: {
                        success: false,
                        analyzer: 'dns',
                        target,
                        targetType,
                        timestamp: new Date().toISOString(),
                        error: error.message
                    }
                }))
        );
    }
    
    // Geolocation Analysis
    if (analysisTypes.includes('geolocation')) {
        log.debug('[ORCHESTRATOR] Queuing geolocation analysis...');
        analysisPromises.push(
            analyzeGeolocation(target, targetType, options.timeout)
                .then(data => ({ type: 'geolocation', data }))
                .catch(error => ({ 
                    type: 'geolocation', 
                    data: {
                        success: false,
                        analyzer: 'geolocation',
                        target,
                        targetType,
                        timestamp: new Date().toISOString(),
                        error: error.message
                    }
                }))
        );
    }
    
    // Reputation Analysis
    if (analysisTypes.includes('reputation')) {
        log.debug('[ORCHESTRATOR] Queuing reputation analysis...');
        analysisPromises.push(
            analyzeReputation(target, targetType, options.timeout)
                .then(data => ({ type: 'reputation', data }))
                .catch(error => ({ 
                    type: 'reputation', 
                    data: {
                        success: false,
                        analyzer: 'reputation',
                        target,
                        targetType,
                        timestamp: new Date().toISOString(),
                        error: error.message
                    }
                }))
        );
    }
    
    // Port Scan Analysis
    if (analysisTypes.includes('ports')) {
        log.debug('[ORCHESTRATOR] Queuing port scan analysis...');
        analysisPromises.push(
            analyzePorts(target, targetType, options.timeout)
                .then(data => ({ type: 'ports', data }))
                .catch(error => ({ 
                    type: 'ports', 
                    data: {
                        success: false,
                        analyzer: 'ports',
                        target,
                        targetType,
                        timestamp: new Date().toISOString(),
                        error: error.message
                    }
                }))
        );
    }
    
    // SSL Analysis (only for domains)
    if (analysisTypes.includes('ssl')) {
        if (targetType === 'domain') {
            log.debug('[ORCHESTRATOR] Queuing SSL analysis...');
            analysisPromises.push(
                analyzeSSL(target, options.timeout)
                    .then(data => ({ type: 'ssl', data }))
                    .catch(error => ({ 
                        type: 'ssl', 
                        data: {
                            success: false,
                            analyzer: 'ssl',
                            target,
                            targetType,
                            timestamp: new Date().toISOString(),
                            error: error.message
                        }
                    }))
            );
        } else {
            log.debug('[ORCHESTRATOR] Skipping SSL analysis (not applicable for IP addresses)');
        }
    }
    
    // Execute all analyses in parallel
    log.debug(`[ORCHESTRATOR] Executing ${analysisPromises.length} analyses in parallel...`);
    const analysisResults = await Promise.all(analysisPromises);
    
    // Combine results
    let successCount = 0;
    let failureCount = 0;
    
    for (const result of analysisResults) {
        results.analyses[result.type] = result.data;
        
        if (result.data.success) {
            successCount++;
            log.debug(`[ORCHESTRATOR] ✓ ${result.type} analysis completed successfully`);
        } else {
            failureCount++;
            log.warning(`[ORCHESTRATOR] ✗ ${result.type} analysis failed: ${result.data.error}`);
        }
    }
    
    log.debug(`[ORCHESTRATOR] Analysis complete: ${successCount} succeeded, ${failureCount} failed`);
    
    // Calculate confidence score based on successful analyses
    results.confidenceScore = calculateConfidenceScore(results.analyses, analysisTypes);
    results.confidenceLevel = getConfidenceLevel(results.confidenceScore);
    
    log.debug(`[ORCHESTRATOR] Confidence score: ${results.confidenceScore}% (${results.confidenceLevel})`);
    
    // Correlate results for insights
    try {
        results.correlation = correlateResults({
            ...results.analyses,
            target,
            targetType
        });
        log.debug(`[ORCHESTRATOR] Correlation complete: ${results.correlation.threatIndicators.length} threat indicators found`);
    } catch (error) {
        log.warning(`[ORCHESTRATOR] Correlation failed: ${error.message}`);
        results.correlation = {
            threatIndicators: [],
            anomalies: [],
            recommendations: [],
            error: error.message
        };
    }
    
    // Remove raw data if not requested
    if (!options.includeRawData) {
        for (const analysisKey in results.analyses) {
            if (results.analyses[analysisKey].rawData) {
                delete results.analyses[analysisKey].rawData;
            }
        }
    }
    
    log.debug('[ORCHESTRATOR] Analysis execution complete ✓');
    
    return results;
}

import { CONFIDENCE_WEIGHTS } from '../config/constants.js';

/**
 * Calculates a confidence score based on successful analysis results
 * @param {Object} results - Combined results from all analyzers
 * @param {Array} requestedAnalyses - List of requested analysis types
 * @returns {number} Confidence score (0-100)
 */
export function calculateConfidenceScore(results, requestedAnalyses) {
    let totalWeight = 0;
    let achievedWeight = 0;
    
    // Calculate weights for requested analyses
    for (const analysisType of requestedAnalyses) {
        const weight = CONFIDENCE_WEIGHTS[analysisType] || 0.1;
        totalWeight += weight;
        
        // Check if this analysis was successful
        if (results[analysisType] && !results[analysisType].error) {
            achievedWeight += weight;
        }
    }
    
    // Calculate percentage
    const confidenceScore = totalWeight > 0 
        ? Math.round((achievedWeight / totalWeight) * 100) 
        : 0;
    
    return confidenceScore;
}

/**
 * Determines confidence level based on score
 * @param {number} score - Confidence score (0-100)
 * @returns {string} Confidence level
 */
export function getConfidenceLevel(score) {
    if (score >= 90) return 'very_high';
    if (score >= 75) return 'high';
    if (score >= 50) return 'medium';
    if (score >= 25) return 'low';
    return 'very_low';
}

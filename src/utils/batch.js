import pLimit from 'p-limit';
import { detectTargetType, normalizeTarget } from './detection.js';
import { executeAnalysis } from '../analyzers/index.js';

/**
 * Executes analysis on multiple targets in parallel with concurrency control
 * @param {Object} input - The input configuration
 * @returns {Promise<Array>} Array of analysis results
 */
export async function executeBatchAnalysis(input) {
    const { batchTargets, concurrency = 5, targetType = 'auto' } = input;
    
    console.log(`Starting batch analysis with concurrency: ${concurrency}`);
    
    // Create concurrency limiter
    const limit = pLimit(concurrency);
    
    // Create analysis tasks
    const tasks = batchTargets.map((target) => {
        return limit(async () => {
            try {
                const normalizedTarget = normalizeTarget(target);
                
                // Detect target type for this specific target
                const detectedType = targetType === 'auto' 
                    ? detectTargetType(normalizedTarget) 
                    : targetType;
                
                // Create input for this specific target
                const targetInput = {
                    ...input,
                    target: normalizedTarget,
                    targetType: detectedType,
                    batchMode: false // Disable batch mode for individual analysis
                };
                
                console.log(`Analyzing target: ${normalizedTarget}`);
                const result = await executeAnalysis(targetInput);
                
                return result;
            } catch (error) {
                console.error(`Failed to analyze target "${target}":`, error.message);
                
                // Return error result instead of throwing
                return {
                    target,
                    error: true,
                    errorMessage: error.message,
                    timestamp: new Date().toISOString()
                };
            }
        });
    });
    
    // Execute all tasks with concurrency control
    const results = await Promise.all(tasks);
    
    console.log(`Batch analysis completed: ${results.length} results`);
    
    return results;
}

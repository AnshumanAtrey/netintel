import { Actor, log } from 'apify';
import { validateInput } from './utils/validation.js';
import { detectTargetType } from './utils/detection.js';
import { executeAnalysis } from './analyzers/index.js';
import { executeBatchAnalysis } from './utils/batch.js';
import { createExport } from './utils/export.js';

await Actor.init();

const startTime = Date.now();

try {
    log.info('╔══════════════════════════════════════════════════════════════════╗');
    log.info('║                  NetIntel Actor Started                          ║');
    log.info('╚══════════════════════════════════════════════════════════════════╝');
    log.info(`Run ID:      ${process.env.APIFY_ACTOR_RUN_ID || 'LOCAL'}`);
    log.info(`Build:       ${process.env.APIFY_ACTOR_BUILD || 'unknown'}`);
    log.info(`Started at:  ${new Date().toISOString()}`);

    const input = await Actor.getInput();

    if (!input) {
        throw new Error('No input provided. Please provide input in storage/key_value_stores/default/INPUT.json');
    }

    log.info('═══ Input Received ═══');
    log.debug(JSON.stringify(input, null, 2));

    log.info('═══ Input Validation ═══');
    await validateInput(input);
    log.info('✓ Input validation passed');

    if (input.batchMode && input.batchTargets && input.batchTargets.length > 0) {
        log.info('═══ Batch Mode Analysis ═══');
        log.info(`Analyzing ${input.batchTargets.length} targets with concurrency ${input.concurrency || 5}`);
        log.info(`Targets: ${input.batchTargets.join(', ')}`);

        const batchStartTime = Date.now();
        const batchResults = await executeBatchAnalysis(input);
        const duration = ((Date.now() - batchStartTime) / 1000).toFixed(2);

        for (const result of batchResults) {
            await Actor.pushData({
                ...result,
                metadata: {
                    actorVersion: process.env.APIFY_ACTOR_BUILD || 'unknown',
                    runId: process.env.APIFY_ACTOR_RUN_ID,
                    executionTime: `${((Date.now() - batchStartTime) / 1000).toFixed(2)}s`,
                    dataFreshness: new Date().toISOString()
                }
            });
            try { await Actor.charge({ eventName: 'analysis-completed' }); } catch (e) { log.debug(`charge skipped: ${e.message}`); }
        }

        if (input.exportFormat && input.exportFormat !== 'none') {
            log.info('═══ Exporting Results ═══');
            log.info(`Format: ${input.exportFormat.toUpperCase()}`);

            const exportResult = createExport(batchResults, input.exportFormat, {
                pretty: input.exportPretty !== false,
                includeMetadata: input.exportIncludeMetadata !== false,
                prefix: 'netintel-batch'
            });

            await Actor.setValue(exportResult.filename, exportResult.data, {
                contentType: input.exportFormat === 'csv' ? 'text/csv' : 'application/json'
            });

            log.info(`✓ Export saved: ${exportResult.filename} (${(exportResult.size / 1024).toFixed(2)} KB, ${exportResult.recordCount} records)`);
        }

        log.info('═══ Batch Analysis Complete ═══');
        log.info(`Total targets:     ${batchResults.length}`);
        log.info(`Successful:        ${batchResults.filter(r => !r.error).length}`);
        log.info(`Failed:            ${batchResults.filter(r => r.error).length}`);
        log.info(`Duration:          ${duration}s`);

    } else {
        log.info('═══ Single Target Analysis ═══');
        log.info(`Target: ${input.target}`);
        log.info(`Analysis types: ${input.analysisType.join(', ')}`);
        log.info(`Timeout: ${input.timeout || 30}s`);

        if (input.targetType === 'auto') {
            input.targetType = detectTargetType(input.target);
            log.info(`✓ Auto-detected target type: ${input.targetType}`);
        }

        const analysisStartTime = Date.now();
        const result = await executeAnalysis(input);
        const duration = ((Date.now() - analysisStartTime) / 1000).toFixed(2);

        await Actor.pushData({
            ...result,
            metadata: {
                actorVersion: process.env.APIFY_ACTOR_BUILD || 'unknown',
                runId: process.env.APIFY_ACTOR_RUN_ID,
                executionTime: `${duration}s`,
                dataFreshness: new Date().toISOString()
            }
        });
        try { await Actor.charge({ eventName: 'analysis-completed' }); } catch (e) { log.debug(`charge skipped: ${e.message}`); }

        log.info('═══ Analysis Results ═══');
        log.info(`Target:            ${result.target} (${result.targetType})`);
        log.info(`Confidence Score:  ${result.confidenceScore}% (${result.confidenceLevel})`);
        log.info(`Duration:          ${duration}s`);

        log.info('Analyzer Results:');
        for (const [analyzer, analyzerResult] of Object.entries(result.analyses)) {
            const status = analyzerResult.success ? '✓' : '✗';
            const statusText = analyzerResult.success ? 'SUCCESS' : 'FAILED';
            log.info(`  ${status} ${analyzer.padEnd(15)} ${statusText}`);
            if (!analyzerResult.success && analyzerResult.error) {
                log.warning(`    └─ Error: ${analyzerResult.error}`);
            }
        }

        if (result.correlation && result.correlation.threatIndicators.length > 0) {
            log.warning('⚠️  Threat Indicators:');
            result.correlation.threatIndicators.forEach(indicator => {
                log.warning(`  • ${indicator.description} (${indicator.severity})`);
            });
        }

        if (result.correlation && result.correlation.recommendations.length > 0) {
            log.info('💡 Recommendations:');
            result.correlation.recommendations.forEach(rec => {
                log.info(`  • ${rec}`);
            });
        }
    }

    const totalDuration = ((Date.now() - startTime) / 1000).toFixed(2);

    log.info('╔══════════════════════════════════════════════════════════════════╗');
    log.info('║              NetIntel Actor Completed Successfully               ║');
    log.info('╚══════════════════════════════════════════════════════════════════╝');
    log.info(`Results saved to dataset`);
    log.info(`Total execution time: ${totalDuration}s`);
    log.info(`Finished at: ${new Date().toISOString()}`);

} catch (error) {
    log.error('╔══════════════════════════════════════════════════════════════════╗');
    log.error('║                    NetIntel Actor Failed                         ║');
    log.error('╚══════════════════════════════════════════════════════════════════╝');
    log.error(`Error Type:    ${error.name}`);
    log.error(`Error Message: ${error.message}`);
    log.error('Stack Trace:');
    log.error(error.stack);

    const input = await Actor.getInput();
    await Actor.pushData({
        error: true,
        errorMessage: error.message,
        errorType: error.name,
        errorStack: error.stack,
        target: input?.target || 'unknown',
        timestamp: new Date().toISOString(),
        troubleshooting: [
            'Check your input format (must be valid IP or domain)',
            'Ensure all required fields are present',
            'Verify analysis types are valid: whois, dns, ssl, geolocation, reputation, ports',
            'Try increasing timeout value if getting timeout errors',
            'Check network connectivity'
        ],
        metadata: {
            actorVersion: process.env.APIFY_ACTOR_BUILD || 'unknown',
            runId: process.env.APIFY_ACTOR_RUN_ID,
            executionTime: `${((Date.now() - startTime) / 1000).toFixed(2)}s`,
            dataFreshness: new Date().toISOString()
        }
    });

    log.info('💡 Troubleshooting Tips:');
    log.info('  • Check your input in storage/key_value_stores/default/INPUT.json');
    log.info('  • Verify target format (must be valid IP or domain)');
    log.info('  • Ensure all required fields are present');
    log.info('  • Verify analysis types are valid: whois, dns, ssl, geolocation, reputation, ports');
    log.info('  • Try increasing timeout value if getting timeout errors');

    throw error;
} finally {
    await Actor.exit();
}

import { THREAT_INDICATORS } from '../config/constants.js';

/**
 * Correlates data from multiple analysis sources to identify patterns
 * @param {Object} results - Combined results from all analyzers
 * @returns {Object} Correlation insights
 */
export function correlateResults(results) {
    const insights = {
        threatIndicators: [],
        anomalies: [],
        recommendations: []
    };

    const portsData = results.ports?.data;
    if (portsData?.openPorts?.length) {
        const suspiciousPorts = portsData.openPorts.filter(p =>
            THREAT_INDICATORS.suspiciousPorts.includes(p.port)
        );

        if (suspiciousPorts.length > 0) {
            insights.threatIndicators.push({
                type: 'suspicious_ports',
                severity: 'medium',
                description: `Suspicious ports detected: ${suspiciousPorts.map(p => p.port).join(', ')}`,
                ports: suspiciousPorts
            });
        }
    }

    if (results.targetType === 'domain' && results.target) {
        const hasMaliciousTLD = THREAT_INDICATORS.knownMaliciousTLDs.some(tld =>
            results.target.endsWith(tld)
        );

        if (hasMaliciousTLD) {
            insights.threatIndicators.push({
                type: 'suspicious_tld',
                severity: 'high',
                description: 'Domain uses a TLD commonly associated with malicious activity'
            });
        }
    }

    const geoData = results.geolocation?.data;
    if (geoData?.isp) {
        const ispLower = geoData.isp.toLowerCase();
        const isVPN = THREAT_INDICATORS.vpnKeywords.some(keyword =>
            ispLower.includes(keyword)
        );

        if (isVPN) {
            insights.anomalies.push({
                type: 'vpn_proxy_detected',
                description: 'IP appears to be from a VPN, proxy, or hosting provider',
                isp: geoData.isp
            });
        }
    }

    const repData = results.reputation?.data;
    if (repData?.threatScore > 50) {
        insights.threatIndicators.push({
            type: 'high_threat_score',
            severity: 'high',
            description: `High threat score detected: ${repData.threatScore}/100`,
            score: repData.threatScore
        });
    }

    if (insights.threatIndicators.length > 0) {
        insights.recommendations.push('Further investigation recommended due to threat indicators');
    }

    const sslValidity = results.ssl?.data?.validity;
    if (sslValidity?.expired) {
        insights.recommendations.push('SSL certificate is expired - potential security risk');
    } else if (sslValidity?.expiringCritical) {
        insights.recommendations.push(`SSL certificate expires in ${sslValidity.daysUntilExpiry} days — renew now`);
    }

    return insights;
}

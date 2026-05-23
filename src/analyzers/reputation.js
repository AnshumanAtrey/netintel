import dns from 'dns/promises';

/**
 * Checks IP/domain reputation using DNS-based blacklists
 * @param {string} target - IP or domain
 * @param {string} targetType - 'ip' or 'domain'
 * @param {number} timeout - Timeout in seconds
 * @returns {Promise<Object>} Reputation data
 */
export async function analyzeReputation(target, targetType, timeout) {
    console.log(`Running reputation check for ${target}`);

    let ipAddress = target;

    if (targetType === 'domain') {
        try {
            const addresses = await dns.resolve4(target);
            ipAddress = addresses[0];
            console.log(`Resolved ${target} to ${ipAddress}`);
        } catch (error) {
            return {
                success: false,
                analyzer: 'reputation',
                target,
                targetType,
                timestamp: new Date().toISOString(),
                error: `Failed to resolve domain to IP: ${error.message}`
            };
        }
    }

    try {
        const blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'cbl.abuseat.org'
        ];

        const blacklistResults = [];
        let listedCount = 0;

        const reversedIP = ipAddress.split('.').reverse().join('.');

        for (const blacklist of blacklists) {
            try {
                const query = `${reversedIP}.${blacklist}`;
                await dns.resolve4(query);
                blacklistResults.push({ blacklist, listed: true });
                listedCount++;
            } catch (error) {
                blacklistResults.push({ blacklist, listed: false });
            }
        }

        const threatScore = Math.round((listedCount / blacklists.length) * 100);

        console.log(`Reputation check completed: threat score ${threatScore}/100`);

        return {
            success: true,
            analyzer: 'reputation',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            data: {
                ip: ipAddress,
                threatScore,
                threatLevel: threatScore > 75 ? 'high' : threatScore > 25 ? 'medium' : 'low',
                blacklistsChecked: blacklists.length,
                blacklistsListed: listedCount,
                blacklistResults,
                message: listedCount > 0
                    ? `IP is listed on ${listedCount} blacklist(s)`
                    : 'IP is not listed on any checked blacklists'
            }
        };

    } catch (error) {
        console.error(`Reputation check failed:`, error.message);
        return {
            success: false,
            analyzer: 'reputation',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            error: `Reputation check failed: ${error.message}`
        };
    }
}

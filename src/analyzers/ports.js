import net from 'net';
import dns from 'dns/promises';
import { COMMON_PORTS, TIMEOUTS } from '../config/constants.js';

/**
 * Scans common ports on target
 * @param {string} target - IP or domain
 * @param {string} targetType - 'ip' or 'domain'
 * @param {number} timeout - Timeout in seconds
 * @returns {Promise<Object>} Port scan results
 */
export async function analyzePorts(target, targetType, timeout) {
    console.log(`Running port scan for ${target}`);

    let ipAddress = target;

    if (targetType === 'domain') {
        try {
            const addresses = await dns.resolve4(target);
            ipAddress = addresses[0];
            console.log(`Resolved ${target} to ${ipAddress}`);
        } catch (error) {
            return {
                success: false,
                analyzer: 'ports',
                target,
                targetType,
                timestamp: new Date().toISOString(),
                error: `Failed to resolve domain to IP: ${error.message}`
            };
        }
    }

    try {
        const scanResults = [];
        const openPorts = [];
        const closedPorts = [];

        const scanPromises = COMMON_PORTS.map(({ port, service }) => {
            return scanPort(ipAddress, port, TIMEOUTS.port)
                .then(isOpen => {
                    const result = { port, service, status: isOpen ? 'open' : 'closed' };
                    scanResults.push(result);
                    if (isOpen) {
                        openPorts.push(result);
                    } else {
                        closedPorts.push(result);
                    }
                })
                .catch(error => {
                    scanResults.push({
                        port,
                        service,
                        status: 'error',
                        error: error.message
                    });
                });
        });

        await Promise.all(scanPromises);

        console.log(`Port scan completed: ${openPorts.length} open ports found`);

        return {
            success: true,
            analyzer: 'ports',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            data: {
                ip: ipAddress,
                portsScanned: COMMON_PORTS.length,
                openPortsCount: openPorts.length,
                closedPortsCount: closedPorts.length,
                openPorts: openPorts.sort((a, b) => a.port - b.port),
                allResults: scanResults.sort((a, b) => a.port - b.port)
            }
        };

    } catch (error) {
        console.error(`Port scan failed:`, error.message);
        return {
            success: false,
            analyzer: 'ports',
            target,
            targetType,
            timestamp: new Date().toISOString(),
            error: `Port scan failed: ${error.message}`
        };
    }
}

/**
 * Scans a single port
 * @param {string} host - IP address
 * @param {number} port - Port number
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<boolean>} True if port is open
 */
function scanPort(host, port, timeout) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        
        socket.setTimeout(timeout);
        
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(port, host);
    });
}

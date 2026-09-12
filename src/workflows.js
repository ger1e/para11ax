export const WORKFLOWS = Object.freeze({
  ip: Object.freeze(['ipinfo', 'rdap', 'ripestat', 'dshield', 'spamhaus-drop', 'tor-exit', 'feodo-tracker', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'greynoise', 'abuseipdb', 'shodan', 'censys', 'modat', 'cloudflare-radar', 'virustotal', 'otx', 'threatfox', 'urlscan', 'webamon', 'pulsedive']),
  domain: Object.freeze(['threatminer', 'cloudflare-dns', 'openphish', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'urlscan', 'webamon', 'modat', 'ransomware-live', 'virustotal', 'otx', 'threatfox', 'pulsedive']),
  url: Object.freeze(['openphish', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'urlscan', 'webamon', 'urlhaus', 'ransomware-live', 'virustotal', 'otx', 'threatfox', 'pulsedive']),
  hash: Object.freeze(['circl-hashlookup', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'malwarebazaar', 'malpedia', 'virustotal', 'hybrid-analysis', 'otx', 'threatfox']),
  cve: Object.freeze(['cisa-kev', 'cisa-adp', 'epss', 'circl-vulnerability', 'misp-circl-osint', 'misp-botvrij-osint', 'nvd', 'osv', 'otx']),
  attack: Object.freeze(['attack-taxii']),
  asn: Object.freeze(['rdap', 'ripestat', 'spamhaus-drop']),
  cidr: Object.freeze(['rdap', 'ripestat', 'spamhaus-drop']),
  certificate: Object.freeze(['censys', 'virustotal']),
});

// The scheduler permits at most two attempts per admitted provider. Reserve enough
// request-local call tokens for that bounded retry policy across the entire fixed
// workflow so an early timeout cannot starve later providers in the same profile.
export const WORKFLOW_CALL_LIMITS = Object.freeze(
  Object.fromEntries(Object.entries(WORKFLOWS).map(([type, providers]) => [type, providers.length * 2])),
);

export const WORKFLOW_BLUEPRINTS = WORKFLOWS;

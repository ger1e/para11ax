import { ipinfoProvider as rawIpinfoProvider } from './ipinfo.js';
import { rdapProvider as rawRdapProvider } from './rdap.js';
import { ripestatProvider as rawRipestatProvider } from './ripestat.js';
import { dshieldProvider as rawDshieldProvider } from './dshield.js';
import { spamhausDropProvider as rawSpamhausDropProvider } from './spamhaus-drop.js';
import { torExitProvider as rawTorExitProvider } from './tor-exit.js';
import { feodoTrackerProvider as rawFeodoTrackerProvider } from './feodo-tracker.js';
import { threatminerProvider as rawThreatminerProvider } from './threatminer.js';
import { mispCirclOsintProvider as rawMispCirclOsintProvider, mispBotvrijOsintProvider as rawMispBotvrijOsintProvider } from './misp-osint.js';
import { greynoiseProvider as rawGreynoiseProvider } from './greynoise.js';
import { abuseipdbProvider as rawAbuseipdbProvider } from './abuseipdb.js';
import { shodanProvider as rawShodanProvider } from './shodan.js';
import { censysProvider as rawCensysProvider, censysSearchProvider as rawCensysSearchProvider, censysHistoryProvider as rawCensysHistoryProvider } from './censys.js';
import { modatProvider as rawModatProvider } from './modat.js';
import { cloudflareRadarProvider as rawCloudflareRadarProvider } from './cloudflare-radar.js';
import { cloudflareDnsProvider as rawCloudflareDnsProvider } from './cloudflare-dns.js';
import { virustotalProvider as rawVirustotalProvider, virustotalGraphProvider as rawVirustotalGraphProvider } from './virustotal.js';
import { otxProvider as rawOtxProvider } from './otx.js';
import { threatfoxProvider as rawThreatfoxProvider } from './threatfox.js';
import { urlscanProvider as rawUrlscanProvider, urlscanGraphProvider as rawUrlscanGraphProvider } from './urlscan.js';
import { webamonProvider as rawWebamonProvider } from './webamon.js';
import { pulsediveProvider as rawPulsediveProvider } from './pulsedive.js';
import { openphishProvider as rawOpenphishProvider } from './openphish.js';
import { urlhausProvider as rawUrlhausProvider } from './urlhaus.js';
import { circlHashlookupProvider as rawCirclHashlookupProvider } from './circl-hashlookup.js';
import { malwarebazaarProvider as rawMalwarebazaarProvider } from './malwarebazaar.js';
import { malpediaProvider as rawMalpediaProvider } from './malpedia.js';
import { hybridAnalysisProvider as rawHybridAnalysisProvider } from './hybrid-analysis.js';
import { cisaKevProvider as rawCisaKevProvider } from './cisa-kev.js';
import { cisaAdpProvider as rawCisaAdpProvider } from './cisa-adp.js';
import { epssProvider as rawEpssProvider } from './epss.js';
import { circlVulnerabilityProvider as rawCirclVulnerabilityProvider } from './circl-vulnerability.js';
import { nvdProvider as rawNvdProvider } from './nvd.js';
import { osvProvider as rawOsvProvider } from './osv.js';
import { attackTaxiiProvider as rawAttackTaxiiProvider } from './attack-taxii.js';
import { tweetfeedProvider as rawTweetfeedProvider } from './tweetfeed.js';
import { ransomlookProvider as rawRansomlookProvider } from './ransomlook.js';
import { ransomwareLiveProvider as rawRansomwareLiveProvider } from './ransomware-live.js';
import { vulncheckProvider as rawVulncheckProvider } from './vulncheck.js';
import { depsDevProvider as rawDepsDevProvider } from './deps-dev.js';
import { sslblProvider as rawSslblProvider } from './sslbl.js';
import { yaraifyProvider as rawYaraifyProvider } from './yaraify.js';
import { mwdbProvider as rawMwdbProvider } from './mwdb.js';
import { waybackCdxProvider as rawWaybackCdxProvider } from './wayback-cdx.js';
import { d3fendProvider as rawD3fendProvider } from './d3fend.js';
import { chainabuseProvider as rawChainabuseProvider } from './chainabuse.js';
import { gitguardianHmslProvider as rawGitguardianHmslProvider } from './gitguardian-hmsl.js';
import { shadowserverProvider as rawShadowserverProvider } from './shadowserver.js';
import { withProviderMetadata } from './metadata.js';

export const ipinfoProvider = withProviderMetadata(rawIpinfoProvider);
export const rdapProvider = withProviderMetadata(rawRdapProvider);
export const ripestatProvider = withProviderMetadata(rawRipestatProvider);
export const dshieldProvider = withProviderMetadata(rawDshieldProvider);
export const spamhausDropProvider = withProviderMetadata(rawSpamhausDropProvider);
export const torExitProvider = withProviderMetadata(rawTorExitProvider);
export const feodoTrackerProvider = withProviderMetadata(rawFeodoTrackerProvider);
export const threatminerProvider = withProviderMetadata(rawThreatminerProvider);
export const mispCirclOsintProvider = withProviderMetadata(rawMispCirclOsintProvider);
export const mispBotvrijOsintProvider = withProviderMetadata(rawMispBotvrijOsintProvider);
export const greynoiseProvider = withProviderMetadata(rawGreynoiseProvider);
export const abuseipdbProvider = withProviderMetadata(rawAbuseipdbProvider);
export const shodanProvider = withProviderMetadata(rawShodanProvider);
export const censysProvider = withProviderMetadata(rawCensysProvider);
export const censysSearchProvider = withProviderMetadata(rawCensysSearchProvider);
export const censysHistoryProvider = withProviderMetadata(rawCensysHistoryProvider);
export const modatProvider = withProviderMetadata(rawModatProvider);
export const cloudflareRadarProvider = withProviderMetadata(rawCloudflareRadarProvider);
export const cloudflareDnsProvider = withProviderMetadata(rawCloudflareDnsProvider);
export const virustotalProvider = withProviderMetadata(rawVirustotalProvider);
export const virustotalGraphProvider = withProviderMetadata(rawVirustotalGraphProvider);
export const otxProvider = withProviderMetadata(rawOtxProvider);
export const threatfoxProvider = withProviderMetadata(rawThreatfoxProvider);
export const urlscanProvider = withProviderMetadata(rawUrlscanProvider);
export const urlscanGraphProvider = withProviderMetadata(rawUrlscanGraphProvider);
export const webamonProvider = withProviderMetadata(rawWebamonProvider);
export const pulsediveProvider = withProviderMetadata(rawPulsediveProvider);
export const openphishProvider = withProviderMetadata(rawOpenphishProvider);
export const urlhausProvider = withProviderMetadata(rawUrlhausProvider);
export const circlHashlookupProvider = withProviderMetadata(rawCirclHashlookupProvider);
export const malwarebazaarProvider = withProviderMetadata(rawMalwarebazaarProvider);
export const malpediaProvider = withProviderMetadata(rawMalpediaProvider);
export const hybridAnalysisProvider = withProviderMetadata(rawHybridAnalysisProvider);
export const cisaKevProvider = withProviderMetadata(rawCisaKevProvider);
export const cisaAdpProvider = withProviderMetadata(rawCisaAdpProvider);
export const epssProvider = withProviderMetadata(rawEpssProvider);
export const circlVulnerabilityProvider = withProviderMetadata(rawCirclVulnerabilityProvider);
export const nvdProvider = withProviderMetadata(rawNvdProvider);
export const osvProvider = withProviderMetadata(rawOsvProvider);
export const attackTaxiiProvider = withProviderMetadata(rawAttackTaxiiProvider);
export const tweetfeedProvider = withProviderMetadata(rawTweetfeedProvider);
export const ransomlookProvider = withProviderMetadata(rawRansomlookProvider);
export const ransomwareLiveProvider = withProviderMetadata(rawRansomwareLiveProvider);
export const vulncheckProvider = withProviderMetadata(rawVulncheckProvider);
export const depsDevProvider = withProviderMetadata(rawDepsDevProvider);
export const sslblProvider = withProviderMetadata(rawSslblProvider);
export const yaraifyProvider = withProviderMetadata(rawYaraifyProvider);
export const mwdbProvider = withProviderMetadata(rawMwdbProvider);
export const waybackCdxProvider = withProviderMetadata(rawWaybackCdxProvider);
export const d3fendProvider = withProviderMetadata(rawD3fendProvider);
export const chainabuseProvider = withProviderMetadata(rawChainabuseProvider);
export const gitguardianHmslProvider = withProviderMetadata(rawGitguardianHmslProvider);
export const shadowserverProvider = withProviderMetadata(rawShadowserverProvider);

export const ALL_PROVIDERS = Object.freeze([
  ipinfoProvider, rdapProvider, ripestatProvider, dshieldProvider, spamhausDropProvider, torExitProvider,
  feodoTrackerProvider, threatminerProvider, mispCirclOsintProvider, mispBotvrijOsintProvider,
  greynoiseProvider, abuseipdbProvider, shodanProvider, censysProvider, censysSearchProvider, censysHistoryProvider, modatProvider, cloudflareRadarProvider,
  cloudflareDnsProvider, virustotalProvider, virustotalGraphProvider, otxProvider, threatfoxProvider, urlscanProvider, urlscanGraphProvider, webamonProvider,
  pulsediveProvider, openphishProvider, urlhausProvider, circlHashlookupProvider,
  malwarebazaarProvider, malpediaProvider, hybridAnalysisProvider, cisaKevProvider, cisaAdpProvider, epssProvider,
  circlVulnerabilityProvider, nvdProvider, osvProvider, attackTaxiiProvider,
  tweetfeedProvider, ransomlookProvider, ransomwareLiveProvider, vulncheckProvider, depsDevProvider,
  sslblProvider, yaraifyProvider, mwdbProvider, waybackCdxProvider,
  d3fendProvider, chainabuseProvider, gitguardianHmslProvider, shadowserverProvider,
]);
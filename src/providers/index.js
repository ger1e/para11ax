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
import { censysProvider as rawCensysProvider } from './censys.js';
import { modatProvider as rawModatProvider } from './modat.js';
import { cloudflareRadarProvider as rawCloudflareRadarProvider } from './cloudflare-radar.js';
import { cloudflareDnsProvider as rawCloudflareDnsProvider } from './cloudflare-dns.js';
import { virustotalProvider as rawVirustotalProvider } from './virustotal.js';
import { otxProvider as rawOtxProvider } from './otx.js';
import { threatfoxProvider as rawThreatfoxProvider } from './threatfox.js';
import { urlscanProvider as rawUrlscanProvider } from './urlscan.js';
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
export const modatProvider = withProviderMetadata(rawModatProvider);
export const cloudflareRadarProvider = withProviderMetadata(rawCloudflareRadarProvider);
export const cloudflareDnsProvider = withProviderMetadata(rawCloudflareDnsProvider);
export const virustotalProvider = withProviderMetadata(rawVirustotalProvider);
export const otxProvider = withProviderMetadata(rawOtxProvider);
export const threatfoxProvider = withProviderMetadata(rawThreatfoxProvider);
export const urlscanProvider = withProviderMetadata(rawUrlscanProvider);
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

export const ALL_PROVIDERS = Object.freeze([
  ipinfoProvider, rdapProvider, ripestatProvider, dshieldProvider, spamhausDropProvider, torExitProvider,
  feodoTrackerProvider, threatminerProvider, mispCirclOsintProvider, mispBotvrijOsintProvider,
  greynoiseProvider, abuseipdbProvider, shodanProvider, censysProvider, modatProvider, cloudflareRadarProvider,
  cloudflareDnsProvider, virustotalProvider, otxProvider, threatfoxProvider, urlscanProvider, webamonProvider,
  pulsediveProvider, openphishProvider, urlhausProvider, circlHashlookupProvider,
  malwarebazaarProvider, malpediaProvider, hybridAnalysisProvider, cisaKevProvider, cisaAdpProvider, epssProvider,
  circlVulnerabilityProvider, nvdProvider, osvProvider, attackTaxiiProvider,
  tweetfeedProvider, ransomlookProvider, ransomwareLiveProvider,
]);

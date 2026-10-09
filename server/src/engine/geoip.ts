import geoip from 'geoip-lite';

export interface GeoIpResult {
  countryCode: string;
  countryName: string;
  latitude?: number;
  longitude?: number;
  isPrivate: boolean;
}

// Bounded LRU cache for GeoIP lookups
const GEO_CACHE_MAX_SIZE = 5000;
const geoCache = new Map<string, GeoIpResult>();

const COUNTRY_NAMES: Record<string, string> = {
  US: 'United States',
  IN: 'India',
  GB: 'United Kingdom',
  DE: 'Germany',
  FR: 'France',
  CN: 'China',
  RU: 'Russia',
  JP: 'Japan',
  BR: 'Brazil',
  CA: 'Canada',
  AU: 'Australia',
  NL: 'Netherlands',
  SG: 'Singapore',
  KR: 'South Korea',
  UA: 'Ukraine',
  PL: 'Poland',
  RO: 'Romania',
  VN: 'Vietnam',
  ID: 'Indonesia',
  LOCAL: 'Local / Private Network',
  UNKNOWN: 'Unknown Country',
};

/**
 * Checks if an IP is private, loopback, or reserved
 */
function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  const cleanIp = ip.trim().replace(/^::ffff:/i, '');

  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') return true;
  if (cleanIp.startsWith('10.') || cleanIp.startsWith('192.168.')) return true;

  // 172.16.0.0 – 172.31.255.255
  if (cleanIp.startsWith('172.')) {
    const parts = cleanIp.split('.');
    if (parts.length >= 2) {
      const secondOctet = parseInt(parts[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
  }

  // IPv6 Link-local / Loopback
  if (cleanIp.startsWith('fe80:') || cleanIp.startsWith('fc00:') || cleanIp.startsWith('fd00:')) {
    return true;
  }

  return false;
}

/**
 * Performs GeoIP lookup for an IPv4 or IPv6 address with LRU caching
 */
export function lookupGeoIp(ip: string): GeoIpResult {
  if (!ip || typeof ip !== 'string') {
    return { countryCode: 'UNKNOWN', countryName: 'Unknown Country', isPrivate: true };
  }

  const cleanIp = ip.trim().replace(/^::ffff:/i, '');

  if (geoCache.has(cleanIp)) {
    return geoCache.get(cleanIp)!;
  }

  if (isPrivateIp(cleanIp)) {
    const res: GeoIpResult = {
      countryCode: 'LOCAL',
      countryName: COUNTRY_NAMES.LOCAL,
      latitude: 0,
      longitude: 0,
      isPrivate: true,
    };
    cacheResult(cleanIp, res);
    return res;
  }

  try {
    const geo = geoip.lookup(cleanIp);
    if (!geo || !geo.country) {
      const unknownRes: GeoIpResult = {
        countryCode: 'UNKNOWN',
        countryName: COUNTRY_NAMES.UNKNOWN,
        latitude: 0,
        longitude: 0,
        isPrivate: false,
      };
      cacheResult(cleanIp, unknownRes);
      return unknownRes;
    }

    const code = geo.country.toUpperCase();
    const name = COUNTRY_NAMES[code] || code;
    const lat = geo.ll && geo.ll.length >= 2 ? geo.ll[0] : undefined;
    const lon = geo.ll && geo.ll.length >= 2 ? geo.ll[1] : undefined;

    const result: GeoIpResult = {
      countryCode: code,
      countryName: name,
      latitude: lat,
      longitude: lon,
      isPrivate: false,
    };

    cacheResult(cleanIp, result);
    return result;
  } catch (err) {
    const errRes: GeoIpResult = {
      countryCode: 'UNKNOWN',
      countryName: COUNTRY_NAMES.UNKNOWN,
      isPrivate: false,
    };
    return errRes;
  }
}

function cacheResult(ip: string, result: GeoIpResult): void {
  if (geoCache.size >= GEO_CACHE_MAX_SIZE) {
    // Evict oldest entry
    const firstKey = geoCache.keys().next().value;
    if (firstKey) geoCache.delete(firstKey);
  }
  geoCache.set(ip, result);
}

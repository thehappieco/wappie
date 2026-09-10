export interface MapLink {
  provider: 'google' | 'apple' | 'osm'
  label: string
  href: string
}

/** Navigation links only; generating them never loads a remote map or its tiles. */
export function mapLinks(lat: number, lon: number, name: string): MapLink[] {
  if (!Number.isFinite(lat) || Math.abs(lat) > 90 || !Number.isFinite(lon) || Math.abs(lon) > 180) return []
  const point = encodeURIComponent(`${lat},${lon}`)
  return [
    { provider: 'apple', label: 'Apple Maps', href: `https://maps.apple.com/?ll=${point}&q=${encodeURIComponent(name)}` },
    { provider: 'google', label: 'Google Maps', href: `https://www.google.com/maps/search/?api=1&query=${point}` },
    { provider: 'osm', label: 'OpenStreetMap', href: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}` },
  ]
}

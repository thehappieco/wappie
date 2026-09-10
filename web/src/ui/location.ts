import { t } from './i18n'

/** Accept decimal degrees, including the comma decimal separator. Never coerce empty to zero. */
export function coordinate(value: string): number {
  const normalized = value.trim().replace('−', '-').replace(',', '.')
  return /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(normalized) ? Number(normalized) : NaN
}

/** Position is requested only in response to the explicit GPS button. */
export function readPosition(signal: AbortSignal): Promise<{ lat: number; lon: number; accuracy: number }> {
  return new Promise((resolve, reject) => {
    let settled = false
    const complete = (error?: Error, value?: { lat: number; lon: number; accuracy: number }) => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', aborted)
      if (error) reject(error)
      else resolve(value!)
    }
    const aborted = () => complete(new DOMException('Aborted', 'AbortError'))
    if (signal.aborted) { aborted(); return }
    signal.addEventListener('abort', aborted, { once: true })
    if (!navigator.geolocation) { complete(new Error(t('Este navegador não disponibiliza a localização. Informe as coordenadas.'))); return }
    try {
      navigator.geolocation.getCurrentPosition(position => {
        const { latitude: lat, longitude: lon, accuracy } = position.coords
        if (!Number.isFinite(lat) || Math.abs(lat) > 90 || !Number.isFinite(lon) || Math.abs(lon) > 180) {
          complete(new Error(t('Não foi possível obter sua posição. Informe as coordenadas.'))); return
        }
        complete(undefined, { lat, lon, accuracy: Number.isFinite(accuracy) && accuracy > 0 ? Math.min(4294967295, Math.ceil(accuracy)) : 0 })
      }, error => complete(new Error(error.code === 1
        ? t('Permissão de localização negada. Você pode informar as coordenadas.')
        : t('Não foi possível obter sua posição. Informe as coordenadas.'))), { enableHighAccuracy: true, maximumAge: 0, timeout: 10000 })
    } catch { complete(new Error(t('Não foi possível obter sua posição. Informe as coordenadas.'))) }
  })
}

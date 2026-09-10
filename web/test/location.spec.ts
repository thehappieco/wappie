import { afterEach, describe, expect, it, vi } from 'vitest'
import { coordinate, readPosition } from '../src/ui/location'

afterEach(() => vi.unstubAllGlobals())
describe('fixed location coordinates', () => {
  it('accepts decimal degrees and locale separators without interpreting blank as zero', () => {
    expect(coordinate('−23,55052')).toBe(-23.55052)
    expect(coordinate(' +0.0 ')).toBe(0)
    expect(coordinate('-.5')).toBe(-.5)
    for (const value of ['', ' ', '0x12', '1e2', 'NaN', 'Infinity', '12.3.4', '12,3,4', '1 2', '12north']) expect(coordinate(value)).toBeNaN()
  })
  it('does not resolve an aborted request or overwrite a later manual choice with a late GPS result', async () => {
    let success!: PositionCallback
    const getCurrentPosition = vi.fn((callback: PositionCallback) => { success = callback })
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition } })
    const controller = new AbortController()
    const pending = readPosition(controller.signal)
    const refused = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort(); await refused
    success({ coords: { latitude: 1, longitude: 2, accuracy: 3 } } as GeolocationPosition)
    expect(getCurrentPosition).toHaveBeenCalledTimes(1)
  })
  it('requests one fresh position and keeps accuracy without watching movements', async () => {
    const getCurrentPosition = vi.fn((success: PositionCallback) => success({ coords: { latitude: 0, longitude: 0, accuracy: 12.2 } } as GeolocationPosition))
    const watchPosition = vi.fn()
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition, watchPosition } })
    await expect(readPosition(new AbortController().signal)).resolves.toEqual({ lat: 0, lon: 0, accuracy: 13 })
    expect(getCurrentPosition.mock.calls[0]).toHaveLength(3)
    expect(watchPosition).not.toHaveBeenCalled()
  })
  it('keeps permission denial and malformed GPS data as errors', async () => {
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition: (_: PositionCallback, error: PositionErrorCallback) => error({ code: 1 } as GeolocationPositionError) } })
    await expect(readPosition(new AbortController().signal)).rejects.toThrow(/Permissão|permission/i)
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition: (success: PositionCallback) => success({ coords: { latitude: NaN, longitude: 20, accuracy: 1 } } as GeolocationPosition) } })
    await expect(readPosition(new AbortController().signal)).rejects.toThrow()
  })
})

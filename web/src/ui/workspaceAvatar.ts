import { t } from './i18n'

// A local raster thumbnail keeps account metadata small and avoids passing an
// external URL or a vector with active content to any profile renderer.
export async function workspaceAvatar(file: File): Promise<string> {
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type) || file.size > 8 * 1024 * 1024) {
    throw new Error(t('Escolha uma imagem JPG, PNG ou WebP de até 8 MB.'))
  }
  const url = URL.createObjectURL(file)
  try {
    const image = new Image()
    image.src = url
    await image.decode()
    if (!image.naturalWidth || !image.naturalHeight || image.naturalWidth * image.naturalHeight > 40_000_000) {
      throw new Error(t('Esta imagem é muito grande. Escolha uma imagem menor.'))
    }
    const canvas = document.createElement('canvas')
    canvas.width = 256; canvas.height = 256
    const context = canvas.getContext('2d')
    if (!context) throw new Error(t('Não foi possível preparar o avatar.'))
    context.fillStyle = '#ffffff'; context.fillRect(0, 0, 256, 256)
    const side = Math.min(image.naturalWidth, image.naturalHeight)
    context.drawImage(image, (image.naturalWidth - side) / 2, (image.naturalHeight - side) / 2, side, side, 0, 0, 256, 256)
    for (const quality of [0.85, 0.7, 0.5]) {
      const data = canvas.toDataURL('image/jpeg', quality)
      if (data.length <= 43000) return data
    }
    throw new Error(t('Não foi possível reduzir a imagem. Escolha outra imagem.'))
  } catch (error) {
    if (error instanceof DOMException) throw new Error(t('Não foi possível abrir esta imagem. Escolha outra imagem.'))
    throw error
  } finally {
    URL.revokeObjectURL(url)
  }
}

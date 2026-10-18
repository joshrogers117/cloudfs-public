#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Prevent an old asset or packaging path from restoring the retired identity.
import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = fileURLToPath(new URL('../', import.meta.url))
const read = relative => readFile(path.join(root, relative))
const assert = (condition, message) => { if (!condition) throw new Error(message) }
const canonical = await read('client-app/Resources/cloudfs-logo.svg')
assert(canonical.toString().includes('#a08cff'), 'The canonical drive must retain its purple identity.')
for (const directory of ['web/public', 'site/assets']) {
  for (const file of ['brand.svg', 'cloudfs-drive-v2.svg']) {
    assert((await read(`${directory}/${file}`)).equals(canonical), `${directory}/${file} is out of sync; run the icon generator with --web-assets.`)
  }
  for (const size of [32, 180]) {
    const png = await read(`${directory}/cloudfs-drive-v2-${size}.png`)
    assert(png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) &&
      png.readUInt32BE(16) === size && png.readUInt32BE(20) === size, `Invalid ${size}px browser icon in ${directory}.`)
  }
  const ico = await read(`${directory}/cloudfs-drive-v2.ico`)
  assert(ico.readUInt16LE(0) === 0 && ico.readUInt16LE(2) === 1 && ico.readUInt16LE(4) === 3,
    `Invalid browser ICO in ${directory}.`)
  assert(ico.equals(await read(`${directory}/favicon.ico`)), `The conventional favicon in ${directory} is stale.`)
}

for (const [htmlFile, prefix] of [['web/index.html', 'web/public'], ['site/index.html', 'site']]) {
  const html = (await read(htmlFile)).toString()
  const links = [...html.matchAll(/<link\b[^>]*rel="(?:icon|apple-touch-icon)"[^>]*href="([^"]+)"[^>]*>/g)]
  assert(links.length === 4, `${htmlFile} must provide SVG, PNG, ICO, and Apple touch icons.`)
  for (const [, href] of links) {
    assert(href.includes('cloudfs-drive-v2'), `${htmlFile} points to a stale favicon URL.`)
    await read(`${prefix}/${href.replace(/^\//, '')}`)
  }
}

// Historical screenshots and reports are evidence, not active source assets.
async function checkSource(directory) {
  for (const entry of await readdir(path.join(root, directory), { withFileTypes: true })) {
    const relative = `${directory}/${entry.name}`
    if (entry.isDirectory()) { await checkSource(relative); continue }
    if (!/\.(?:svg|tsx?|css|html|swift)$/.test(entry.name)) continue
    const source = (await read(relative)).toString()
    assert(!/#f5c21a|M\s*50\.80\s+62\.55|245,\s*194,\s*26/i.test(source), `Retired brand artwork in ${relative}.`)
  }
}
for (const directory of ['web/src', 'web/public', 'site', 'client-app/Sources', 'client-app/Resources']) {
  await checkSource(directory)
}
console.log('Purple-drive assets, browser icons, and active source branding verified.')

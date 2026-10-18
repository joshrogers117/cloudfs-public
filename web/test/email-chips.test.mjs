import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  formatEmailTokens,
  isValidEmailAddress,
  mergeUniqueEmails,
  parseEmailTokens,
} from '../src/pages/emailChips.ts'

test('email validation accepts common addresses and enforces dot-atom local parts', () => {
  for (const email of ['avery@example.com', 'first.last+invite@media-team.co.uk', "o'hara@example.org"]) {
    assert.equal(isValidEmailAddress(email), true, email)
  }

  for (const email of [
    '.first@example.com',
    'last.@example.com',
    'two..dots@example.com',
    `${'a'.repeat(65)}@example.com`,
    'avery@-example.com',
    'avery@example-.com',
    'avery@example',
    'avery@@example.com',
  ]) {
    assert.equal(isValidEmailAddress(email), false, email)
  }
})

test('delimited input accepts valid addresses while retaining each invalid token', () => {
  const parsed = parseEmailTokens('first@example.com; broken;\nsecond@example.org, no-at-sign')
  assert.deepEqual(parsed, {
    valid: ['first@example.com', 'second@example.org'],
    invalid: ['broken', 'no-at-sign'],
  })
  assert.equal(formatEmailTokens(parsed.invalid), 'broken, no-at-sign')
})

test('invalid tokens remain independently parseable after one is corrected', () => {
  const afterCorrection = parseEmailTokens('fixed@example.com, still-bad')
  assert.deepEqual(afterCorrection, {
    valid: ['fixed@example.com'],
    invalid: ['still-bad'],
  })
})

test('merging chips de-duplicates case-insensitively and keeps first spelling', () => {
  assert.deepEqual(
    mergeUniqueEmails(['Avery@example.com'], ['avery@EXAMPLE.com', 'blair@example.com', 'BLAIR@example.com']),
    ['Avery@example.com', 'blair@example.com'],
  )
})

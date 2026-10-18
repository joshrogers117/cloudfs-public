// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * GetTheAppSection — signed-in home for the shared GetTheAppCard (ONBOARDING.md
 * build step 3). The post-/join success screen shows the same card once right
 * after account creation; this is where an existing member finds it again later
 * — setting up a SECOND Mac, or coming back after skipping it the first time.
 * Sits next to DevicesSection (the devices it produces show up there).
 */
import { SettingsGroup, SettingsRow } from './SettingsGroup'
import { GetTheAppCard } from '../join/GetTheAppCard'
import { IconLaptop } from './icons'

export function GetTheAppSection() {
  return (
    <SettingsGroup
      label="Get the app"
      description="Connect another Mac to this account with one click — no server address to type."
    >
      <SettingsRow leading={<IconLaptop />} title="cloud-fs for Mac" align="top">
        <GetTheAppCard />
      </SettingsRow>
    </SettingsGroup>
  )
}

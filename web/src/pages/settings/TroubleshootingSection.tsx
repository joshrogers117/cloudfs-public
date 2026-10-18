import { useState } from 'react'
import { Button } from '../../design'
import { HealthCheckPanel } from '../HealthCheckPanel'
import { SettingsGroup, SettingsRow } from './SettingsGroup'

export function TroubleshootingSection({ org }: { org: string }) {
  const [started, setStarted] = useState(false)
  return <section id="troubleshooting">
    <SettingsGroup label="Troubleshooting">
      <SettingsRow title="Check workspace services" sublabel="Diagnose storage, sign-in and email issues."
        trailing={!started && <Button variant="secondary" onClick={() => setStarted(true)}>Run checks</Button>}>
        {started && <HealthCheckPanel org={org} />}
      </SettingsRow>
    </SettingsGroup>
  </section>
}

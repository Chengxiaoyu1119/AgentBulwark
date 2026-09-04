import { SettingsBasicsTab } from './SettingsBasicsTab';
import type { ModelProviderProbeResult, ModelRuntimeConfig, ModelStatusByProfile, Overview } from '../../types';

type ProviderSettingsProps = {
  overview: Overview;
  config: ModelRuntimeConfig | null;
  canEdit: boolean;
  permissionKnown?: boolean;
  saving: boolean;
  loading?: boolean;
  loadError?: string;
  canProbe?: boolean;
  probingProviderKey?: string;
  probeResult?: ModelProviderProbeResult | null;
  onProbeProvider?: (profile: string, providerId: string) => void | Promise<void>;
  profileStatuses?: ModelStatusByProfile;
  profileStatusError?: string;
  profileStatusLoading?: boolean;
  onChange: (config: ModelRuntimeConfig) => void;
  onSave: () => void | Promise<void>;
};

/** Keep the production settings import stable while sharing one Provider workflow. */
export function ProviderSettings({
  overview,
  config,
  canEdit,
  permissionKnown = true,
  saving,
  loading = false,
  loadError,
  canProbe = true,
  probingProviderKey,
  probeResult,
  onProbeProvider,
  profileStatuses,
  profileStatusError,
  profileStatusLoading,
  onChange,
  onSave
}: ProviderSettingsProps) {
  return (
    <SettingsBasicsTab
      overview={overview}
      modelConfig={config}
      canEdit={canEdit}
      permissionKnown={permissionKnown}
      savingModelConfig={saving}
      onModelConfigChange={onChange}
      onSaveModelConfig={onSave}
      loadingModelConfig={loading}
      modelConfigError={loadError}
      canProbe={canProbe}
      probingProviderKey={probingProviderKey}
      probeResult={probeResult}
      onProbeProvider={onProbeProvider}
      profileStatuses={profileStatuses}
      profileStatusError={profileStatusError}
      profileStatusLoading={profileStatusLoading}
    />
  );
}

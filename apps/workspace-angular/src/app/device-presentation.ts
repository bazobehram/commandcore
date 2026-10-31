/** Pure display helpers for device cards.
 *
 * These are presentation hints only. They must never influence OAuth grants,
 * device-local permissions, enrollment, or dispatch.
 */
export type DeviceDisplayInfo = {
  id: string;
  display_name: string;
  hostname?: string;
  platform?: string;
  capabilities?: Record<string, unknown>;
};

export type DeviceDisplayRole = 'server' | 'workstation' | 'desktop' | 'laptop' | 'computer';
const DISPLAY_ROLES: ReadonlySet<string> = new Set(['server', 'workstation', 'desktop', 'laptop', 'computer']);

export function deviceDisplayRole(
  device: DeviceDisplayInfo,
  overrides: Readonly<Record<string, string>>,
): string {
  // Existing saved preferences may come from earlier UI versions. Preserve
  // their display fallback without treating them as security authority.
  const explicit = overrides[device.id];
  if (explicit && explicit !== 'auto') return explicit;
  if (device.capabilities?.['desktop'] === true) return 'workstation';
  if (/server|nas|storage|node/i.test(device.hostname || device.display_name || '')
      && device.capabilities?.['services']) return 'server';
  return 'computer';
}

export function isDeviceDisplayRole(role: string): role is DeviceDisplayRole {
  return DISPLAY_ROLES.has(role);
}

export function deviceDisplayType(role: string): string {
  const types: Record<DeviceDisplayRole, string> = {
    server: 'SERVER',
    workstation: 'WORKSTATION',
    desktop: 'DESKTOP PC',
    laptop: 'LAPTOP',
    computer: 'COMPUTER',
  };
  return types[role as DeviceDisplayRole] || 'DEVICE';
}

export function deviceDisplayOS(platform?: string): string {
  const normalized = String(platform || '').toLowerCase();
  return normalized.includes('windows') ? 'Windows'
    : normalized.includes('linux') ? 'Linux'
    : normalized.includes('darwin') || normalized.includes('mac') ? 'macOS'
    : platform || 'Unknown OS';
}

export function deviceDisplayOSSymbol(platform?: string): string {
  const os = deviceDisplayOS(platform);
  return os === 'Windows' ? '⊞' : os === 'Linux' ? '◈' : os === 'macOS' ? '⌘' : '◇';
}

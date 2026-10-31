import { describe, expect, it } from 'vitest';
import {
  deviceDisplayOS,
  deviceDisplayOSSymbol,
  deviceDisplayRole,
  deviceDisplayType,
  isDeviceDisplayRole,
} from './device-presentation';

const laptop = { id: 'one', hostname: 'netti', display_name: 'Netti', platform: 'Linux x86_64' };

describe('device card display helpers (never authorization)', () => {
  it('uses the legacy computer fallback and supports explicit display role', () => {
    expect(deviceDisplayRole(laptop, {})).toBe('computer');
    expect(deviceDisplayRole(laptop, { one: 'laptop' })).toBe('laptop');
    expect(deviceDisplayRole(laptop, { one: 'auto' })).toBe('computer');
    expect(deviceDisplayType('laptop')).toBe('LAPTOP');
    expect(deviceDisplayType('desktop')).toBe('DESKTOP PC');
    expect(deviceDisplayType('unknown')).toBe('DEVICE');
  });

  it('prefers desktop capability over hostname-based server classification', () => {
    const device = {
      ...laptop,
      hostname: 'server-node',
      capabilities: { desktop: true, services: true },
    };
    expect(deviceDisplayRole(device, {})).toBe('workstation');
    expect(deviceDisplayRole({ ...device, capabilities: { services: true } }, {})).toBe('server');
    expect(deviceDisplayType('workstation')).toBe('WORKSTATION');
  });

  it('recognizes supported display roles but rejects unrecognized choices', () => {
    expect(isDeviceDisplayRole('server')).toBe(true);
    expect(isDeviceDisplayRole('computer')).toBe(true);
    expect(isDeviceDisplayRole('FULL_CONTROL')).toBe(false);
    expect(isDeviceDisplayRole('auto')).toBe(false);
  });

  it('preserves Windows, Linux, macOS and unknown OS labels and symbols', () => {
    expect(deviceDisplayOS('Windows_NT')).toBe('Windows');
    expect(deviceDisplayOSSymbol('Windows_NT')).toBe('⊞');
    expect(deviceDisplayOS('Ubuntu Linux')).toBe('Linux');
    expect(deviceDisplayOSSymbol('Ubuntu Linux')).toBe('◈');
    expect(deviceDisplayOS('Darwin')).toBe('macOS');
    expect(deviceDisplayOSSymbol('macOS')).toBe('⌘');
    expect(deviceDisplayOS('FreeBSD')).toBe('FreeBSD');
    expect(deviceDisplayOSSymbol('FreeBSD')).toBe('◇');
    expect(deviceDisplayOS()).toBe('Unknown OS');
  });
});

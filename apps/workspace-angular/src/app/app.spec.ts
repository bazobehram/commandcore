import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './app';

type Reply = { status?: number; body?: unknown };

function apiReply({ status = 200, body = {} }: Reply = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function stubApi(routes: Record<string, Reply>) {
  const requests: string[] = [];
  const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
    const key = (options?.method ?? 'GET') + ' ' + url;
    requests.push(key);
    return apiReply(routes[key] ?? { status: 404, body: { detail: 'Unmocked request' } });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { requests, fetchMock };
}

async function mountWorkspace() {
  await TestBed.configureTestingModule({ imports: [App] }).compileComponents();
  const fixture = TestBed.createComponent(App);
  fixture.detectChanges();
  await fixture.whenStable();
  await vi.waitFor(() => expect(fixture.componentInstance.loading()).toBe(false));
  fixture.detectChanges();
  return fixture;
}

const loggedInApi = {
  'GET /api/session': { body: { subject: 'test-account', auth_kind: 'oauth2-panel', scopes: ['commandcore:read', 'commandcore:standard'] } },
  'GET /api/devices': { body: { devices: [] } },
  'GET /api/managed-devices': { body: { devices: [] } },
  'GET /api/enrollment/pending': { body: { enrollments: [] } },
};

describe('Workspace component: authenticated session lifecycle', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('renders the sign-in view when the initial session is unauthorized', async () => {
    const { requests } = stubApi({
      'GET /api/session': { status: 401, body: { detail: 'Unauthorized' } },
    });
    const fixture = await mountWorkspace();

    expect(fixture.componentInstance.loggedIn()).toBe(false);
    expect(fixture.nativeElement.querySelector('.login-surface a[href="/auth/login"]')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.account-logout')).toBeNull();
    expect(requests).toEqual(['GET /api/session']);
    fixture.destroy();
  });

  it('shows the authorized workspace and opens the account menu', async () => {
    stubApi(loggedInApi);
    const fixture = await mountWorkspace();
    expect(fixture.componentInstance.loggedIn()).toBe(true);
    expect(fixture.nativeElement.querySelector('.login-surface')).toBeNull();
    const menuButton: HTMLButtonElement = fixture.nativeElement.querySelector('.account-trigger');
    expect(menuButton.getAttribute('aria-expanded')).toBe('false');

    menuButton.click();
    fixture.detectChanges();
    expect(menuButton.getAttribute('aria-expanded')).toBe('true');
    expect(fixture.nativeElement.querySelector('.account-logout')?.textContent).toContain('Sign out');
    fixture.destroy();
  });

  it('clears device and Browser information after a subsequent HTTP 401', async () => {
    const routes: Record<string, Reply> = { ...loggedInApi };
    stubApi(routes);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    component.devices.set([{ id: 'fake-device', display_name: 'Synthetic' }]);
    component.browsers.set([{ client_id: 'synthetic-browser' }]);
    component.browserFrame.set('synthetic-frame');
    component.activity.set([{ id: 'synthetic-operation' }]);

    routes['GET /api/devices'] = { status: 401, body: { detail: 'Expired session' } };
    await component.refreshDeviceStates();
    fixture.detectChanges();

    expect(component.loggedIn()).toBe(false);
    expect(component.devices()).toEqual([]);
    expect(component.browsers()).toEqual([]);
    expect(component.browserFrame()).toBe('');
    expect(component.activity()).toEqual([]);
    expect(fixture.nativeElement.querySelector('.login-surface')).not.toBeNull();
    fixture.destroy();
  });

  it('preserves the workspace on a temporary device-state error', async () => {
    const routes: Record<string, Reply> = { ...loggedInApi };
    stubApi(routes);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    component.devices.set([{ id: 'synthetic-device', display_name: 'Synthetic' }]);

    routes['GET /api/devices'] = { status: 503, body: { detail: 'Temporarily unavailable' } };
    await component.refreshDeviceStates();
    fixture.detectChanges();

    expect(component.loggedIn()).toBe(true);
    expect(component.devices().map(device => device.id)).toEqual(['synthetic-device']);
    expect(component.syncHealthy()).toBe(false);
    expect(fixture.nativeElement.querySelector('.login-surface')).toBeNull();
    fixture.destroy();
  });

  it('keeps the session intact when the sign-out request fails', async () => {
    const routes: Record<string, Reply> = {
      ...loggedInApi,
      'DELETE /api/session': { status: 503, body: { detail: 'Unavailable' } },
    };
    const { requests } = stubApi(routes);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    component.toggleAccount();
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('.account-logout') as HTMLButtonElement).click();
    await vi.waitFor(() => expect(requests).toContain('DELETE /api/session'));
    await vi.waitFor(() => expect(component.logoutBusy()).toBe(false));
    expect(component.loggedIn()).toBe(true);
    fixture.destroy();
  });

  it('clears all account state and redirects after a successful sign-out', async () => {
    const { requests } = stubApi({
      ...loggedInApi,
      'DELETE /api/session': { body: { ok: true } },
    });
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    component.devices.set([{ id: 'synthetic-device', display_name: 'Fixture' }]);
    component.browsers.set([{ client_id: 'fixture-browser' }]);
    component.browserFrame.set('private-frame');
    component.activity.set([{ tool: 'synthetic-operation' }]);
    const redirect = vi.fn();
    vi.stubGlobal('location', { replace: redirect });

    await component.signOut();
    fixture.detectChanges();

    expect(requests).toContain('DELETE /api/session');
    expect(component.loggedIn()).toBe(false);
    expect(component.session()).toBeNull();
    expect(component.devices()).toEqual([]);
    expect(component.browsers()).toEqual([]);
    expect(component.browserFrame()).toBe('');
    expect(component.activity()).toEqual([]);
    expect(redirect).toHaveBeenCalledWith('/');
    fixture.destroy();
  });

  it('discards a delayed previous-account device response after session replacement', async () => {
    const routes: Record<string, Reply> = { ...loggedInApi };
    const { fetchMock } = stubApi(routes);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    let resolveOld: ((response: Response) => void) | undefined;
    const oldResponse = new Promise<Response>(resolve => { resolveOld = resolve; });
    let deviceCall = 0;
    fetchMock.mockImplementation(async (url: string, options?: RequestInit) => {
      const key = (options?.method ?? 'GET') + ' ' + url;
      if (key === 'GET /api/devices') {
        deviceCall++;
        if (deviceCall === 1) return oldResponse;
        if (deviceCall === 2) return apiReply({ status: 401, body: { detail: 'Expired' } });
        return apiReply({ body: { devices: [{ id: 'new-device', display_name: 'New account' }] } });
      }
      if (key === 'GET /api/session') {
        return apiReply({ body: {
          subject: 'second-account', auth_kind: 'oauth2-panel',
          scopes: ['commandcore:read', 'commandcore:standard'],
        } });
      }
      return apiReply(routes[key] ?? { body: {} });
    });

    const pendingOld = component.refreshDeviceStates();
    await component.refresh();
    expect(component.loggedIn()).toBe(false);
    await component.init();
    expect(component.loggedIn()).toBe(true);
    expect(component.session()?.subject).toBe('second-account');
    expect(component.devices().map(d => d.id)).toEqual(['new-device']);

    resolveOld!(apiReply({ body: { devices: [{ id: 'old-device', display_name: 'Previous account' }] } }));
    await pendingOld;
    fixture.detectChanges();
    expect(component.devices().map(d => d.id)).toEqual(['new-device']);
    fixture.destroy();
  });

  it('uses a native, keyboard-activatable button for workspace navigation', async () => {
    stubApi(loggedInApi);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    const brand: HTMLButtonElement = fixture.nativeElement.querySelector('button.brand');
    expect(brand).not.toBeNull();
    expect(brand.getAttribute('aria-label')).toBe('Go to workspace');

    component.view.set('browser');
    brand.click();
    expect(component.view()).toBe('workspace');
    fixture.destroy();
  });

  it('shows one prominent first-device card and no redundant add tile when empty', async () => {
    stubApi(loggedInApi);
    const fixture = await mountWorkspace();
    const host: HTMLElement = fixture.nativeElement;

    expect(host.querySelectorAll('.machine-empty')).toHaveLength(1);
    expect(host.querySelectorAll('.add-tile')).toHaveLength(0);
    expect(host.querySelectorAll('.add-link')).toHaveLength(1);
    expect(host.querySelectorAll('.round-nav')).toHaveLength(0);
    (host.querySelector('.machine-empty') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(host.querySelector('.sheet[aria-label="Add device"]')).not.toBeNull();
    expect(host.querySelector('.sheet .x-close')?.getAttribute('aria-label')).toBe('Close dialog');
    fixture.destroy();
  });

  it('shows each connected device and one compact add tile without empty onboarding', async () => {
    stubApi(loggedInApi);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    component.devices.set([{ id: 'fixture-device', display_name: 'Fixture Linux', platform: 'Linux', permission_profile: 'STANDARD', status: 'online' }]);
    fixture.detectChanges();
    const host: HTMLElement = fixture.nativeElement;
    expect(host.querySelectorAll('.machine-empty')).toHaveLength(0);
    expect(host.querySelectorAll('.device-tile:not(.add-tile)')).toHaveLength(1);
    expect(host.querySelectorAll('.add-tile')).toHaveLength(1);
    expect(host.querySelectorAll('.round-nav')).toHaveLength(0);

    component.devices.set([...component.devices(), { id: 'fixture-2', display_name: 'Fixture Windows' }]);
    fixture.detectChanges();
    expect(host.querySelectorAll('.round-nav')).toHaveLength(2);
    fixture.destroy();
  });

  it('closes the account menu with Escape without signing out', async () => {
    const { requests } = stubApi(loggedInApi);
    const fixture = await mountWorkspace();
    const component = fixture.componentInstance;
    const accountButton: HTMLButtonElement = fixture.nativeElement.querySelector('.account-trigger');
    accountButton.click();
    fixture.detectChanges();
    expect(component.accountMenu()).toBe(true);

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    fixture.detectChanges();
    expect(component.accountMenu()).toBe(false);
    expect(accountButton.getAttribute('aria-expanded')).toBe('false');
    expect(requests).not.toContain('DELETE /api/session');
    fixture.destroy();
  });
});

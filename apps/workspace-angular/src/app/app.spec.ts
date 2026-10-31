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
});

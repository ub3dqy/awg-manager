import { afterEach, describe, it, expect, vi } from 'vitest';
import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { flushSync } from 'svelte';
import { locale } from '$lib/i18n';
import UpdateSection from './UpdateSection.svelte';
import { api } from '$lib/api/client';
import type { Settings } from '$lib/types';

vi.mock('$lib/api/client', () => ({ api: { updateSettings: vi.fn() } }));
vi.mock('$lib/stores/notifications', () => ({ notifications: { success: vi.fn(), error: vi.fn() } }));
vi.mock('$lib/stores/settings', () => ({ setSettings: vi.fn() }));

const settings = {
	authEnabled: true,
	apiKey: 'old-key',
	usageLevel: 'expert',
	updates: { checkEnabled: true, channel: 'stable', autoInstallEnabled: false, autoInstallIntervalDays: 7, autoInstallTime: '05:00', statsEnabled: true },
} as unknown as Settings;

afterEach(() => { cleanup(); vi.clearAllMocks(); locale.set('ru'); });

describe('UpdateSection', () => {
	it('shows manual fork updates instead of an unverified latest-version claim', () => {
		render(UpdateSection, { settings, updateInfo: { currentVersion:'2.19.23+ub3dqy.1', available:false, checking:false, checkedAt:'', warning:'fork_manual_updates' } });
		expect(screen.getByText(/Пробная версия ub3dqy обновляется вручную/)).toBeTruthy();
		expect(screen.getByRole('link', {name:'Открыть разработку на GitHub'}).getAttribute('href')).toBe('https://github.com/ub3dqy/awg-manager');
		expect(screen.queryByRole('button', {name:'Проверить'})).toBeNull();
		expect(screen.queryByText('fork_manual_updates')).toBeNull();
		locale.set('en'); flushSync();
		expect(screen.getByText(/This ub3dqy preview is updated manually/)).toBeTruthy();
	});
	// F684: шлётся только изменённое поле, а не снимок настроек — устаревший
	// снимок другой вкладки откатил бы чужие изменения (например, apiKey).
	it('переключатель статистики шлёт только updates.statsEnabled', async () => {
		vi.mocked(api.updateSettings).mockResolvedValue(settings);
		render(UpdateSection, { settings, updateInfo: null });
		const row = screen.getByText('Анонимная статистика').parentElement?.parentElement;
		await fireEvent.click(row?.querySelector('input[type="checkbox"]') as HTMLInputElement);
		await waitFor(() => expect(api.updateSettings).toHaveBeenCalledTimes(1));
		expect(vi.mocked(api.updateSettings).mock.calls[0][0]).toEqual({ updates: { statsEnabled: false } });
	});
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpAdapter } from './http-adapter.js';

describe('HttpAdapter', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('extracts nested response text on success', async () => {
        const fetchMock = vi.fn().mockResolvedValue(
            new Response(JSON.stringify({ data: { text: 'hello' } }), {
                status: 200,
                headers: { 'content-type': 'application/json' },
            }),
        );
        vi.stubGlobal('fetch', fetchMock);

        const adapter = new HttpAdapter({
            targetUrl: 'https://example.test',
            responseField: 'data.text',
        });

        const result = await adapter.sendPrompt('ping');

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(200);
        expect(result.text).toBe('hello');
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('uses raw response body when response is not JSON', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue(
                new Response('plain text response', {
                    status: 200,
                    headers: { 'content-type': 'text/plain' },
                }),
            ),
        );

        const adapter = new HttpAdapter({ targetUrl: 'https://example.test' });
        const result = await adapter.sendPrompt('ping');

        expect(result.success).toBe(true);
        expect(result.text).toBe('plain text response');
    });

    it('returns unsuccessful result for HTTP error responses', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue(
                new Response(JSON.stringify({ response: 'nope' }), { status: 500, statusText: 'Server Error' }),
            ),
        );

        const adapter = new HttpAdapter({ targetUrl: 'https://example.test' });
        const result = await adapter.sendPrompt('ping');

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(500);
        expect(result.error).toContain('HTTP 500');
    });

    it('retries on network errors and eventually succeeds', async () => {
        const fetchMock = vi
            .fn()
            .mockRejectedValueOnce(new Error('network down'))
            .mockRejectedValueOnce(new Error('still down'))
            .mockResolvedValueOnce(new Response(JSON.stringify({ response: 'ok' }), { status: 200 }));
        vi.stubGlobal('fetch', fetchMock);

        const adapter = new HttpAdapter({
            targetUrl: 'https://example.test',
            maxRetries: 2,
            retryDelayMs: 1,
        });

        const result = await adapter.sendPrompt('ping');

        expect(fetchMock).toHaveBeenCalledTimes(3);
        expect(result.success).toBe(true);
        expect(result.text).toBe('ok');
    });

    it('returns an error after exhausting retries', async () => {
        const fetchMock = vi.fn().mockRejectedValue(new Error('network down'));
        vi.stubGlobal('fetch', fetchMock);

        const adapter = new HttpAdapter({
            targetUrl: 'https://example.test',
            maxRetries: 1,
            retryDelayMs: 1,
        });

        const result = await adapter.sendPrompt('ping');

        expect(fetchMock).toHaveBeenCalledTimes(2);
        expect(result.success).toBe(false);
        expect(result.error).toContain('failed after 2 attempts');
    });

    it('returns timeout error when request is aborted', async () => {
        const fetchMock = vi
            .fn()
            .mockRejectedValue(new DOMException('The operation was aborted.', 'AbortError'));
        vi.stubGlobal('fetch', fetchMock);

        const adapter = new HttpAdapter({
            targetUrl: 'https://example.test',
            timeoutMs: 50,
            maxRetries: 0,
        });

        const result = await adapter.sendPrompt('ping');

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(0);
        expect(result.error).toContain('timed out after 50ms');
    });
});

/**
 * mantis — HTTP Adapter
 *
 * Default LLMAdapter implementation that communicates with target
 * LLM applications over HTTP. Supports configurable request format,
 * authentication, rate limiting, retries, and timeout.
 */

import type { LLMAdapter, LLMAdapterConfig, LLMResponse } from '../types/types.js';

/**
 * Resolve a dot-notation path on an object.
 * e.g., getNestedValue({ a: { b: "hello" } }, "a.b") → "hello"
 */
function getNestedValue(obj: unknown, path: string): unknown {
    const keys = path.split('.');
    let current: unknown = obj;
    for (const key of keys) {
        if (current === null || current === undefined || typeof current !== 'object') {
            return undefined;
        }
        current = (current as Record<string, unknown>)[key];
    }
    return current;
}

/**
 * Set a value at a dot-notation path on an object.
 * e.g., setNestedValue({}, "messages.0.content", "hi") → { messages: { "0": { content: "hi" } } }
 */
function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const keys = path.split('.');
    let current: Record<string, unknown> = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        const key = keys[i];
        if (!(key in current) || typeof current[key] !== 'object') {
            current[key] = {};
        }
        current = current[key] as Record<string, unknown>;
    }
    current[keys[keys.length - 1]] = value;
}

/** Sleep for a given number of milliseconds */
function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * HttpAdapter — sends attack prompts to target LLM apps via HTTP.
 *
 * Features:
 * - Configurable request/response JSON paths
 * - Bearer token authentication
 * - Rate limiting (token bucket)
 * - Automatic retries with backoff
 * - Timeout handling
 */
export class HttpAdapter implements LLMAdapter {
    config: LLMAdapterConfig;
    private lastRequestTime = 0;
    private minRequestIntervalMs: number;

    constructor(config: Partial<LLMAdapterConfig> & { targetUrl: string }) {
        this.config = {
            targetUrl: config.targetUrl,
            method: config.method ?? 'POST',
            headers: config.headers ?? { 'Content-Type': 'application/json' },
            timeoutMs: config.timeoutMs ?? 30_000,
            maxRetries: config.maxRetries ?? 2,
            retryDelayMs: config.retryDelayMs ?? 1_000,
            rateLimit: config.rateLimit ?? 10,
            promptField: config.promptField ?? 'prompt',
            responseField: config.responseField ?? 'response',
            authToken: config.authToken,
        };

        this.minRequestIntervalMs = 1000 / this.config.rateLimit;
    }

    /**
     * Send a single prompt to the target.
     */
    async sendPrompt(prompt: string): Promise<LLMResponse> {
        await this.enforceRateLimit();

        const body: Record<string, unknown> = {};
        setNestedValue(body, this.config.promptField, prompt);

        const headers: Record<string, string> = { ...this.config.headers };
        if (this.config.authToken) {
            headers['Authorization'] = `Bearer ${this.config.authToken}`;
        }

        let lastError: Error | undefined;

        for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
            if (attempt > 0) {
                await sleep(this.config.retryDelayMs * attempt);
            }

            try {
                const startTime = Date.now();

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

                const response = await fetch(this.config.targetUrl, {
                    method: this.config.method,
                    headers,
                    body: JSON.stringify(body),
                    signal: controller.signal,
                });

                clearTimeout(timeoutId);

                const responseTimeMs = Date.now() - startTime;
                const rawBody = await response.text();

                let text = '';
                try {
                    const parsed = JSON.parse(rawBody) as unknown;
                    const extracted = getNestedValue(parsed, this.config.responseField);
                    text = typeof extracted === 'string' ? extracted : JSON.stringify(extracted);
                } catch {
                    // If response is not JSON, use raw body
                    text = rawBody;
                }

                const responseHeaders: Record<string, string> = {};
                response.headers.forEach((value, key) => {
                    responseHeaders[key] = value;
                });

                return {
                    statusCode: response.status,
                    headers: responseHeaders,
                    rawBody,
                    text,
                    responseTimeMs,
                    success: response.ok,
                    error: response.ok ? undefined : `HTTP ${response.status}: ${response.statusText}`,
                };
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));

                if (error instanceof DOMException && error.name === 'AbortError') {
                    return {
                        statusCode: 0,
                        headers: {},
                        rawBody: '',
                        text: '',
                        responseTimeMs: this.config.timeoutMs,
                        success: false,
                        error: `Request timed out after ${this.config.timeoutMs}ms`,
                    };
                }

                // Retry on network errors
                if (attempt < this.config.maxRetries) continue;
            }
        }

        return {
            statusCode: 0,
            headers: {},
            rawBody: '',
            text: '',
            responseTimeMs: 0,
            success: false,
            error: `Request failed after ${this.config.maxRetries + 1} attempts: ${lastError?.message}`,
        };
    }

    /**
     * Send multiple prompts in sequence with rate limiting.
     */
    async sendBatch(prompts: string[]): Promise<LLMResponse[]> {
        const responses: LLMResponse[] = [];
        for (const prompt of prompts) {
            const response = await this.sendPrompt(prompt);
            responses.push(response);
        }
        return responses;
    }

    /**
     * Test connectivity to the target.
     */
    async healthCheck(): Promise<boolean> {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5_000);

            const response = await fetch(this.config.targetUrl, {
                method: 'HEAD',
                signal: controller.signal,
            });

            clearTimeout(timeoutId);
            return response.status < 500;
        } catch {
            return false;
        }
    }

    /**
     * Enforce rate limiting between requests.
     */
    private async enforceRateLimit(): Promise<void> {
        const now = Date.now();
        const elapsed = now - this.lastRequestTime;

        if (elapsed < this.minRequestIntervalMs) {
            await sleep(this.minRequestIntervalMs - elapsed);
        }

        this.lastRequestTime = Date.now();
    }
}

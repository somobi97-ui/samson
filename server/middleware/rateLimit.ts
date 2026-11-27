import type { NextFunction, Request, Response } from 'express';
import { hashIdentifier, logger } from '../services/logger.ts';

interface RateBucket {
  count: number;
  resetAt: number;
}

export interface RateLimitOptions {
  name: string;
  windowMs: number;
  maxRequests: number;
}

const stores = new Map<string, Map<string, RateBucket>>();

export function resetRateLimitStores(): void {
  for (const store of stores.values()) {
    store.clear();
  }
}

function getClientIp(req: Request): string {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  return ip.replace(/^::ffff:/, '');
}

function consumeBucket(
  store: Map<string, RateBucket>,
  key: string,
  windowMs: number,
  maxRequests: number,
  now: number,
): { allowed: boolean; remaining: number; resetAt: number } {
  if (store.size > 5000) {
    for (const [k, b] of store.entries()) {
      if (now >= b.resetAt) store.delete(k);
    }
  }

  const existing = store.get(key);
  if (!existing || now >= existing.resetAt) {
    const fresh: RateBucket = { count: 1, resetAt: now + windowMs };
    store.set(key, fresh);
    return {
      allowed: true,
      remaining: Math.max(0, maxRequests - 1),
      resetAt: fresh.resetAt,
    };
  }

  if (existing.count >= maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: existing.resetAt,
    };
  }

  existing.count += 1;
  return {
    allowed: true,
    remaining: Math.max(0, maxRequests - existing.count),
    resetAt: existing.resetAt,
  };
}

export function createRateLimiter(options: RateLimitOptions) {
  let store = stores.get(options.name);
  if (!store) {
    store = new Map<string, RateBucket>();
    stores.set(options.name, store);
  }

  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    const clientIp = getClientIp(req);
    const key = `ip:${clientIp}`;
    const outcome = consumeBucket(store, key, options.windowMs, options.maxRequests, now);

    if (!outcome.allowed) {
      const retryAfterSec = Math.max(1, Math.ceil((outcome.resetAt - now) / 1000));
      logger.warn('rate_limit.exceeded', {
        requestId: (req as Request & { requestId?: string }).requestId,
        limiter: options.name,
        clientIpHash: hashIdentifier(clientIp),
        retryAfterSec,
      });
      res.setHeader('RateLimit-Limit', String(options.maxRequests));
      res.setHeader('RateLimit-Remaining', '0');
      res.setHeader('RateLimit-Reset', String(retryAfterSec));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.status(429).json({
        error: `Rate limit exceeded for ${options.name}. Try again in ${retryAfterSec}s.`,
      });
      return;
    }

    const resetSec = Math.max(1, Math.ceil((outcome.resetAt - now) / 1000));
    res.setHeader('RateLimit-Limit', String(options.maxRequests));
    res.setHeader('RateLimit-Remaining', String(outcome.remaining));
    res.setHeader('RateLimit-Reset', String(resetSec));
    next();
  };
}

import { QueryClient } from '@tanstack/react-query';
import { createRouter } from '@tanstack/react-router';
import { describe, expect, it } from 'vitest';
import { routeTree } from '@/routeTree.gen';
describe('Minimal scanner routing', () => {
  const router = createRouter({ routeTree, context: { queryClient: new QueryClient() } });
  it('keeps the scanner at /', () => { expect(router.matchRoutes('/').at(-1)?.routeId).toBe('/'); });
  it.each(['/scans', '/scans/new', '/scans/example', '/settings'])('removes feature page %s', path => {
    expect(router.matchRoutes(path).some(match => match.routeId !== '__root__')).toBe(false);
  });
});

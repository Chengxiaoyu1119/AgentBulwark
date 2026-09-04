export function isAbortError(error: unknown) {
  return (
    (error instanceof DOMException && error.name === 'AbortError') ||
    (typeof error === 'object' && error !== null && 'name' in error && error.name === 'AbortError')
  );
}

export function linkAbortSignal(source: AbortSignal | null | undefined, target: AbortController) {
  if (!source) return () => undefined;

  const abortTarget = () => target.abort();
  if (source.aborted) {
    abortTarget();
    return () => undefined;
  }

  source.addEventListener('abort', abortTarget, { once: true });
  return () => source.removeEventListener('abort', abortTarget);
}

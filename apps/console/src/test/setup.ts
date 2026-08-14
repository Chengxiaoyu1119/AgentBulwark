import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false
  })
});

class TestResizeObserver implements ResizeObserver {
  observe() {
    // jsdom does not lay out elements, but Ant Design expects ResizeObserver to exist.
  }

  unobserve() {
    // See observe().
  }

  disconnect() {
    // See observe().
  }
}

Object.defineProperty(window, 'ResizeObserver', {
  writable: true,
  value: TestResizeObserver
});

const nativeGetComputedStyle = window.getComputedStyle.bind(window);
Object.defineProperty(window, 'getComputedStyle', {
  writable: true,
  value: (element: Element, pseudoElement?: string | null) =>
    nativeGetComputedStyle(element, pseudoElement ? undefined : pseudoElement)
});

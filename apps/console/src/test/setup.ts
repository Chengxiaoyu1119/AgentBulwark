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
const zeroLengthProperties = new Set([
  'padding-top',
  'padding-right',
  'padding-bottom',
  'padding-left',
  'border-top-width',
  'border-right-width',
  'border-bottom-width',
  'border-left-width'
]);
Object.defineProperty(window, 'getComputedStyle', {
  writable: true,
  value: (element: Element, pseudoElement?: string | null) => {
    const style = nativeGetComputedStyle(element, pseudoElement ? undefined : pseudoElement);
    // jsdom does not resolve Ant Design's CSS variables and returns an empty
    // string for a few box-model properties. rc-textarea parses these values
    // as numbers while calculating autoSize, so an empty string becomes NaN
    // and React emits an invalid inline height warning. Keep the browser
    // values untouched and provide only the mathematically neutral fallback.
    return new Proxy(style, {
      get(target, property, receiver) {
        if (property === 'getPropertyValue') {
          return (name: string) => {
            const value = target.getPropertyValue(name);
            return value.trim() === '' && zeroLengthProperties.has(name) ? '0px' : value;
          };
        }
        return Reflect.get(target, property, receiver);
      }
    });
  }
});

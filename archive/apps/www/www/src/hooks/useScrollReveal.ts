import { useEffect } from 'react';

export function useScrollReveal() {
  useEffect(() => {
    const sections = Array.from(document.querySelectorAll<HTMLElement>('[data-scroll-fx]'));
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          entry.target.classList.toggle('is-inview', entry.isIntersecting);
        });
      },
      { rootMargin: '-18% 0px -18% 0px', threshold: 0.18 }
    );

    sections.forEach((section) => observer.observe(section));

    return () => observer.disconnect();
  }, []);
}

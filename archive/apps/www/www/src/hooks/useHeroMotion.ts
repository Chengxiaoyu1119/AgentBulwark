import { useEffect } from 'react';

export function useHeroMotion() {
  useEffect(() => {
    let frame = 0;

    const updateHeroMotion = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => {
        const scrollY = window.scrollY;
        const progress = Math.min(1, scrollY / Math.max(1, window.innerHeight * 0.92));
        const root = document.documentElement;

        root.style.setProperty('--hero-y', `${progress * -26}px`);
        root.style.setProperty('--hero-scale', `${1 - progress * 0.035}`);
        root.style.setProperty('--hero-opacity', `${1 - progress * 0.18}`);
        root.style.setProperty('--bg-shift', `${scrollY * -0.035}px`);
      });
    };

    updateHeroMotion();
    window.addEventListener('scroll', updateHeroMotion, { passive: true });
    window.addEventListener('resize', updateHeroMotion);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener('scroll', updateHeroMotion);
      window.removeEventListener('resize', updateHeroMotion);
    };
  }, []);
}

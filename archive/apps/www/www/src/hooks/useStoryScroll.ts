import { useEffect, useState } from 'react';

export function useStoryScroll(storyCount: number) {
  const [storyIndex, setStoryIndex] = useState(0);

  useEffect(() => {
    const updateStory = () => {
      const section = document.querySelector<HTMLElement>('[data-story-scroll]');
      if (!section || storyCount <= 0) return;

      const rect = section.getBoundingClientRect();
      const progress = Math.min(1, Math.max(0, -rect.top / Math.max(1, rect.height - window.innerHeight)));
      setStoryIndex(Math.min(storyCount - 1, Math.floor(progress * storyCount)));
    };

    updateStory();
    window.addEventListener('scroll', updateStory, { passive: true });
    window.addEventListener('resize', updateStory);

    return () => {
      window.removeEventListener('scroll', updateStory);
      window.removeEventListener('resize', updateStory);
    };
  }, [storyCount]);

  return storyIndex;
}

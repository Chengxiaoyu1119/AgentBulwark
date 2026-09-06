import type { CardItem } from '../../content';
import { ReferenceCardStack } from './ReferenceCardStack';

type StickyStorySectionProps = {
  storyCards: CardItem[];
  storyIndex: number;
};

export function StickyStorySection({ storyCards, storyIndex }: StickyStorySectionProps) {
  const activeStory = storyCards[storyIndex] ?? storyCards[0];

  if (!activeStory) return null;

  return (
    <section className="landing-section sticky-story" data-story-scroll data-story-index={storyIndex}>
      <div className="story-pin">
        <div className="story-copy">
          <p>{activeStory.title}</p>
          <h2>滚动时，监督链路逐步展开。</h2>
          <p>{activeStory.body}</p>
          <div className="story-dots" aria-hidden="true">
            {storyCards.map((item, index) => (
              <span key={item.title} className={index === storyIndex ? 'active' : ''} />
            ))}
          </div>
        </div>
        <ReferenceCardStack cards={storyCards} activeIndex={storyIndex} tone="story" />
      </div>
    </section>
  );
}

import type { FeatureSectionContent } from '../../content';
import { LineTitle } from './LineTitle';
import { ReferenceCardStack } from './ReferenceCardStack';

type FeatureSectionProps = {
  feature: FeatureSectionContent;
};

export function FeatureSection({ feature }: FeatureSectionProps) {
  return (
    <section
      className={`landing-section feature-section ${feature.reverse ? 'reverse' : ''}`}
      id={feature.id}
      data-scroll-fx
    >
      <div className="feature-copy">
        <span>{feature.eyebrow}</span>
        <h2>
          <LineTitle lines={feature.titleLines} />
        </h2>
        <p>{feature.body}</p>
      </div>
      <div className="feature-visual">
        <ReferenceCardStack cards={feature.cards} tone={feature.tone} />
      </div>
    </section>
  );
}

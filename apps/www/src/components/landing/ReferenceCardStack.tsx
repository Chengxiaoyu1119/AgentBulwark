import { CheckCircle2, ShieldCheck } from 'lucide-react';
import type { CardItem } from '../../content';

type ReferenceCardStackProps = {
  cards: CardItem[];
  tone: string;
  activeIndex?: number;
};

export function ReferenceCardStack({ cards, tone, activeIndex = 0 }: ReferenceCardStackProps) {
  return (
    <div className={`reference-card-stack reference-card-stack--${tone}`} aria-label="信息卡片">
      {cards.map((card, index) => (
        <article
          className={`reference-card reference-card-${index + 1} ${index === activeIndex ? 'active' : ''}`}
          key={card.title}
        >
          <small>{card.meta}</small>
          <strong>{card.title}</strong>
          <p>{card.body}</p>
          {index === activeIndex ? (
            <span>
              <CheckCircle2 size={15} />
              当前重点
            </span>
          ) : null}
        </article>
      ))}
      <ShieldCheck className="reference-card-mark" size={38} aria-hidden="true" />
    </div>
  );
}

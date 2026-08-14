import { ArrowRight } from 'lucide-react';
import { finalContent } from '../../content';

type FinalSectionProps = {
  consoleUrl: string;
  docsUrl: string;
};

export function FinalSection({ consoleUrl, docsUrl }: FinalSectionProps) {
  return (
    <section className="landing-section final-section" data-scroll-fx>
      <div className="final-copy">
        <p>{finalContent.eyebrow}</p>
        <h2>{finalContent.title}</h2>
        <div className="hero-actions">
          <a className="site-button site-button--primary" href={consoleUrl}>
            进入控制台
            <ArrowRight size={18} />
          </a>
          <a className="site-button site-button--soft" href={docsUrl}>
            打开接入文档
          </a>
        </div>
      </div>
    </section>
  );
}

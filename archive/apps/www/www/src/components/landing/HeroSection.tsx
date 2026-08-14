import { Play } from 'lucide-react';
import { heroContent } from '../../content';

type HeroSectionProps = {
  consoleUrl: string;
  docsUrl: string;
  repoUrl: string;
};

export function HeroSection({ consoleUrl, docsUrl, repoUrl }: HeroSectionProps) {
  return (
    <section className="landing-section hero-section" id="top" data-scroll-fx>
      <div className="hero-center">
        <p className="hero-kicker">{heroContent.kicker}</p>
        <h1>{heroContent.title}</h1>
        <p className="hero-subtitle">{heroContent.subtitle}</p>
        <div className="hero-actions">
          <a className="site-button site-button--primary" href={consoleUrl}>
            <Play size={18} />
            进入控制台
          </a>
          <a className="site-button site-button--soft" href={docsUrl}>
            查看文档
          </a>
          <a className="site-button site-button--link" href={repoUrl} target="_blank" rel="noreferrer">
            GitHub 仓库
          </a>
        </div>
      </div>
    </section>
  );
}

import { featureSections, siteLinks, storyCards } from '../content';
import { FeatureSection } from '../components/landing/FeatureSection';
import { FinalSection } from '../components/landing/FinalSection';
import { FoliaBackground } from '../components/landing/FoliaBackground';
import { HeroSection } from '../components/landing/HeroSection';
import { StickyStorySection } from '../components/landing/StickyStorySection';
import { Header } from '../components/site/Header';
import type { ThemeMode } from '../hooks/useThemeMode';

type LandingPageProps = {
  theme: ThemeMode;
  storyIndex: number;
  onToggleTheme: () => void;
};

export function LandingPage({ theme, storyIndex, onToggleTheme }: LandingPageProps) {
  return (
    <div className="site-shell">
      <Header
        theme={theme}
        consoleUrl={siteLinks.consoleUrl}
        repoUrl={siteLinks.repoUrl}
        onToggleTheme={onToggleTheme}
      />
      <FoliaBackground />

      <main>
        <HeroSection consoleUrl={siteLinks.consoleUrl} docsUrl={siteLinks.docsUrl} repoUrl={siteLinks.repoUrl} />
        {featureSections.slice(0, 3).map((feature) => (
          <FeatureSection key={feature.id} feature={feature} />
        ))}
        <StickyStorySection storyCards={storyCards} storyIndex={storyIndex} />
        <FeatureSection feature={featureSections[3]} />
        <FinalSection consoleUrl={siteLinks.consoleUrl} docsUrl={siteLinks.docsUrl} />
      </main>
    </div>
  );
}

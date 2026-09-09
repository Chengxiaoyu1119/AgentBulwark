import { storyCards } from './content';
import { useHeroMotion } from './hooks/useHeroMotion';
import { useScrollReveal } from './hooks/useScrollReveal';
import { useStoryScroll } from './hooks/useStoryScroll';
import { useThemeMode } from './hooks/useThemeMode';
import { LandingPage } from './pages/LandingPage';

export function App() {
  const { theme, toggleTheme } = useThemeMode();
  const storyIndex = useStoryScroll(storyCards.length);

  useScrollReveal();
  useHeroMotion();

  return <LandingPage theme={theme} storyIndex={storyIndex} onToggleTheme={toggleTheme} />;
}

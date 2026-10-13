import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Moon, Sun, Menu, X, Chrome, Github } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

export const Navbar: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  const isActive = (path: string) => location.pathname === path;

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand Logo */}
        <Link to="/" className="flex items-center space-x-2.5 group">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-surface border border-border group-hover:border-accent transition-colors shadow-sm">
            <Shield className="h-5 w-5 text-accent group-hover:scale-105 transition-transform" />
          </div>
          <div className="flex flex-col">
            <span className="text-base font-semibold tracking-tight text-text-primary">RevShield</span>
            <span className="text-[10px] uppercase font-mono tracking-widest text-text-muted -mt-1">Intelligence</span>
          </div>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center space-x-8">
          <Link
            to="/"
            className={`text-sm font-medium transition-colors ${
              isActive('/') ? 'text-text-primary font-semibold' : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            Analyze
          </Link>
          <Link
            to="/extension"
            className={`text-sm font-medium flex items-center space-x-1.5 transition-colors ${
              isActive('/extension') ? 'text-text-primary font-semibold' : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Chrome className="h-4 w-4" />
            <span>Extension</span>
          </Link>
          <a
            href="https://github.com/ifshreyas/RevShield"
            target="_blank"
            rel="noreferrer"
            className="text-sm font-medium text-text-secondary hover:text-text-primary flex items-center space-x-1.5 transition-colors"
          >
            <Github className="h-4 w-4" />
            <span>GitHub</span>
          </a>
        </nav>

        {/* Right Controls (Theme Toggle) */}
        <div className="hidden md:flex items-center space-x-4">
          <button
            onClick={toggleTheme}
            aria-label="Toggle theme"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-text-secondary hover:text-text-primary hover:border-border-focus transition-colors"
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
        </div>

        {/* Mobile Hamburger Button */}
        <div className="flex items-center space-x-2 md:hidden">
          <button
            onClick={toggleTheme}
            aria-label="Toggle theme"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-text-secondary"
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle mobile menu"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-text-primary"
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="md:hidden border-b border-border bg-surface px-4 py-4 space-y-3">
          <Link
            to="/"
            onClick={() => setMobileOpen(false)}
            className="block text-sm font-medium text-text-primary py-1.5"
          >
            Analyze Website
          </Link>
          <Link
            to="/extension"
            onClick={() => setMobileOpen(false)}
            className="block text-sm font-medium text-text-primary py-1.5 flex items-center space-x-2"
          >
            <Chrome className="h-4 w-4" />
            <span>Browser Extension</span>
          </Link>
          <a
            href="https://github.com/ifshreyas/RevShield"
            target="_blank"
            rel="noreferrer"
            onClick={() => setMobileOpen(false)}
            className="block text-sm font-medium text-text-primary py-1.5 flex items-center space-x-2"
          >
            <Github className="h-4 w-4" />
            <span>GitHub Repository</span>
          </a>
        </div>
      )}
    </header>
  );
};

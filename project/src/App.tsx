import React, { useState, useEffect } from 'react';
import { 
  Menu, 
  X, 
  Code, 
  Zap, 
  Users, 
  Award, 
  ArrowRight,
  Github,
  Mail,
  Phone,
  MapPin,
  Check,
  Star,
  ExternalLink,
  ChevronDown,
  Shield,
  Clock,
  Eye,
  Settings,
  Video,
  Scissors,
  Film,
  Calendar,
  Send,
  Instagram,
  Youtube,
  Twitter,
  Facebook,
  Linkedin,
  Play,
  Home,
  User,
  FileText,
  DollarSign,
  Moon,
  Sun
} from 'lucide-react';
import { Spotlight } from '@/components/ui/spotlight';
import { GlowCard } from '@/components/ui/spotlight-card';
import { ExpandableTabs } from '@/components/ui/expandable-tabs';
import { Footer } from '@/components/ui/footer';

function App() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('home');
  const [isDarkMode, setIsDarkMode] = useState(true);

  useEffect(() => {
    const handleScroll = () => {
      const sections = ['home', 'about', 'connect', 'featured-projects', 'pricing', 'contact'];
      const scrollPosition = window.scrollY + 100;

      for (const section of sections) {
        const element = document.getElementById(section);
        if (element) {
          const offsetTop = element.offsetTop;
          const offsetBottom = offsetTop + element.offsetHeight;

          if (scrollPosition >= offsetTop && scrollPosition < offsetBottom) {
            setActiveSection(section);
            break;
          }
        }
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
    setIsMenuOpen(false);
  };

  const toggleTheme = () => {
    setIsDarkMode(!isDarkMode);
  };

  // Navigation tabs configuration with updated names - removed separators
  const navigationTabs = [
    { title: "Home", icon: Home },
    { title: "About", icon: User },
    { title: "Connection", icon: Mail },
    { title: "Projects", icon: FileText },
    { title: "Pricing", icon: DollarSign },
    { title: "Contact", icon: Phone },
  ];

  // Get current active tab index based on active section
  const getActiveTabIndex = () => {
    const sectionToTabMap: { [key: string]: number } = {
      'home': 0,
      'about': 1,
      'connect': 2,
      'featured-projects': 3,
      'pricing': 4,
      'contact': 5
    };
    
    const tabIndex = sectionToTabMap[activeSection];
    return tabIndex !== undefined ? tabIndex : null;
  };

  const handleTabChange = (index: number | null) => {
    if (index === null) return;
    
    const selectedTab = navigationTabs[index];
    
    if (selectedTab) {
      const sectionMap: { [key: string]: string } = {
        'Home': 'home',
        'About': 'about',
        'Connection': 'connect',
        'Projects': 'featured-projects',
        'Pricing': 'pricing',
        'Contact': 'contact'
      };
      
      const sectionId = sectionMap[selectedTab.title];
      if (sectionId) {
        scrollToSection(sectionId);
      }
    }
  };

  return (
    <div className={isDarkMode ? "bg-black text-white" : "bg-white text-black"}>
      {/* Navigation */}
      <nav className={`fixed top-0 w-full z-50 backdrop-blur-sm border-b ${
        isDarkMode 
          ? "bg-black/80 border-white/10" 
          : "bg-white/80 border-black/10"
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className={`text-2xl font-bold ${
              isDarkMode ? "text-white" : "text-black"
            }`}>
              SakethSirX
            </div>
            
            {/* Desktop Navigation - ExpandableTabs - Centered */}
            <div className="hidden md:flex justify-center flex-1 mx-8">
              <ExpandableTabs 
                tabs={navigationTabs}
                activeColor={isDarkMode ? "text-blue-400" : "text-blue-600"}
                onChange={handleTabChange}
                activeTabIndex={getActiveTabIndex()}
                isDarkMode={isDarkMode}
                className={`border backdrop-blur-md ${
                  isDarkMode 
                    ? "border-white/20 bg-white/5" 
                    : "border-black/20 bg-black/5"
                }`}
              />
            </div>

            {/* Right Side Buttons */}
            <div className="hidden md:flex items-center gap-4">
              {/* Theme Toggle Button */}
              <button 
                onClick={toggleTheme}
                className={`w-10 h-10 rounded-lg flex items-center justify-center transition-colors duration-300 group backdrop-blur-sm border ${
                  isDarkMode 
                    ? "bg-white/10 hover:bg-white/20 border-white/10" 
                    : "bg-black/10 hover:bg-black/20 border-black/10"
                }`}
              >
                {isDarkMode ? (
                  <Sun size={18} className="text-white/70 group-hover:text-white" />
                ) : (
                  <Moon size={18} className="text-black/70 group-hover:text-black" />
                )}
              </button>
              
              {/* Sign In / Sign Up Button */}
              <button className={`px-6 py-2.5 rounded-lg font-medium transition-all duration-300 border backdrop-blur-sm ${
                isDarkMode 
                  ? "bg-white/10 hover:bg-white/20 text-white border-white/20 hover:border-white/30" 
                  : "bg-black/10 hover:bg-black/20 text-black border-black/20 hover:border-black/30"
              }`}>
                Sign In / Sign Up
              </button>
            </div>

            {/* Mobile Menu Button */}
            <button
              className={`md:hidden ${isDarkMode ? "text-white" : "text-black"}`}
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className={`md:hidden backdrop-blur-md border-t ${
            isDarkMode 
              ? "bg-black/90 border-white/10" 
              : "bg-white/90 border-black/10"
          }`}>
            <div className="px-4 py-4 space-y-4">
              {['home', 'about', 'connect', 'featured-projects', 'pricing', 'contact'].map((section) => (
                <button
                  key={section}
                  onClick={() => scrollToSection(section)}
                  className={`block w-full text-left capitalize transition-colors duration-200 ${
                    isDarkMode 
                      ? "text-gray-300 hover:text-blue-400" 
                      : "text-gray-700 hover:text-blue-600"
                  }`}
                >
                  {section === 'connect' ? 'Connection' : 
                   section === 'featured-projects' ? 'Projects' : section}
                </button>
              ))}
              
              {/* Mobile Theme Toggle */}
              <div className={`pt-4 border-t ${isDarkMode ? "border-white/10" : "border-black/10"}`}>
                <button 
                  onClick={toggleTheme}
                  className={`w-full px-6 py-3 rounded-lg font-medium transition-all duration-300 border backdrop-blur-sm flex items-center justify-center gap-2 ${
                    isDarkMode 
                      ? "bg-white/10 hover:bg-white/20 text-white border-white/20" 
                      : "bg-black/10 hover:bg-black/20 text-black border-black/20"
                  }`}
                >
                  {isDarkMode ? <Sun size={18} /> : <Moon size={18} />}
                  {isDarkMode ? "Light Mode" : "Dark Mode"}
                </button>
              </div>
              
              {/* Mobile Sign In Button */}
              <div>
                <button className={`w-full px-6 py-3 rounded-lg font-medium transition-all duration-300 border backdrop-blur-sm ${
                  isDarkMode 
                    ? "bg-white/10 hover:bg-white/20 text-white border-white/20" 
                    : "bg-black/10 hover:bg-black/20 text-black border-black/20"
                }`}>
                  Sign In / Sign Up
                </button>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Welcome Badge - Fixed position below navigation */}
      <div className="fixed top-20 left-1/2 transform -translate-x-1/2 z-40 mt-6">
        <div className={`inline-flex items-center gap-2 border rounded-full px-6 py-2 backdrop-blur-sm hover:bg-opacity-80 transition-colors duration-300 ${
          isDarkMode 
            ? "bg-gray-900/80 border-gray-700/50 text-white" 
            : "bg-gray-100/80 border-gray-300/50 text-black"
        }`}>
          <Star size={16} className={isDarkMode ? "text-white" : "text-black"} />
          <span className="text-sm font-medium">Welcome, stranger no more — your story now lives here too</span>
        </div>
      </div>

      {/* Hero Section */}
      <section id="home" className={`min-h-screen flex items-center justify-center relative overflow-hidden antialiased ${
        isDarkMode ? "bg-black" : "bg-white"
      }`}>
        {isDarkMode && (
          <Spotlight
            className="-top-40 left-0 md:left-60 md:-top-20"
            fill="white"
          />
        )}
        
        <div className="relative z-10 text-center px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full pt-32">
          {/* Main Heading */}
          <h1 className={`text-4xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight ${
            isDarkMode ? "text-white" : "text-black"
          }`}>
            This is Sakethsirx
          </h1>

          {/* Subtitle */}
          <h2 className={`text-xl md:text-2xl lg:text-3xl mb-6 font-medium ${
            isDarkMode ? "text-gray-300" : "text-gray-700"
          }`}>
            Your editor for turning memories into magic
          </h2>

          {/* Description */}
          <p className={`text-base md:text-lg max-w-2xl mx-auto mb-12 leading-relaxed ${
            isDarkMode ? "text-gray-400" : "text-gray-600"
          }`}>
            Every pixel holds intent, and every frame speaks emotion. From concept to creation, we craft experiences that truly connect.
          </p>

          {/* Hashtags */}
          <div className={`flex flex-wrap justify-center gap-4 mb-12 text-sm ${
            isDarkMode ? "text-gray-500" : "text-gray-500"
          }`}>
            <span>#sakethsirx</span>
            <span>#sakethsirxae</span>
            <span>#sirxedits</span>
            <span>#editedbysakethsirx</span>
          </div>

          {/* Statistics */}
          <div className="grid grid-cols-3 gap-8 mb-12 max-w-2xl mx-auto">
            <div className="text-center">
              <div className={`text-3xl md:text-4xl font-bold mb-2 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>100+</div>
              <div className={`text-sm ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}>Projects Delivered</div>
            </div>
            <div className="text-center">
              <div className={`text-3xl md:text-4xl font-bold mb-2 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>50+</div>
              <div className={`text-sm ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}>Happy Clients</div>
            </div>
            <div className="text-center">
              <div className={`text-3xl md:text-4xl font-bold mb-2 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>5+</div>
              <div className={`text-sm ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}>Years Experience</div>
            </div>
          </div>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-16">
            <button 
              onClick={() => scrollToSection('contact')}
              className={`px-8 py-3 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 ${
                isDarkMode 
                  ? "bg-white text-black hover:bg-gray-100" 
                  : "bg-black text-white hover:bg-gray-800"
              }`}
            >
              Order your own! →
            </button>
            <button 
              onClick={() => scrollToSection('about')}
              className={`border px-8 py-3 rounded-lg font-semibold transition-all duration-300 hover:bg-opacity-50 flex items-center justify-center gap-2 ${
                isDarkMode 
                  ? "border-gray-600 hover:border-gray-400 text-white hover:bg-gray-800/50" 
                  : "border-gray-400 hover:border-gray-600 text-black hover:bg-gray-200/50"
              }`}
            >
              <Code size={16} />
              View Portfolio
            </button>
          </div>

          {/* Animated Feature Cards */}
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-6xl mx-auto">
            <GlowCard 
              glowColor="blue" 
              customSize={true} 
              className="w-full h-auto min-h-[280px] animate-fade-in-up"
              style={{ animationDelay: '0.1s' }}
            >
              <div className="flex flex-col h-full">
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 ${
                  isDarkMode ? "bg-gray-800" : "bg-gray-200"
                }`}>
                  <Shield size={24} className="text-blue-400" />
                </div>
                <h3 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Client Privacy</h3>
                <p className={`text-sm leading-relaxed flex-grow ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>
                  Your clips, your story — handled with complete confidentiality. Every project stays secure and personal.
                </p>
              </div>
            </GlowCard>

            <GlowCard 
              glowColor="purple" 
              customSize={true} 
              className="w-full h-auto min-h-[280px] animate-fade-in-up"
              style={{ animationDelay: '0.2s' }}
            >
              <div className="flex flex-col h-full">
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 ${
                  isDarkMode ? "bg-gray-800" : "bg-gray-200"
                }`}>
                  <Settings size={24} className="text-purple-400" />
                </div>
                <h3 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>High-Quality Edits</h3>
                <p className={`text-sm leading-relaxed flex-grow ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>
                  Each frame is carefully cut, colored, and crafted to deliver cinematic, emotion-rich edits that stand out.
                </p>
              </div>
            </GlowCard>

            <GlowCard 
              glowColor="green" 
              customSize={true} 
              className="w-full h-auto min-h-[280px] animate-fade-in-up"
              style={{ animationDelay: '0.3s' }}
            >
              <div className="flex flex-col h-full">
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 ${
                  isDarkMode ? "bg-gray-800" : "bg-gray-200"
                }`}>
                  <Clock size={24} className="text-green-400" />
                </div>
                <h3 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>On-Time Delivery</h3>
                <p className={`text-sm leading-relaxed flex-grow ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>
                  No delays, no excuses. I respect your time and guarantee timely delivery without compromising quality.
                </p>
              </div>
            </GlowCard>

            <GlowCard 
              glowColor="orange" 
              customSize={true} 
              className="w-full h-auto min-h-[280px] animate-fade-in-up"
              style={{ animationDelay: '0.4s' }}
            >
              <div className="flex flex-col h-full">
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 ${
                  isDarkMode ? "bg-gray-800" : "bg-gray-200"
                }`}>
                  <Eye size={24} className="text-orange-400" />
                </div>
                <h3 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Transparent Process</h3>
                <p className={`text-sm leading-relaxed flex-grow ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>
                  Want to see how your story comes to life? I openly share my editing process when requested — full transparency, no secrets.
                </p>
              </div>
            </GlowCard>
          </div>
        </div>
      </section>

      {/* About Section */}
      <section id="about" className={`py-20 ${isDarkMode ? "bg-black" : "bg-white"}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className={`text-4xl sm:text-5xl font-bold mb-4 ${
              isDarkMode ? "text-white" : "text-black"
            }`}>
              About <span className="text-red-500">sakethsirx</span>
            </h2>
            <p className={`text-xl max-w-3xl mx-auto ${
              isDarkMode ? "text-gray-400" : "text-gray-600"
            }`}>
              I'm not just an editor — I edit your story, As you dreamed !!
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-12 items-center">
            {/* Profile Image */}
            <div className="relative">
              <div className={`rounded-2xl overflow-hidden aspect-[4/5] max-w-md mx-auto ${
                isDarkMode ? "bg-gray-800" : "bg-gray-200"
              }`}>
                <img 
                  src="/logo saketh.jpg" 
                  alt="Sakethsirx Profile"
                  className="w-full h-full object-cover"
                />
              </div>
            </div>

            {/* About Content */}
            <div className="space-y-8">
              <div>
                <p className={`text-lg leading-relaxed mb-6 ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}>
                  At sakethsirx, I transform raw footage into meaningful visual experiences. From cinematic reels to memory-rich montages, every edit is crafted with purpose and emotion.
                </p>
                <p className={`text-lg leading-relaxed ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}>
                  What sets my work apart is a clear creative vision, attention to detail, and a process that values your story as much as the final result. Here, your clips aren't just edited — they're understood.
                </p>
              </div>

              {/* Software Cards */}
              <div className="grid grid-cols-2 gap-6">
                <div className={`border rounded-xl p-6 ${
                  isDarkMode 
                    ? "bg-gray-900/50 border-gray-800" 
                    : "bg-gray-50/50 border-gray-200"
                }`}>
                  <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 ${
                    isDarkMode ? "bg-gray-800" : "bg-gray-200"
                  }`}>
                    <Film size={24} className="text-blue-400" />
                  </div>
                  <h3 className={`font-semibold mb-2 ${
                    isDarkMode ? "text-white" : "text-black"
                  }`}>Adobe Premiere Pro</h3>
                  <p className={`text-sm ${
                    isDarkMode ? "text-gray-400" : "text-gray-600"
                  }`}>
                    Precision editing, seamless transitions, and storytelling control — built for creators who value flow and feel.
                  </p>
                </div>

                <div className={`border rounded-xl p-6 ${
                  isDarkMode 
                    ? "bg-gray-900/50 border-gray-800" 
                    : "bg-gray-50/50 border-gray-200"
                }`}>
                  <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 ${
                    isDarkMode ? "bg-gray-800" : "bg-gray-200"
                  }`}>
                    <Zap size={24} className="text-purple-400" />
                  </div>
                  <h3 className={`font-semibold mb-2 ${
                    isDarkMode ? "text-white" : "text-black"
                  }`}>Adobe After Effects</h3>
                  <p className={`text-sm ${
                    isDarkMode ? "text-gray-400" : "text-gray-600"
                  }`}>
                    Where motion meets magic. I use After Effects to add energy, emotion, and visual impact to your content.
                  </p>
                </div>
              </div>

              {/* CTA Button */}
              <button 
                onClick={() => scrollToSection('connect')}
                className={`px-8 py-3 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 flex items-center gap-2 ${
                  isDarkMode 
                    ? "bg-white text-black hover:bg-gray-100" 
                    : "bg-black text-white hover:bg-gray-800"
                }`}
              >
                <Zap size={16} />
                Let's Work Together
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Connect with sakethsirx Section */}
      <section id="connect" className={`py-20 ${isDarkMode ? "bg-black" : "bg-white"}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className={`text-4xl sm:text-5xl font-bold mb-16 ${
              isDarkMode ? "text-white" : "text-black"
            }`}>
              Let's Get in <span className="text-red-500">Touch</span>
            </h2>
            
            {/* Social Media Icons */}
            <div className="flex justify-center items-center gap-8">
              <a 
                href="#" 
                className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 group ${
                  isDarkMode 
                    ? "bg-gray-800 hover:bg-gray-700" 
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
              >
                <Instagram size={24} className={`group-hover:text-pink-500 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`} />
              </a>
              
              <a 
                href="#" 
                className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 group ${
                  isDarkMode 
                    ? "bg-gray-800 hover:bg-gray-700" 
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
              >
                <Youtube size={24} className={`group-hover:text-red-500 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`} />
              </a>
              
              <a 
                href="#" 
                className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 group ${
                  isDarkMode 
                    ? "bg-gray-800 hover:bg-gray-700" 
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
              >
                <Twitter size={24} className={`group-hover:text-blue-500 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`} />
              </a>
              
              <a 
                href="#" 
                className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 group ${
                  isDarkMode 
                    ? "bg-gray-800 hover:bg-gray-700" 
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
              >
                <Facebook size={24} className={`group-hover:text-blue-600 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`} />
              </a>
              
              <a 
                href="#" 
                className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 group ${
                  isDarkMode 
                    ? "bg-gray-800 hover:bg-gray-700" 
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
              >
                <Linkedin size={24} className={`group-hover:text-blue-700 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`} />
              </a>
              
              <a 
                href="#" 
                className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 group ${
                  isDarkMode 
                    ? "bg-gray-800 hover:bg-gray-700" 
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
              >
                <Github size={24} className={`group-hover:text-gray-900 ${
                  isDarkMode ? "text-gray-400 group-hover:text-white" : "text-gray-600"
                }`} />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Featured Projects Section */}
      <section id="featured-projects" className={`py-20 ${isDarkMode ? "bg-black" : "bg-white"}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className={`text-4xl sm:text-5xl font-bold mb-4 ${
              isDarkMode ? "text-white" : "text-black"
            }`}>
              Featured <span className="text-red-500">Projects</span>
            </h2>
            <p className={`text-xl max-w-3xl mx-auto ${
              isDarkMode ? "text-gray-400" : "text-gray-600"
            }`}>
              Explore some of my latest work and creative projects available for free download.
            </p>
          </div>

          {/* Projects Grid */}
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {/* Project 1 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-blue-600 to-purple-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Dark CC Tutorial</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Dark CC tutorial like iguro. (🖤)</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Professional color correction tutorial with dark aesthetic effects.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 2 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-orange-500 to-red-600 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Reflections</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>"Reflections"🌊🌀</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Cinematic reflection effects with water and motion graphics.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 3 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Cardigan</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>"Cardigan"🌊🌀 | Demon Slayer [AMV/edit] (🖤 FREE PF)</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Demon Slayer AMV with emotional storytelling and smooth transitions.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 4 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-green-600 to-emerald-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Infected</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>"INFECTED"🧟 | Tengen Uzui [AMV/edit] (🖤 FREE PF)</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>High-energy Tengen Uzui AMV with infected theme and dynamic effects.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 5 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-pink-500 to-rose-600 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Sign of Affection</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>A sign of Affection</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Romantic edit with soft transitions and emotional storytelling.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 6 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-red-600 to-orange-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Wanderer</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>"WANDERER"🔥 | Dandadan [AMV/edit] (🔥QUICK🔥 FREE PF)</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Fast-paced Dandadan AMV with fire effects and quick cuts.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 7 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-indigo-600 to-purple-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Iguro 3k Pack</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>IGURO 3k FREE PACK🔥</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Complete Iguro editing pack with 3k resolution assets and effects.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 8 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-teal-600 to-cyan-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Levi</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>"LEVI"💀 | Dead on Arrival [+Free project file]</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Attack on Titan Levi edit with project file included for learning.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>

            {/* Project 9 */}
            <div className={`border rounded-xl overflow-hidden hover:border-gray-700 transition-all duration-300 group ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className="relative aspect-video bg-gradient-to-br from-slate-600 to-gray-700 flex items-center justify-center">
                <div className="absolute inset-0 bg-black/20"></div>
                <div className="relative z-10 text-center">
                  <Play size={48} className="text-white/80 mx-auto mb-2" />
                  <h3 className="text-lg font-bold text-white">Stop That</h3>
                </div>
              </div>
              <div className="p-6">
                <h4 className={`font-semibold mb-2 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>STOP THAT!</h4>
                <p className={`text-sm mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>Dynamic edit with stop-motion effects and creative transitions.</p>
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-green-400">₹0.00</span>
                  <span className={`text-sm px-3 py-1 rounded-full ${
                    isDarkMode 
                      ? "text-gray-500 bg-gray-800" 
                      : "text-gray-600 bg-gray-200"
                  }`}>Free</span>
                </div>
              </div>
            </div>
          </div>

          {/* View More Button */}
          <div className="text-center mt-12">
            <button className={`px-8 py-3 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 flex items-center justify-center gap-2 mx-auto ${
              isDarkMode 
                ? "bg-white text-black hover:bg-gray-100" 
                : "bg-black text-white hover:bg-gray-800"
            }`}>
              <ExternalLink size={16} />
              View All Projects
            </button>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className={`py-20 ${isDarkMode ? "bg-black" : "bg-white"}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className={`text-4xl sm:text-5xl font-bold mb-4 ${
              isDarkMode ? "text-white" : "text-black"
            }`}>
              Prices that <span className="text-red-500">make sense!</span>
            </h2>
            <p className={`text-xl max-w-3xl mx-auto ${
              isDarkMode ? "text-gray-400" : "text-gray-600"
            }`}>
              Managing a small business today is already tough.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {/* Short Edit */}
            <div className={`border rounded-xl p-8 hover:border-gray-700 transition-colors duration-300 ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-6 ${
                isDarkMode ? "bg-gray-800" : "bg-gray-200"
              }`}>
                <Scissors size={24} className={isDarkMode ? "text-gray-400" : "text-gray-600"} />
              </div>
              
              <h3 className={`text-2xl font-bold mb-2 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>Short Edit</h3>
              <p className={`mb-6 ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}>Best for quick reels or clips up to 40 seconds.</p>
              
              <div className="mb-8">
                <span className={`text-4xl font-bold ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>₹7,500</span>
                <span className={`ml-2 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>/ project</span>
              </div>

              <ul className="space-y-4 mb-8">
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Basic color grading</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Sound sync and smooth transitions</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Optimized for Instagram, YouTube Shorts, etc.</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
              </ul>

              <div className="text-center">
                <span className={`text-lg font-semibold ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Order Now →</span>
              </div>
            </div>

            {/* Full-Length Video - Most Popular */}
            <div className={`border-2 rounded-xl p-8 relative transform scale-105 ${
              isDarkMode 
                ? "bg-gray-900/50 border-white" 
                : "bg-gray-50/50 border-black"
            }`}>
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                <span className={`px-4 py-1 rounded-full text-sm font-semibold ${
                  isDarkMode 
                    ? "bg-white text-black" 
                    : "bg-black text-white"
                }`}>
                  Most Popular
                </span>
              </div>
              
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-6 ${
                isDarkMode ? "bg-gray-800" : "bg-gray-200"
              }`}>
                <Video size={24} className={isDarkMode ? "text-gray-400" : "text-gray-600"} />
              </div>
              
              <h3 className={`text-2xl font-bold mb-2 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>Full-Length Video</h3>
              <p className={`mb-6 ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}>For long-form content between 7-10 minutes.</p>
              
              <div className="mb-8">
                <span className={`text-4xl font-bold ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>₹45,000</span>
                <span className={`ml-2 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>/ video</span>
              </div>

              <ul className="space-y-4 mb-8">
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Detailed editing and scene structure</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Color correction and audio cleanup</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Perfect for vlogs, events, or YouTube content</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
              </ul>

              <div className="text-center">
                <span className={`text-lg font-semibold ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Order Now →</span>
              </div>
            </div>

            {/* Combo Pack */}
            <div className={`border rounded-xl p-8 hover:border-gray-700 transition-colors duration-300 ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200 hover:border-gray-400"
            }`}>
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center mb-6 ${
                isDarkMode ? "bg-gray-800" : "bg-gray-200"
              }`}>
                <Film size={24} className={isDarkMode ? "text-gray-400" : "text-gray-600"} />
              </div>
              
              <h3 className={`text-2xl font-bold mb-2 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>Combo Pack</h3>
              <p className={`mb-6 ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}>A smart deal for clients who want both a short reel + full video.</p>
              
              <div className="mb-8">
                <span className={`text-4xl font-bold ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>₹60,000</span>
                <span className={`ml-2 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>/ bundle</span>
              </div>

              <ul className="space-y-4 mb-8">
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Full-length video edit (7-10 min)</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>30-40 sec short reel from the same content</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Brand-consistent transitions and effects</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <Check size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className={`font-medium ${
                      isDarkMode ? "text-white" : "text-black"
                    }`}>Ideal for creators, influencers, or businesses</span>
                    <p className={`text-sm ${
                      isDarkMode ? "text-gray-400" : "text-gray-600"
                    }`}>We've made it fast and reliable.</p>
                  </div>
                </li>
              </ul>

              <div className="text-center">
                <span className={`text-lg font-semibold ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Get the Bundle →</span>
              </div>
            </div>
          </div>

          {/* Custom Quote Section */}
          <div className="text-center mt-16">
            <h3 className={`text-2xl font-bold mb-4 ${
              isDarkMode ? "text-white" : "text-black"
            }`}>Need a Custom Quote?</h3>
            <p className={`mb-8 max-w-2xl mx-auto ${
              isDarkMode ? "text-gray-400" : "text-gray-600"
            }`}>
              Have a unique project in mind? Let's discuss your specific requirements and create a tailored solution that fits your vision and budget.
            </p>
            <button 
              onClick={() => scrollToSection('contact')}
              className={`px-8 py-3 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 flex items-center justify-center gap-2 mx-auto ${
                isDarkMode 
                  ? "bg-white text-black hover:bg-gray-100" 
                  : "bg-black text-white hover:bg-gray-800"
              }`}
            >
              Get Custom Quote →
            </button>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className={`py-20 ${isDarkMode ? "bg-black" : "bg-white"}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className={`text-4xl sm:text-5xl font-bold mb-4 ${
              isDarkMode ? "text-white" : "text-black"
            }`}>
              Let's <span className="text-red-500">Connect</span>
            </h2>
            <p className={`text-xl max-w-3xl mx-auto ${
              isDarkMode ? "text-gray-400" : "text-gray-600"
            }`}>
              Ready to bring your ideas to life? Let's discuss how we can work together to create something amazing.
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-12">
            {/* Left Side - Contact Info */}
            <div className="space-y-8">
              {/* Get in Touch Card */}
              <div className={`border rounded-xl p-8 ${
                isDarkMode 
                  ? "bg-gray-900/50 border-gray-800" 
                  : "bg-gray-50/50 border-gray-200"
              }`}>
                <h3 className={`text-2xl font-bold mb-6 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Get in Touch</h3>
                
                <div className="space-y-6">
                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                      isDarkMode ? "bg-gray-800" : "bg-gray-200"
                    }`}>
                      <Mail size={20} className={isDarkMode ? "text-gray-400" : "text-gray-600"} />
                    </div>
                    <div>
                      <h4 className={`font-semibold ${
                        isDarkMode ? "text-white" : "text-black"
                      }`}>Email</h4>
                      <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>hello@sakethsirx.dev</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                      isDarkMode ? "bg-gray-800" : "bg-gray-200"
                    }`}>
                      <Phone size={20} className={isDarkMode ? "text-gray-400" : "text-gray-600"} />
                    </div>
                    <div>
                      <h4 className={`font-semibold ${
                        isDarkMode ? "text-white" : "text-black"
                      }`}>Phone</h4>
                      <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>+1 (555) 123-4567</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                      isDarkMode ? "bg-gray-800" : "bg-gray-200"
                    }`}>
                      <MapPin size={20} className={isDarkMode ? "text-gray-400" : "text-gray-600"} />
                    </div>
                    <div>
                      <h4 className={`font-semibold ${
                        isDarkMode ? "text-white" : "text-black"
                      }`}>Location</h4>
                      <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>San Francisco, CA</p>
                    </div>
                  </div>
                </div>

                <div className="flex gap-4 mt-8">
                  <button className={`flex-1 py-3 rounded-lg font-semibold transition-all duration-300 flex items-center justify-center gap-2 ${
                    isDarkMode 
                      ? "bg-white text-black hover:bg-gray-100" 
                      : "bg-black text-white hover:bg-gray-800"
                  }`}>
                    <Send size={16} />
                    Send Message
                  </button>
                  <button className={`flex-1 border py-3 rounded-lg font-semibold transition-all duration-300 hover:bg-opacity-50 flex items-center justify-center gap-2 ${
                    isDarkMode 
                      ? "border-gray-600 hover:border-gray-400 text-white hover:bg-gray-800/50" 
                      : "border-gray-400 hover:border-gray-600 text-black hover:bg-gray-200/50"
                  }`}>
                    <Calendar size={16} />
                    Schedule Call
                  </button>
                </div>
              </div>

              {/* Current Availability Card */}
              <div className={`border rounded-xl p-8 ${
                isDarkMode 
                  ? "bg-gray-900/50 border-gray-800" 
                  : "bg-gray-50/50 border-gray-200"
              }`}>
                <h3 className={`text-2xl font-bold mb-4 ${
                  isDarkMode ? "text-white" : "text-black"
                }`}>Current Availability</h3>
                <p className={`mb-4 ${
                  isDarkMode ? "text-gray-400" : "text-gray-600"
                }`}>
                  I'm currently available for new projects and collaborations. Typical response time is within 24 hours.
                </p>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                  <span className="text-green-400 font-medium">Available for hire</span>
                </div>
              </div>
            </div>

            {/* Right Side - Contact Form */}
            <div className={`border rounded-xl p-8 ${
              isDarkMode 
                ? "bg-gray-900/50 border-gray-800" 
                : "bg-gray-50/50 border-gray-200"
            }`}>
              <h3 className={`text-2xl font-bold mb-6 ${
                isDarkMode ? "text-white" : "text-black"
              }`}>Send a Message</h3>
              
              <form className="space-y-6">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="firstName" className={`block text-sm font-medium mb-2 ${
                      isDarkMode ? "text-gray-300" : "text-gray-700"
                    }`}>First Name</label>
                    <input
                      type="text"
                      id="firstName"
                      placeholder="John"
                      className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                        isDarkMode 
                          ? "bg-gray-800 border-gray-700 text-white placeholder-gray-400" 
                          : "bg-white border-gray-300 text-black placeholder-gray-500"
                      }`}
                    />
                  </div>
                  <div>
                    <label htmlFor="lastName" className={`block text-sm font-medium mb-2 ${
                      isDarkMode ? "text-gray-300" : "text-gray-700"
                    }`}>Last Name</label>
                    <input
                      type="text"
                      id="lastName"
                      placeholder="Doe"
                      className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                        isDarkMode 
                          ? "bg-gray-800 border-gray-700 text-white placeholder-gray-400" 
                          : "bg-white border-gray-300 text-black placeholder-gray-500"
                      }`}
                    />
                  </div>
                </div>
                
                <div>
                  <label htmlFor="email" className={`block text-sm font-medium mb-2 ${
                    isDarkMode ? "text-gray-300" : "text-gray-700"
                  }`}>Email</label>
                  <input
                    type="email"
                    id="email"
                    placeholder="john@example.com"
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-400" 
                        : "bg-white border-gray-300 text-black placeholder-gray-500"
                    }`}
                  />
                </div>
                
                <div>
                  <label htmlFor="subject" className={`block text-sm font-medium mb-2 ${
                    isDarkMode ? "text-gray-300" : "text-gray-700"
                  }`}>Subject</label>
                  <input
                    type="text"
                    id="subject"
                    placeholder="Project Discussion"
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-400" 
                        : "bg-white border-gray-300 text-black placeholder-gray-500"
                    }`}
                  />
                </div>
                
                <div>
                  <label htmlFor="message" className={`block text-sm font-medium mb-2 ${
                    isDarkMode ? "text-gray-300" : "text-gray-700"
                  }`}>Message</label>
                  <textarea
                    id="message"
                    rows={4}
                    placeholder="Tell me about your project..."
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-400" 
                        : "bg-white border-gray-300 text-black placeholder-gray-500"
                    }`}
                  />
                </div>
                
                <button
                  type="submit"
                  className={`w-full font-semibold py-3 rounded-lg transition-all duration-300 transform hover:scale-105 flex items-center justify-center gap-2 ${
                    isDarkMode 
                      ? "bg-white text-black hover:bg-gray-100" 
                      : "bg-black text-white hover:bg-gray-800"
                  }`}
                >
                  <Send size={16} />
                  Send Message
                </button>
              </form>
            </div>
          </div>
        </div>
      </section>

      {/* New Footer */}
      <Footer
        logo={<Star className="h-8 w-8 text-blue-400" />}
        brandName="Sakethsirx"
        socialLinks={[
          {
            icon: <Instagram className="h-5 w-5" />,
            href: "https://instagram.com",
            label: "Instagram",
          },
          {
            icon: <Youtube className="h-5 w-5" />,
            href: "https://youtube.com",
            label: "YouTube",
          },
          {
            icon: <Twitter className="h-5 w-5" />,
            href: "https://twitter.com",
            label: "Twitter",
          },
          {
            icon: <Github className="h-5 w-5" />,
            href: "https://github.com",
            label: "GitHub",
          },
        ]}
        mainLinks={[
          { href: "#about", label: "About" },
          { href: "#featured-projects", label: "Projects" },
          { href: "#pricing", label: "Pricing" },
          { href: "#contact", label: "Contact" },
        ]}
        legalLinks={[
          { href: "/privacy", label: "Privacy" },
          { href: "/terms", label: "Terms" },
        ]}
        copyright={{
          text: "© 2024 Sakethsirx",
          license: "All rights reserved",
        }}
      />
    </div>
  );
}

export default App;
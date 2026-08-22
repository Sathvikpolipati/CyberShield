import React, { useState, useEffect } from 'react'
import { Shield, Terminal, Cpu, MessageSquare, HelpCircle, Github, Activity, Menu, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

export const Navbar: React.FC = () => {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-[#050811]/90 backdrop-blur-lg border-b border-cyan-500/20 py-3 shadow-2xl shadow-black/50'
          : 'bg-transparent py-5'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Brand */}
        <a href="#" className="flex items-center gap-3 group">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-700 p-0.5 shadow-lg shadow-cyan-500/30 group-hover:scale-105 transition-transform">
            <div className="w-full h-full bg-[#050811] rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-cyan-400 group-hover:rotate-12 transition-transform" />
            </div>
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg tracking-wider text-white">CYBER<span className="text-cyan-400">SHIELD</span></span>
              <Badge variant="cyan" className="text-[10px] px-1.5 py-0">SOC v2.0</Badge>
            </div>
            <span className="text-[11px] text-slate-400 font-mono tracking-tighter">Real-Time NIDS & Traffic Defense</span>
          </div>
        </a>

        {/* Desktop Links */}
        <div className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-300">
          <a href="#features" className="hover:text-cyan-400 transition-colors flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-cyan-500" /> Features
          </a>
          <a href="#architecture" className="hover:text-cyan-400 transition-colors flex items-center gap-1.5">
            <Activity className="w-4 h-4 text-cyan-500" /> Architecture
          </a>
          <a href="#synapse-demo" className="hover:text-cyan-400 transition-colors flex items-center gap-1.5">
            <Terminal className="w-4 h-4 text-cyan-500" /> Synapse Grid
          </a>
          <a href="#testimonials" className="hover:text-cyan-400 transition-colors flex items-center gap-1.5">
            <MessageSquare className="w-4 h-4 text-cyan-500" /> Testimonials
          </a>
          <a href="#faqs" className="hover:text-cyan-400 transition-colors flex items-center gap-1.5">
            <HelpCircle className="w-4 h-4 text-cyan-500" /> FAQs
          </a>
        </div>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-3">
          <a
            href="https://github.com/Sathvikpolipati/CyberShield"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Button variant="outline" size="sm" className="gap-2 font-mono">
              <Github className="w-4 h-4" /> GitHub Repo
            </Button>
          </a>
          <a href="#quickstart">
            <Button variant="cyan" size="sm" className="gap-2 font-mono shadow-md shadow-cyan-500/20">
              <Terminal className="w-4 h-4" /> Launch SOC
            </Button>
          </a>
        </div>

        {/* Mobile menu toggle */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="md:hidden p-2 text-slate-300 hover:text-white"
        >
          {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="md:hidden bg-[#0a0f1d] border-b border-cyan-500/20 px-6 py-5 space-y-4">
          <a href="#features" onClick={() => setMobileOpen(false)} className="block text-slate-300 hover:text-cyan-400 py-1">Features</a>
          <a href="#architecture" onClick={() => setMobileOpen(false)} className="block text-slate-300 hover:text-cyan-400 py-1">Architecture</a>
          <a href="#synapse-demo" onClick={() => setMobileOpen(false)} className="block text-slate-300 hover:text-cyan-400 py-1">Synapse Grid</a>
          <a href="#testimonials" onClick={() => setMobileOpen(false)} className="block text-slate-300 hover:text-cyan-400 py-1">Testimonials</a>
          <a href="#faqs" onClick={() => setMobileOpen(false)} className="block text-slate-300 hover:text-cyan-400 py-1">FAQs</a>
          <div className="pt-2 flex flex-col gap-2">
            <a href="https://github.com/Sathvikpolipati/CyberShield" target="_blank" rel="noopener noreferrer">
              <Button variant="outline" className="w-full gap-2 font-mono">
                <Github className="w-4 h-4" /> GitHub Repository
              </Button>
            </a>
          </div>
        </div>
      )}
    </nav>
  )
}

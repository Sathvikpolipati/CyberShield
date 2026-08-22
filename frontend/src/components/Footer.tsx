import React from 'react'
import { Shield, Github, Terminal, Heart } from 'lucide-react'

export const Footer: React.FC = () => {
  return (
    <footer className="bg-[#03050a] border-t border-slate-900 text-slate-400 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <span className="font-extrabold text-white tracking-wider">CYBER<span className="text-cyan-400">SHIELD</span></span>
            <span className="text-xs text-slate-500 block">MIT Open Source Security Project</span>
          </div>
        </div>

        <div className="text-xs text-slate-500 font-mono text-center md:text-left">
          Crafted by <span className="text-cyan-400 font-bold">Sathvik Polipati</span> for enterprise perimeter defense & research.
        </div>

        <div className="flex items-center gap-4">
          <a
            href="https://github.com/Sathvikpolipati/CyberShield"
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            <Github className="w-4 h-4" />
          </a>
        </div>
      </div>
    </footer>
  )
}

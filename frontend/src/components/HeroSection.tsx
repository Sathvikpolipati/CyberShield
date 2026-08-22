import React, { useState } from 'react'
import { Shield, Terminal, ArrowRight, Play, CheckCircle, Copy, Check, Zap, Lock, Activity } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import InteractiveSynapseNetwork from '@/components/ui/interactive-synapse-network'

export const HeroSection: React.FC = () => {
  const [copied, setCopied] = useState(false)
  const cloneCmd = "git clone https://github.com/Sathvikpolipati/CyberShield.git"

  const handleCopy = () => {
    navigator.clipboard.writeText(cloneCmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="relative min-h-screen flex items-center justify-center pt-24 pb-16 overflow-hidden">
      {/* Neural Synapse Canvas Background */}
      <div className="absolute inset-0 z-0">
        <InteractiveSynapseNetwork
          nodeColor="rgba(0, 220, 255, 0.7)"
          pulseColor="rgba(255, 255, 255, 0.95)"
          nodeCount={65}
          connectionRadius={220}
          trailOpacity={0.15}
          className="h-full w-full"
        />
        {/* Radial Dark Overlay to keep text perfectly legible */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#050811]/70 via-[#050811]/50 to-[#050811] pointer-events-none" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center flex flex-col items-center">
        {/* Release Pill */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-500/30 bg-cyan-950/40 backdrop-blur-md mb-8 animate-float">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="text-xs font-mono text-cyan-300 font-semibold tracking-wide">
            Zero-Driver Native Engine • Windows, Linux, Termux & macOS
          </span>
          <Badge variant="cyan" className="ml-1 text-[10px] px-1.5 py-0">v2.0 LIVE</Badge>
        </div>

        {/* Hero Title */}
        <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight max-w-5xl">
          Autonomous <span className="text-gradient">Real-Time NIDS</span> & Active Threat Defense SOC
        </h1>

        {/* Subtitle */}
        <p className="mt-6 text-lg sm:text-xl text-slate-300 max-w-3xl leading-relaxed">
          High-performance network packet sniffer, sliding-window anomaly detectors, and dual-layer kernel firewall mitigations with zero capture latency.
        </p>

        {/* Quick Action Buttons */}
        <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
          <a href="#quickstart">
            <Button variant="cyan" size="lg" className="gap-3 font-mono text-base shadow-xl shadow-cyan-500/20">
              <Play className="w-5 h-5 fill-current" /> Deploy CyberShield <ArrowRight className="w-4 h-4" />
            </Button>
          </a>
          <a href="#synapse-demo">
            <Button variant="outline" size="lg" className="gap-2 font-mono text-base">
              <Activity className="w-5 h-5 text-cyan-400" /> Test Neural Grid
            </Button>
          </a>
        </div>

        {/* Terminal Code Snippet Bar */}
        <div className="mt-8 flex items-center justify-between w-full max-w-xl bg-black/60 backdrop-blur-md border border-cyan-500/30 rounded-xl px-4 py-2.5 font-mono text-xs sm:text-sm text-cyan-300 shadow-2xl">
          <div className="flex items-center gap-2 overflow-hidden">
            <span className="text-slate-500 select-none">$</span>
            <span className="truncate text-slate-200">{cloneCmd}</span>
          </div>
          <button
            onClick={handleCopy}
            className="ml-3 p-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 transition-colors flex items-center gap-1 shrink-0"
            title="Copy command"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span className="text-[11px] font-mono">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        {/* 3 Metric Pills */}
        <div className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-4 w-full max-w-4xl text-left font-mono">
          <div className="p-4 rounded-xl bg-slate-900/60 backdrop-blur-sm border border-cyan-500/20">
            <div className="text-xs text-slate-400">INSPECTION LATENCY</div>
            <div className="text-xl font-bold text-cyan-400 mt-1">0.0 ms (In-Engine)</div>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 backdrop-blur-sm border border-cyan-500/20">
            <div className="text-xs text-slate-400">THREAT HEURISTICS</div>
            <div className="text-xl font-bold text-emerald-400 mt-1">Port, SYN, ICMP, DNS</div>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 backdrop-blur-sm border border-cyan-500/20">
            <div className="text-xs text-slate-400">ACTIVE DEFENSE</div>
            <div className="text-xl font-bold text-yellow-400 mt-1">netsh & iptables</div>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 backdrop-blur-sm border border-cyan-500/20">
            <div className="text-xs text-slate-400">TEST SUITE</div>
            <div className="text-xl font-bold text-cyan-300 mt-1">11/11 Passed (100%)</div>
          </div>
        </div>
      </div>
    </div>
  )
}

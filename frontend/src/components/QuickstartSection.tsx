import React, { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { Badge } from '@/components/ui/badge'

export const QuickstartSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'win' | 'linux' | 'termux' | 'mac'>('win')
  const [copied, setCopied] = useState(false)

  const guides = {
    win: {
      title: "Windows (PowerShell / Windows Terminal / CMD / VS Code)",
      code: `# 1. Clone CyberShield
git clone https://github.com/Sathvikpolipati/CyberShield.git
cd CyberShield

# 2. Setup Virtual Environment
python -m venv venv
.\\venv\\Scripts\\activate

# 3. Install SOC Dependencies
pip install -r requirements.txt

# 4. Launch Interactive Menu
python launcher.py

# Or launch directly into Terminal TUI:
python run_tui.py`
    },
    linux: {
      title: "Linux (Ubuntu / Kali / Debian / Arch / Fedora)",
      code: `# 1. Install prerequisites
sudo apt update && sudo apt install -y python3 python3-pip python3-venv libpcap-dev

# 2. Clone & Setup
git clone https://github.com/Sathvikpolipati/CyberShield.git
cd CyberShield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Launch with Root Privileges
sudo ./venv/bin/python main.py`
    },
    termux: {
      title: "Android Termux (1-Click Automated Setup)",
      code: `# 1. Clone in Termux
git clone https://github.com/Sathvikpolipati/CyberShield.git
cd CyberShield

# 2. Run 1-Click Automated Installer & Launcher
chmod +x termux_setup.sh
./termux_setup.sh`
    },
    mac: {
      title: "macOS (Apple Silicon & Intel)",
      code: `# 1. Clone & Setup
git clone https://github.com/Sathvikpolipati/CyberShield.git
cd CyberShield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Run CyberShield
sudo ./venv/bin/python main.py`
    }
  }

  const currentCode = guides[activeTab].code

  const handleCopy = () => {
    navigator.clipboard.writeText(currentCode)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section id="quickstart" className="py-24 relative bg-[#070b18]/90 border-t border-cyan-500/10">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <Badge variant="cyan" className="mb-3">DEPLOYMENT GUIDE</Badge>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Ready to Defend Your <span className="text-gradient">Perimeter</span>?
          </h2>
          <p className="mt-4 text-slate-400 text-base sm:text-lg">
            Choose your operating system and launch CyberShield in less than 60 seconds.
          </p>
        </div>

        {/* Platform Selector Tabs */}
        <div className="flex flex-wrap items-center justify-center gap-2 mb-6">
          {(['win', 'linux', 'termux', 'mac'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2.5 rounded-xl font-mono text-sm font-semibold transition-all flex items-center gap-2 ${
                activeTab === tab
                  ? 'bg-cyan-500 text-black shadow-lg shadow-cyan-500/25 border border-cyan-400'
                  : 'bg-slate-900/80 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {tab === 'win' && '🪟 Windows'}
              {tab === 'linux' && '🐧 Linux / Kali'}
              {tab === 'termux' && '📱 Android Termux'}
              {tab === 'mac' && '🍎 macOS'}
            </button>
          ))}
        </div>

        {/* Code Terminal Box */}
        <div className="rounded-2xl border border-cyan-500/30 bg-black/80 backdrop-blur-md shadow-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800 bg-slate-900/50">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
              <span className="ml-3 text-xs font-mono text-slate-400">{guides[activeTab].title}</span>
            </div>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-950/60 hover:bg-cyan-500/20 border border-cyan-500/30 text-xs font-mono text-cyan-300 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy All'}</span>
            </button>
          </div>
          <pre className="p-6 font-mono text-xs sm:text-sm text-cyan-300 overflow-x-auto leading-relaxed">
            <code>{currentCode}</code>
          </pre>
        </div>
      </div>
    </section>
  )
}

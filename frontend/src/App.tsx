import React from 'react'
import { Navbar } from '@/components/Navbar'
import { HeroSection } from '@/components/HeroSection'
import { FeaturesSection } from '@/components/FeaturesSection'
import { ArchitectureSection } from '@/components/ArchitectureSection'
import InteractiveSynapseNetworkDemo from '@/components/ui/demo'
import { TestimonialsSection } from '@/components/TestimonialsSection'
import { FaqSection } from '@/components/FaqSection'
import { QuickstartSection } from '@/components/QuickstartSection'
import { Footer } from '@/components/Footer'
import { Badge } from '@/components/ui/badge'

export function App() {
  return (
    <div className="min-h-screen bg-[#050811] text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-black">
      <Navbar />
      <main className="flex-1">
        <HeroSection />
        <FeaturesSection />
        <ArchitectureSection />
        
        {/* Synapse Network Interactive Showcase */}
        <section id="synapse-demo" className="py-24 bg-[#050811] border-t border-cyan-500/10">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-3xl mx-auto mb-12">
              <Badge variant="cyan" className="mb-3">SYNAPSE NEURAL THREAT ENGINE</Badge>
              <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
                Live Interactive <span className="text-gradient">Synapse Grid</span>
              </h2>
              <p className="mt-4 text-slate-400 text-base sm:text-lg">
                Move your cursor to excite neural pathway nodes and visualize traveling threat pulses across network nodes.
              </p>
            </div>
            <div className="max-w-4xl mx-auto shadow-2xl shadow-cyan-500/10">
              <InteractiveSynapseNetworkDemo />
            </div>
          </div>
        </section>

        <TestimonialsSection />
        <FaqSection />
        <QuickstartSection />
      </main>
      <Footer />
    </div>
  )
}

export default App

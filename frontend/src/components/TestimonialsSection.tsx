import React from 'react'
import { Star, ShieldCheck, Quote } from 'lucide-react'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

export const TestimonialsSection: React.FC = () => {
  const testimonials = [
    {
      name: "Marcus Vance",
      role: "Lead SOC Analyst",
      company: "Apex Cyber Defense Labs",
      image: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
      quote: "CyberShield is by far the cleanest and fastest terminal-based NIDS I've used. The zero-driver engine captured SYN flood bursts instantly without dropping a single packet. The native mouse wheel scrolling in Windows Terminal makes triage effortless.",
      rating: 5,
      highlight: "Saved 40% investigation time during incident triage"
    },
    {
      name: "Dr. Elena Rostova",
      role: "Principal Security Architect",
      company: "Vanguard Global Infrastructure",
      image: "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150&auto=format&fit=crop&q=80",
      quote: "The dual-layer firewall architecture is ingenious. Dropping packets in-engine before heavy CPU parsing prevents DoS attacks from choking our monitoring nodes, while netsh/iptables integration ensures permanent host isolation.",
      rating: 5,
      highlight: "Impervious to CPU starvation under gigabit traffic"
    },
    {
      name: "Karan Patel",
      role: "Red Team & Offensive Researcher",
      company: "CipherSec Network Assessments",
      image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80",
      quote: "Having full sliding-window detection for DNS tunneling and ICMP sweeps on Android Termux is a game changer for field audits. I can carry a full-fledged portable SOC in my pocket and export executive PDFs on site.",
      rating: 5,
      highlight: "Top pick for portable Android Termux field forensics"
    },
    {
      name: "Sarah Jenkins",
      role: "DevSecOps Director",
      company: "CloudMatrix Technologies",
      image: "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=150&auto=format&fit=crop&q=80",
      quote: "Our team loves the modular launcher. Junior analysts can run the standalone Web Dashboard while engineering operates the pure Terminal TUI. 100% test coverage with pytest gave us complete confidence for deployment.",
      rating: 5,
      highlight: "Flawless modular execution across TUI & Web"
    }
  ]

  return (
    <section id="testimonials" className="py-24 relative bg-[#070b18]/80 border-t border-cyan-500/10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto">
          <Badge variant="cyan" className="mb-3">OPERATIONAL TESTIMONIALS</Badge>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Trusted by <span className="text-gradient">Security Engineers</span> & SOC Teams
          </h2>
          <p className="mt-4 text-slate-400 text-base sm:text-lg">
            See how enterprise defenders, incident responders, and cybersecurity researchers rely on CyberShield for perimeter defense.
          </p>
        </div>

        <div className="mt-16 grid grid-cols-1 md:grid-cols-2 gap-8">
          {testimonials.map((t, idx) => (
            <Card key={idx} className="cyber-card relative flex flex-col justify-between p-2">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-4">
                    <img
                      src={t.image}
                      alt={t.name}
                      className="w-14 h-14 rounded-full object-cover border-2 border-cyan-500/40 shadow-lg shadow-cyan-500/20"
                    />
                    <div>
                      <h4 className="font-bold text-white text-base">{t.name}</h4>
                      <p className="text-xs text-cyan-400 font-mono">{t.role}</p>
                      <p className="text-xs text-slate-500">{t.company}</p>
                    </div>
                  </div>
                  <div className="flex gap-1 text-amber-400">
                    {Array.from({ length: t.rating }).map((_, i) => (
                      <Star key={i} className="w-4 h-4 fill-current" />
                    ))}
                  </div>
                </div>

                <div className="relative">
                  <Quote className="w-8 h-8 text-cyan-500/20 absolute -top-2 -left-2 -z-0" />
                  <p className="relative z-10 text-slate-300 text-sm leading-relaxed italic">
                    "{t.quote}"
                  </p>
                </div>
              </CardHeader>

              <CardContent className="pt-2">
                <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 rounded-lg px-3 py-2">
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <span>{t.highlight}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  )
}

import React from 'react'
import InteractiveSynapseNetwork, {
  InteractiveSynapseNetworkProps,
} from '@/components/ui/interactive-synapse-network'

export const InteractiveSynapseNetworkDemo = () => {
  const glowStyle = '0 0 5px #00dcff, 0 0 10px #00dcff'
  const demoProps: InteractiveSynapseNetworkProps = {
    nodeColor: 'rgba(0,220,255,0.8)',
    pulseColor: 'rgba(255,255,255,1)',
    nodeCount: 60,
    connectionRadius: 180,
    trailOpacity: 0.15,
    className: 'flex items-center justify-center min-h-[500px] rounded-2xl border border-cyan-500/30',
  }

  return (
    <InteractiveSynapseNetwork {...demoProps}>
      <div className="text-center select-none p-6">
        <div className="px-8 py-6 bg-black/40 backdrop-blur-md rounded-2xl border border-cyan-500/20 shadow-2xl">
          <h1
            className="text-4xl sm:text-6xl font-extrabold uppercase tracking-widest text-cyan-200"
            style={{ textShadow: glowStyle }}
          >
            Synapse
          </h1>
          <h2 className="mt-2 text-base sm:text-xl uppercase tracking-wider text-cyan-200/70 font-mono">
            Interactive Threat Neural Grid
          </h2>
        </div>
        <p className="mt-6 text-sm text-cyan-300/60 font-mono flex items-center justify-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          Move cursor across the canvas to excite the neural threat pathways.
        </p>
      </div>
    </InteractiveSynapseNetwork>
  )
}

export default InteractiveSynapseNetworkDemo

import * as React from "react"
import { cn } from "@/lib/utils"

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "outline" | "cyan" | "danger" | "success"
}

function Badge({ className, variant = "default", ...props }: BadgeProps) {
  const variants = {
    default: "bg-slate-800 text-slate-200 border-slate-700",
    outline: "border-cyan-500/40 text-cyan-300 bg-cyan-950/20",
    cyan: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    danger: "bg-red-950/40 text-red-400 border-red-500/30",
    success: "bg-emerald-950/40 text-emerald-400 border-emerald-500/30"
  }
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold font-mono tracking-wider transition-colors",
        variants[variant],
        className
      )}
      {...props}
    />
  )
}

export { Badge }

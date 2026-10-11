import { useRef } from 'react'
import { useHeroScene } from '../hero/useHeroScene.js'
import '../hero/hero.css'

// Liquid Metal Hero. Layers, back to front (all decorative, pointer-events
// off): aurora gradients, tech grid, light lines through the transition
// zone, reactive particles, cursor halo and a subtle noise. The sphere is a
// WebGL shader (src/hero/sphereRenderer.js) with a CSS fallback.
export default function Hero() {
  const section = useRef(null)
  const sphere = useRef(null)
  const particles = useRef(null)
  useHeroScene(section, sphere, particles)

  return (
    <section id="top" ref={section} className="hero relative isolate overflow-hidden" data-webgl="pending">
      <div className="hero-bg" aria-hidden="true">
        <div className="hero-depth hero-depth-1">
          <div className="hero-aurora hero-aurora-a" />
          <div className="hero-aurora hero-aurora-b" />
        </div>
        <div className="hero-depth hero-depth-2">
          <div className="hero-aurora hero-aurora-c" />
          <div className="hero-grid" />
        </div>
        <svg className="hero-lines hero-depth hero-depth-3" viewBox="0 0 1200 600" preserveAspectRatio="none">
          <defs>
            <linearGradient id="hero-line" x1="0" x2="1">
              <stop offset="0" stopColor="#38bdf8" stopOpacity="0" />
              <stop offset="0.45" stopColor="#60a5fa" />
              <stop offset="0.7" stopColor="#a78bfa" />
              <stop offset="1" stopColor="#22d3ee" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path className="hero-line hero-line-1" d="M120 470 C 420 470, 560 230, 1080 250" />
          <path className="hero-line hero-line-2" d="M60 330 C 380 300, 600 420, 1140 330" />
          <path className="hero-line hero-line-3" d="M200 150 C 480 210, 700 120, 1100 420" />
        </svg>
        <canvas ref={particles} className="hero-particles" />
        <div className="hero-halo" />
        <div className="hero-noise" />
      </div>

      <div className="relative mx-auto grid max-w-7xl items-center gap-6 px-6 pt-14 pb-10 sm:px-10 md:min-h-[38rem] md:grid-cols-[1.1fr_1fr] md:gap-4 md:py-20 lg:px-16">
        <div className="max-w-xl">
          <p className="hero-in hero-in-1 hero-tag">
            <span className="hero-tag-dot" aria-hidden="true" /> DevSecOps · Seguridad de dependencias
          </p>
          <h1 className="hero-in hero-in-2 mt-6 text-6xl font-semibold tracking-tight sm:text-7xl lg:text-8xl">
            <span className="hero-metal">DepGuard</span>
          </h1>
          <p className="hero-in hero-in-3 mt-6 max-w-md text-lg text-pretty text-slate-300 sm:text-xl">
            Escáner de dependencias que detecta vulnerabilidades conocidas y prioriza cuáles corregir primero.
          </p>
          <div className="hero-in hero-in-4 mt-9 flex flex-wrap gap-3">
            <a href="#demo" className="hero-cta-primary">Probar la demo</a>
            <a href="#certificado" className="hero-cta-secondary">Ver certificado</a>
          </div>
        </div>

        <div className="hero-in hero-in-3 relative mx-auto aspect-square w-full max-w-[19rem] sm:max-w-[26rem] md:max-w-[34rem]">
          <div className="hero-depth hero-depth-4 absolute inset-0">
            <div className="hero-float absolute inset-0">
              <div className="hero-sphere-shadow" aria-hidden="true" />
              <canvas ref={sphere} className="hero-sphere" role="img" aria-label="Esfera de metal líquido iridiscente" />
              <div className="hero-sphere-fallback" aria-hidden="true" />
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

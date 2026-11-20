import { useSyncExternalStore } from 'react'
import { NeuroNoise } from '@paper-design/shaders-react'
import '../hero/hero.css'

// Hero background: Paper Design's Neuro Noise shader (WebGL2), one instance
// behind the content. The library sizes its canvas to the parent with a
// ResizeObserver and pauses itself when the hero is off screen or the tab is
// hidden. With prefers-reduced-motion it keeps moving, at a quarter speed.
// Without WebGL2 the shader is not mounted and the section keeps its black
// background (the shader's colorBack), so the text never sits on nothing.
// The library injects a small base <style>; the CSP admits it by hash.

let webgl2
function hasWebGL2() {
  if (webgl2 === undefined) {
    try {
      const gl = document.createElement('canvas').getContext('webgl2')
      webgl2 = Boolean(gl)
      gl?.getExtension('WEBGL_lose_context')?.loseContext()
    } catch {
      webgl2 = false
    }
  }
  return webgl2
}

// A soft full-bleed noise needs no 2x supersampling (the library default):
// render at the device's own ratio, capped at ~1080p worth of pixels so 4K
// and high-DPI phones stay cheap. The canvas is still stretched to fill.
const MAX_PIXELS = 1920 * 1080

const SPEED = 2
// Reduced motion slows the drift instead of freezing it: Windows reports
// "reduce" whenever its animation effects are off, often only for speed.
const REDUCED_FACTOR = 0.25

const REDUCED = '(prefers-reduced-motion: reduce)'
const subscribeReduced = (onChange) => {
  const query = globalThis.matchMedia?.(REDUCED)
  query?.addEventListener('change', onChange)
  return () => query?.removeEventListener('change', onChange)
}
const getReduced = () => Boolean(globalThis.matchMedia?.(REDUCED).matches)

export default function Hero() {
  const webgl = useSyncExternalStore(noSubscribe, hasWebGL2, noWebGL)
  const reducedMotion = useSyncExternalStore(subscribeReduced, getReduced, noWebGL)

  return (
    <section id="top" className="hero relative isolate overflow-hidden" data-webgl={webgl ? 'on' : 'off'}>
      {webgl && (
        <NeuroNoise
          className="hero-shader"
          aria-hidden="true"
          colorFront="#caffc7"
          colorMid="#0067c7"
          colorBack="#000000"
          brightness={0.2}
          contrast={0.28}
          speed={reducedMotion ? SPEED * REDUCED_FACTOR : SPEED}
          scale={0.6}
          rotation={36}
          minPixelRatio={1}
          maxPixelCount={MAX_PIXELS}
        />
      )}

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

        {/* Keeps the hero's original size and composition: the shader shows through here. */}
        <div className="mx-auto aspect-square w-full max-w-[19rem] sm:max-w-[26rem] md:max-w-[34rem]" aria-hidden="true" />
      </div>
    </section>
  )
}

const noSubscribe = () => () => {}
const noWebGL = () => false

// One animation loop for the hero: smoothed pointer -> CSS variables (halo
// and parallax layers), shader uniforms and particles. It only runs while
// the hero is on screen and the tab is visible; with reduced motion it draws
// a single still frame. Touch devices get a slow automatic drift instead of
// hover. WebGL support is exposed as data-webgl on the section, so CSS can
// show the fallback sphere without a React re-render.

import { useEffect } from 'react'
import { createSphereRenderer } from './sphereRenderer.js'
import { createParticles } from './particles.js'

const FOLLOW = 3.2 // pointer smoothing (1/s): higher = snappier
const MAX_DT = 0.05
const SLOW_FRAME = 1 / 40 // average frame time above this lowers the sphere's resolution

const REST = { x: 0.62, y: 0.42 } // halo rest position (fraction of the hero)

export function useHeroScene(sectionRef, sphereRef, particlesRef) {
  useEffect(() => {
    const section = sectionRef.current
    if (!section) return undefined
    const media = (q) => globalThis.matchMedia?.(q) ?? { matches: false, addEventListener() {}, removeEventListener() {} }
    const reduced = media('(prefers-reduced-motion: reduce)')
    const finePointer = media('(hover: hover) and (pointer: fine)')

    const sphereCanvas = sphereRef.current
    const sphere = sphereCanvas ? createSphereRenderer(sphereCanvas) : null
    section.dataset.webgl = sphere ? 'on' : 'off'
    const particles = particlesRef.current ? createParticles(particlesRef.current, { count: finePointer.matches ? 44 : 22 }) : null

    let width = section.clientWidth
    let height = section.clientHeight
    const target = { x: REST.x * width, y: REST.y * height, inside: false }
    const current = { x: target.x, y: target.y }
    let frame = 0
    let last = 0
    let visible = true
    let lastVars = ''
    let avgDt = 1 / 60
    let slowFrames = 0

    const writeVars = () => {
      const nx = (current.x / (width || 1)) * 2 - 1
      const ny = (current.y / (height || 1)) * 2 - 1
      const vars = `${current.x.toFixed(1)}|${current.y.toFixed(1)}|${nx.toFixed(3)}|${ny.toFixed(3)}`
      if (vars !== lastVars) {
        lastVars = vars
        section.style.setProperty('--mx', `${current.x.toFixed(1)}px`)
        section.style.setProperty('--my', `${current.y.toFixed(1)}px`)
        section.style.setProperty('--px', nx.toFixed(3))
        section.style.setProperty('--py', ny.toFixed(3))
      }
      return { x: nx, y: -ny }
    }

    const draw = (time, dt) => {
      const normalized = writeVars()
      sphere?.render(time, normalized)
      particles?.step(dt, time, target.inside ? current : null)
    }

    const tick = (now) => {
      frame = 0
      const time = now / 1000
      const dt = last ? Math.min(time - last, MAX_DT) : 0
      last = time
      if (!finePointer.matches) {
        // No hover on touch screens: the light drifts on its own.
        target.x = width * (0.55 + 0.25 * Math.sin(time * 0.23))
        target.y = height * (0.45 + 0.2 * Math.sin(time * 0.31 + 1.3))
      }
      if (dt) {
        avgDt += (dt - avgDt) * 0.05
        slowFrames = avgDt > SLOW_FRAME ? slowFrames + 1 : 0
        if (slowFrames > 90 && sphere?.degrade()) {
          slowFrames = 0
          avgDt = 1 / 60
        }
      }
      const k = 1 - Math.exp(-dt * FOLLOW)
      current.x += (target.x - current.x) * k
      current.y += (target.y - current.y) * k
      draw(time, dt)
      schedule()
    }

    const running = () => visible && !document.hidden && !reduced.matches
    function schedule() {
      if (!frame && running()) frame = requestAnimationFrame(tick)
    }
    const stillFrame = () => {
      particles?.resize()
      draw(12, 0) // a pleasant fixed moment of the animation
    }
    const restart = () => {
      if (frame) cancelAnimationFrame(frame)
      frame = 0
      last = 0
      if (running()) schedule()
      else stillFrame()
    }

    const onMove = (e) => {
      if (e.pointerType === 'touch' || !finePointer.matches) return
      const rect = section.getBoundingClientRect()
      target.x = e.clientX - rect.left
      target.y = e.clientY - rect.top
      target.inside = true
    }
    const onLeave = () => {
      target.inside = false
      target.x = REST.x * width
      target.y = REST.y * height
    }
    const resizeObserver = new ResizeObserver(() => {
      width = section.clientWidth
      height = section.clientHeight
      particles?.resize()
      sphere?.resize()
      if (!running()) stillFrame()
    })
    const visibility = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting
      restart()
    })
    const onContextLost = (e) => {
      e.preventDefault()
      section.dataset.webgl = 'off'
    }

    section.addEventListener('pointermove', onMove, { passive: true })
    section.addEventListener('pointerleave', onLeave)
    document.addEventListener('visibilitychange', restart)
    reduced.addEventListener('change', restart)
    sphereCanvas?.addEventListener('webglcontextlost', onContextLost)
    resizeObserver.observe(section)
    visibility.observe(section)
    particles?.resize()
    restart()

    return () => {
      if (frame) cancelAnimationFrame(frame)
      section.removeEventListener('pointermove', onMove)
      section.removeEventListener('pointerleave', onLeave)
      document.removeEventListener('visibilitychange', restart)
      reduced.removeEventListener('change', restart)
      sphereCanvas?.removeEventListener('webglcontextlost', onContextLost)
      resizeObserver.disconnect()
      visibility.disconnect()
      sphere?.dispose()
      particles?.dispose()
    }
  }, [sectionRef, sphereRef, particlesRef])
}

// A few dozen light motes drifting across the hero (2D canvas). Near the
// pointer they brighten, are gently pushed away and link to it with faint
// lines, which is what makes the background feel reactive.

const LINK_RADIUS = 150
const PALETTE = ['125, 211, 252', '167, 139, 250', '96, 165, 250', '226, 232, 240']

export function createParticles(canvas, { count = 44, maxDpr = 1.5 } = {}) {
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  let width = 0
  let height = 0
  let dpr = 1
  const motes = []

  const resize = () => {
    dpr = Math.min(globalThis.devicePixelRatio || 1, maxDpr)
    const w = canvas.clientWidth
    const h = canvas.clientHeight
    if (w === width && h === height) return
    width = w
    height = h
    canvas.width = Math.round(w * dpr)
    canvas.height = Math.round(h * dpr)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    if (!motes.length)
      for (let i = 0; i < count; i++)
        motes.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 8,
          vy: (Math.random() - 0.5) * 6 - 2,
          r: 0.6 + Math.random() * 1.4,
          depth: 0.35 + Math.random() * 0.65,
          color: PALETTE[i % PALETTE.length],
          phase: Math.random() * Math.PI * 2,
        })
  }

  /** dt in seconds; pointer in CSS px relative to the canvas, or null. */
  const step = (dt, time, pointer) => {
    ctx.clearRect(0, 0, width, height)
    for (const m of motes) {
      m.x += m.vx * dt * m.depth
      m.y += m.vy * dt * m.depth
      if (m.x < -10) m.x = width + 10
      if (m.x > width + 10) m.x = -10
      if (m.y < -10) m.y = height + 10
      if (m.y > height + 10) m.y = -10

      let near = 0
      if (pointer) {
        const dx = m.x - pointer.x
        const dy = m.y - pointer.y
        const dist = Math.hypot(dx, dy)
        if (dist < LINK_RADIUS) {
          near = 1 - dist / LINK_RADIUS
          const push = near * near * 28 * dt
          m.x += (dx / (dist || 1)) * push
          m.y += (dy / (dist || 1)) * push
          ctx.strokeStyle = `rgba(${m.color}, ${near * 0.28})`
          ctx.lineWidth = 0.6
          ctx.beginPath()
          ctx.moveTo(m.x, m.y)
          ctx.lineTo(pointer.x, pointer.y)
          ctx.stroke()
        }
      }
      const twinkle = 0.55 + 0.45 * Math.sin(time * 1.3 + m.phase)
      ctx.fillStyle = `rgba(${m.color}, ${Math.min(1, (0.18 + near * 0.7) * twinkle * (0.5 + m.depth))})`
      ctx.beginPath()
      ctx.arc(m.x, m.y, m.r * (1 + near * 0.8), 0, Math.PI * 2)
      ctx.fill()
    }
  }

  return { resize, step, dispose: () => ctx.clearRect(0, 0, width, height) }
}

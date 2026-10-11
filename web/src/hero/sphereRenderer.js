// Liquid-metal sphere rendered with plain WebGL (no 3D library): one
// full-canvas quad and a fragment shader that ray-marches a sphere whose
// surface is displaced by slow sine waves, lit by a procedural studio
// environment (silver softbox + electric blue, violet and cyan rims) with a
// thin-film iridescence term. Rays that miss the bounding sphere exit
// immediately, so the cost is limited to the sphere's footprint.

const VERTEX = `
attribute vec2 aPos;
void main() { gl_Position = vec4(aPos, 0.0, 1.0); }
`

const FRAGMENT = `
#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif
uniform vec2 uRes;
uniform float uTime;
uniform vec2 uPointer;

const float BOUND = 1.18;

float map(vec3 p) {
  float t = uTime * 0.32;
  float w = 0.7 * sin(p.x * 2.6 + t * 1.3) * sin(p.y * 2.3 - t * 1.1) * sin(p.z * 2.9 + t * 0.9);
  w += 0.45 * sin(p.x * 6.1 - t * 1.7 + p.y * 2.0) * sin(p.z * 5.3 + t * 1.2);
  w += 0.2 * sin(p.y * 11.0 + t * 2.1 + p.x * 3.0);
  return length(p) - 1.0 + w * 0.03;
}

vec3 normalAt(vec3 p) {
  const vec2 k = vec2(1.0, -1.0);
  const float e = 0.0025;
  return normalize(k.xyy * map(p + k.xyy * e) + k.yyx * map(p + k.yyx * e) +
                   k.yxy * map(p + k.yxy * e) + k.xxx * map(p + k.xxx * e));
}

vec3 env(vec3 r) {
  // Sky: deep navy to blue; floor: violet glow fading into black.
  vec3 col = r.y > 0.0
    ? mix(vec3(0.05, 0.07, 0.17), vec3(0.01, 0.012, 0.03), smoothstep(0.0, 0.9, r.y))
    : mix(vec3(0.16, 0.1, 0.34), vec3(0.01, 0.01, 0.025), smoothstep(0.0, -0.7, r.y));
  // Crisp silver horizon and two thin studio strips: the metal look.
  col += vec3(0.85, 0.88, 0.95) * exp(-pow((r.y - 0.04) * 14.0, 2.0)) * 1.1;
  col += vec3(0.7, 0.78, 0.95) * exp(-pow((r.y - 0.42) * 22.0, 2.0)) * 0.55;
  col += vec3(0.55, 0.65, 0.95) * exp(-pow((r.y + 0.3) * 18.0, 2.0)) * 0.35;
  vec3 key = normalize(vec3(-0.55 + uPointer.x * 0.45, 0.72 + uPointer.y * 0.25, 0.6));
  float kd = max(dot(r, key), 0.0);
  col += vec3(1.0) * (pow(kd, 120.0) * 3.5 + pow(kd, 12.0) * 0.35);
  float T = uTime * 0.45;
  vec3 sweep = normalize(vec3(cos(T), 0.35 + 0.25 * sin(T * 0.7), sin(T)));
  col += vec3(0.95, 0.97, 1.0) * pow(max(dot(r, sweep), 0.0), 90.0) * 1.6;
  col += vec3(0.18, 0.36, 1.0) * pow(max(dot(r, normalize(vec3(0.95, -0.15, -0.3))), 0.0), 5.0) * 1.25;
  col += vec3(0.55, 0.24, 1.0) * pow(max(dot(r, normalize(vec3(-0.9, -0.45, -0.15))), 0.0), 4.0) * 1.05;
  col += vec3(0.1, 0.88, 1.0) * pow(max(dot(r, normalize(vec3(0.25, 0.9, -0.45))), 0.0), 10.0) * 0.8;
  return col;
}

mat2 rot(float a) { float c = cos(a), s = sin(a); return mat2(c, -s, s, c); }

void main() {
  float scale = min(uRes.x, uRes.y);
  vec2 uv = (gl_FragCoord.xy - 0.5 * uRes) / scale;
  vec3 ro = vec3(0.0, 0.0, 3.2);
  vec3 rd = normalize(vec3(uv, -1.12));
  mat2 ry = rot(uPointer.x * 0.35 + uTime * 0.05);
  mat2 rx = rot(-uPointer.y * 0.22);
  ro.xz = ry * ro.xz; rd.xz = ry * rd.xz;
  ro.yz = rx * ro.yz; rd.yz = rx * rd.yz;

  // Bounding sphere: misses only get the soft outer glow.
  float b = dot(ro, rd);
  float h = b * b - dot(ro, ro) + BOUND * BOUND;
  float miss = length(cross(ro, rd));
  vec3 glowCol = mix(vec3(0.2, 0.4, 1.0), vec3(0.6, 0.3, 1.0), 0.5 + 0.5 * uv.y);
  float glow = exp(-max(miss - 1.0, 0.0) * 5.0) * 0.28 * (1.0 - smoothstep(0.36, 0.5, length(uv)));
  if (h < 0.0) { gl_FragColor = vec4(glowCol * glow, glow); return; }

  float t = -b - sqrt(h);
  float tMax = -b + sqrt(h);
  float dMin = 1e3;
  float tMin = t;
  bool hit = false;
  for (int i = 0; i < 64; i++) {
    float d = map(ro + rd * t);
    if (d < dMin) { dMin = d; tMin = t; }
    if (d < 0.0008) { hit = true; break; }
    t += d * 0.85;
    if (t > tMax) break;
  }
  // Edge anti-aliasing: near misses are shaded with partial coverage.
  float px = 2.0 / scale;
  float cover = hit ? 1.0 : 1.0 - smoothstep(0.0, px * tMin, dMin);
  if (cover <= 0.0) { gl_FragColor = vec4(glowCol * glow, glow); return; }

  vec3 p = ro + rd * (hit ? t : tMin);
  vec3 n = normalAt(p);
  vec3 v = -rd;
  float ndv = max(dot(n, v), 0.0);
  vec3 r = reflect(rd, n);
  vec3 col = env(r);
  vec3 irid = 0.5 + 0.5 * cos(6.2831 * (vec3(0.0, 0.33, 0.67) + ndv * 1.3 + n.y * 0.25 + uTime * 0.04));
  col *= mix(vec3(0.9, 0.92, 0.98), irid, 0.28);
  col += pow(1.0 - ndv, 4.0) * mix(vec3(0.35, 0.5, 1.0), vec3(0.65, 0.4, 1.0), 0.5 + 0.5 * n.y) * 1.1;
  col = col / (1.0 + col) * 1.12;
  col = pow(col, vec3(0.88));
  float a = max(cover, glow);
  gl_FragColor = vec4(col * cover + glowCol * glow * (1.0 - cover), a);
}
`

function compile(gl, type, source) {
  const shader = gl.createShader(type)
  gl.shaderSource(shader, source)
  gl.compileShader(shader)
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(shader)
    gl.deleteShader(shader)
    throw new Error(`shader: ${log}`)
  }
  return shader
}

/** -> renderer, or null if WebGL is unavailable or the shader fails. */
export function createSphereRenderer(canvas, { maxDpr = 2 } = {}) {
  let gl
  try {
    gl = canvas.getContext('webgl', { alpha: true, premultipliedAlpha: true, antialias: false, powerPreference: 'low-power' })
  } catch {
    return null
  }
  if (!gl) return null

  let program, buffer, vs, fs
  try {
    vs = compile(gl, gl.VERTEX_SHADER, VERTEX)
    fs = compile(gl, gl.FRAGMENT_SHADER, FRAGMENT)
    program = gl.createProgram()
    gl.attachShader(program, vs)
    gl.attachShader(program, fs)
    gl.linkProgram(program)
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program))
  } catch {
    return null
  }
  gl.useProgram(program)
  buffer = gl.createBuffer()
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer)
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW)
  const aPos = gl.getAttribLocation(program, 'aPos')
  gl.enableVertexAttribArray(aPos)
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0)
  const u = {
    res: gl.getUniformLocation(program, 'uRes'),
    time: gl.getUniformLocation(program, 'uTime'),
    pointer: gl.getUniformLocation(program, 'uPointer'),
  }

  // Lowered by degrade() when frames are too slow (weak GPUs).
  let quality = 1
  const resize = () => {
    const dpr = Math.min(globalThis.devicePixelRatio || 1, maxDpr) * quality
    const w = Math.max(1, Math.round(canvas.clientWidth * dpr))
    const h = Math.max(1, Math.round(canvas.clientHeight * dpr))
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w
      canvas.height = h
      gl.viewport(0, 0, w, h)
    }
  }

  return {
    resize,
    /** Renders fewer pixels from now on; false once at the minimum. */
    degrade() {
      if (quality <= 0.5) return false
      quality = Math.max(0.5, quality - 0.25)
      return true
    },
    render(timeSeconds, pointer) {
      if (gl.isContextLost()) return
      resize()
      gl.uniform2f(u.res, canvas.width, canvas.height)
      gl.uniform1f(u.time, timeSeconds)
      gl.uniform2f(u.pointer, pointer.x, pointer.y)
      gl.clearColor(0, 0, 0, 0)
      gl.clear(gl.COLOR_BUFFER_BIT)
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    },
    dispose() {
      gl.deleteBuffer(buffer)
      gl.deleteProgram(program)
      gl.deleteShader(vs)
      gl.deleteShader(fs)
      // The context is not force-lost: the same canvas may be re-used (StrictMode remount).
    },
  }
}

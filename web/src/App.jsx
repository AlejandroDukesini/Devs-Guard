import { useState } from 'react'
import Header from './components/Header.jsx'
import Hero from './components/Hero.jsx'
import ScanPanel from './components/ScanPanel.jsx'
import Results from './components/Results.jsx'
import { Architecture, DemoVsLocal, Footer, HowItWorks } from './components/Sections.jsx'
import { useScanner } from './demo/useScanner.js'
import { SAMPLES, loadSample } from './demo/samples.js'
import { DEFAULT_CONFIG } from './demo/labels.js'

const INITIAL = {
  source: 'sample',
  sampleId: SAMPLES[0].id,
  userFiles: [],
  pasteName: 'requirements.txt',
  pasteText: '',
  mode: 'live',
  configText: DEFAULT_CONFIG,
  simulateOutage: false,
}

export default function App() {
  const [input, setInput] = useState(INITIAL)
  const scanner = useScanner()

  const onScan = async () => {
    let files
    let projectName = 'project'
    if (input.source === 'sample') {
      files = await loadSample(input.sampleId)
      projectName = input.sampleId
    } else if (input.userFiles.length) {
      files = input.userFiles
    } else {
      files = [{ path: input.pasteName, content: input.pasteText }]
    }
    scanner.run({
      files,
      mode: input.mode,
      configText: input.configText,
      simulateOutage: input.simulateOutage && input.mode === 'live',
      source: projectName,
    })
  }

  const onReset = () => {
    scanner.reset()
    setInput(INITIAL)
  }

  return (
    <>
      <a href="#demo" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-white focus:p-2">
        Saltar a la demo
      </a>
      <Header />
      <main>
        <Hero />
        <section id="demo" className="scroll-mt-16 bg-slate-50 py-12 dark:bg-slate-900/40">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <h2 className="section-title">Demo interactiva</h2>
            <p className="mt-2 max-w-3xl text-slate-600 dark:text-slate-400">
              Escaneo real: el motor corre en esta pestaña y consulta las fuentes públicas. Elige un ejemplo o usa tus propios
              archivos.
            </p>
            <div className="mt-6 grid items-start gap-6 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
              <ScanPanel
                scanning={scanner.phase === 'scanning'}
                onScan={onScan}
                onReset={onReset}
                state={input}
                setState={setInput}
              />
              <Results
                phase={scanner.phase}
                report={scanner.report}
                error={scanner.error}
                steps={scanner.steps}
                meta={scanner.meta}
                projectName={scanner.meta?.source}
                onNewScan={() => {
                  onReset()
                  document.getElementById('demo')?.scrollIntoView()
                }}
              />
            </div>
          </div>
        </section>
        <HowItWorks />
        <Architecture />
        <DemoVsLocal />
      </main>
      <Footer />
    </>
  )
}

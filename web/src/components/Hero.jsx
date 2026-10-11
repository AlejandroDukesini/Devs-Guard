// Photo: padlock on a keyboard, by FlyD on Unsplash (Unsplash License),
// stored locally in public/ so the CSP (img-src 'self') still holds.
export default function Hero() {
  return (
    <section id="top" className="grid bg-black md:min-h-[32rem] md:grid-cols-2">
      <div className="flex flex-col justify-center px-6 py-16 sm:px-12 lg:px-16">
        <h1 className="text-5xl font-semibold tracking-tight text-white sm:text-6xl">DepGuard</h1>
        <p className="mt-5 max-w-md text-lg text-pretty text-slate-300">
          Escáner de dependencias que detecta vulnerabilidades conocidas y prioriza cuáles corregir primero.
        </p>
      </div>
      <img
        src="/hero-security.webp"
        alt="Candado metálico sobre un teclado iluminado"
        width="1200"
        height="1200"
        fetchPriority="high"
        className="h-64 w-full object-cover sm:h-80 md:h-full"
      />
    </section>
  )
}

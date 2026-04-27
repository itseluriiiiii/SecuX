import { useEffect, useState, useRef } from 'react'
import { motion, useScroll, useTransform, AnimatePresence, Variants } from 'framer-motion'
import { Shield, Zap, Brain, Target, Terminal, ArrowRight, Search, LucideIcon, Cpu, FileText, Activity } from 'lucide-react'
import './index.css'
import Preloader from './components/Preloader'

const fadeInUp: Variants = {
  hidden: { opacity: 0, y: 40 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.8, ease: [0.22, 1, 0.36, 1] as const } }
}

const staggerContainer: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.12, delayChildren: 0.4 }
  }
}

const textBlurIn: Variants = {
  hidden: { opacity: 0, filter: 'blur(10px)', y: 20 },
  visible: { opacity: 1, filter: 'blur(0px)', y: 0, transition: { duration: 1, ease: 'easeOut' } }
}

interface Particle {
  x: number
  y: number
  size: number
  speedX: number
  speedY: number
  opacity: number
}

function BackgroundEffects() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    
    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)
    
    const particles: Particle[] = []
    for (let i = 0; i < 50; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        size: Math.random() * 1.5 + 0.5,
        speedX: (Math.random() - 0.5) * 0.2,
        speedY: (Math.random() - 0.5) * 0.2,
        opacity: Math.random() * 0.3 + 0.05
      })
    }
    
    const animate = () => {
      ctx.fillStyle = '#000000'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      
      particles.forEach((p) => {
        p.x += p.speedX
        p.y += p.speedY
        if (p.x < 0 || p.x > canvas.width) p.speedX *= -1
        if (p.y < 0 || p.y > canvas.height) p.speedY *= -1
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(0, 183, 181, ${p.opacity})`
        ctx.fill()
      })
      
      requestAnimationFrame(animate)
    }
    
    animate()
    return () => window.removeEventListener('resize', resize)
  }, [])
  
  return <canvas ref={canvasRef} className='fixed inset-0 pointer-events-none z-0' style={{ opacity: 0.4 }} />
}

function CursorGlow() {
  const [position, setPosition] = useState({ x: 0, y: 0 })
  useEffect(() => {
    const handleMove = (e: MouseEvent) => setPosition({ x: e.clientX, y: e.clientY })
    window.addEventListener('mousemove', handleMove)
    return () => window.removeEventListener('mousemove', handleMove)
  }, [])
  return <div className='fixed w-[500px] h-[500px] rounded-full pointer-events-none z-0 transition-opacity duration-300' style={{ background: 'radial-gradient(circle, rgba(0, 183, 181, 0.04) 0%, transparent 70%)', left: position.x - 250, top: position.y - 250 }} />
}

function Hero({ isLoaded }: { isLoaded: boolean }) {
  const { scrollY } = useScroll()
  const y = useTransform(scrollY, [0, 500], [0, 100])
  
  return (
    <motion.section 
      className='relative min-h-[90vh] md:min-h-screen flex flex-col items-center justify-center px-6 py-20 md:py-32 grid-bg overflow-hidden bg-surface_container_lowest'
      initial='hidden'
      animate={isLoaded ? 'visible' : 'hidden'}
      variants={staggerContainer}
    >
      <motion.div className='absolute inset-0 bg-gradient-to-b from-transparent via-surface/30 to-surface_container_lowest z-10' style={{ y }} />
      <motion.div className='relative z-20 text-center w-full max-w-7xl mx-auto'>
        <motion.div variants={fadeInUp} className='inline-flex items-center gap-3 mb-8 md:mb-10'>
          <div className='pulse-indicator' />
          <span className='text-[10px] uppercase tracking-[0.2em] font-medium text-on_surface_variant'>System Status: Secure</span>
        </motion.div>
        
        <motion.h1 variants={textBlurIn} className='text-[2.2rem] sm:text-[4rem] md:text-[6rem] lg:text-[7.5rem] font-bold mb-6 md:mb-8 leading-[0.95] tracking-tighter font-display break-words uppercase'>
          THE <span className='text-gradient'>SECUX</span><br />
          <span className='text-on_surface opacity-90'>PERSPECTIVE.</span>
        </motion.h1>
        
        <motion.p variants={fadeInUp} className='text-xs md:text-xl text-on_surface_variant max-w-xl mx-auto mb-10 md:mb-16 leading-relaxed font-light px-4 opacity-70'>
          Autonomous LLM agents simulating real-world cyberattacks through silent, powerful intelligence.
        </motion.p>
        
        <motion.div variants={fadeInUp} className='flex flex-col sm:flex-row gap-4 md:gap-8 justify-center items-center'>
          {/* Desktop Download Button */}
          <motion.a 
            href="/secux_backend.zip"
            download="secux_backend.zip"
            whileHover={{ scale: 1.02, y: -2 }} 
            whileTap={{ scale: 0.98 }} 
            className='hidden md:flex group w-full sm:w-auto px-8 md:px-10 py-4 md:py-5 bg-gradient-to-r from-primary to-primary_container text-[#000] font-bold rounded-md items-center justify-center gap-3 transition-all ambient-glow text-xs md:text-base cursor-pointer'
          >
            DOWNLOAD NOW
            <motion.div
                animate={{ x: [0, 5, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: "easeInOut" }}
            >
                <ArrowRight className='w-5 h-5' />
            </motion.div>
          </motion.a>
          
          {/* Mobile Desktop Notice */}
          <div className='flex md:hidden flex-col items-center gap-4 p-6 bg-surface_container rounded-lg border border-primary/10 ambient-glow'>
              <Search className='w-8 h-8 text-primary opacity-50' />
              <p className='text-[10px] uppercase tracking-[0.2em] font-bold text-primary'>Desktop Perspective Required</p>
              <p className='text-[11px] text-on_surface_variant opacity-60 max-w-[240px]'>For full autonomous orchestration and vector analysis, please access SecuX from a laptop or PC.</p>
          </div>
        </motion.div>
      </motion.div>
      
      {/* Scroll indicator */}
      <motion.div 
        variants={fadeInUp}
        initial={{ opacity: 0 }}
        animate={{ opacity: 0.3 }}
        transition={{ delay: 2 }}
        className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2"
      >
          <span className="text-[8px] uppercase tracking-[0.4em] font-bold">Scroll</span>
          <div className="w-px h-12 bg-gradient-to-b from-primary to-transparent" />
      </motion.div>
    </motion.section>
  )
}

interface Step {
  icon: LucideIcon
  title: string
  desc: string
}

function HowItWorks() {
  const steps: Step[] = [
    { icon: Terminal, title: 'SYSTEM MAPPING', desc: 'Ingest architecture, APIs, and permission flows.' },
    { icon: Brain, title: 'AGENT ALLOCATION', desc: 'Autonomous LLM entities assigned specific threat profiles.' },
    { icon: Target, title: 'STRATEGY SYNTHESIS', desc: 'Deep-horizon simulations of SQLi, XSS, and lateral movement.' },
    { icon: Shield, title: 'SECUX INSIGHTS', desc: 'Full spectrum vulnerability mapping with remediation logic.' },
  ]
  return (
    <section className='relative py-32 md:py-64 px-6 bg-surface'>
      <motion.div className='relative z-10 max-w-7xl mx-auto' initial='hidden' whileInView='visible' viewport={{ once: true, margin: '-100px' }} variants={staggerContainer}>
        <div className='flex flex-col lg:flex-row gap-16 lg:gap-24 items-start'>
          <div className='lg:w-1/3'>
            <motion.label variants={fadeInUp} className='text-[10px] uppercase tracking-[0.3em] text-primary mb-6 block font-bold'>Operational Protocol</motion.label>
            <motion.h2 variants={fadeInUp} className='text-4xl md:text-6xl font-bold mb-8 font-display leading-tight'>HOW THE <span className='text-gradient'>SECUX MATRIX</span> OPERATES</motion.h2>
            <motion.p variants={fadeInUp} className='text-on_surface_variant text-lg leading-relaxed font-light mb-8'>
              We eliminate the noise of traditional security dashboards. Our agents perform silent, authoritative analysis through editorial precision.
            </motion.p>
          </div>
          
          <div className='lg:w-2/3 grid sm:grid-cols-2 gap-4 bg-transparent rounded-lg overflow-hidden w-full'>
            {steps.map((step, i) => (
              <motion.div 
                key={i} 
                variants={fadeInUp} 
                whileHover={{ y: -5 }}
                className='bg-surface_container p-10 group transition-all hover:bg-surface_container_high rounded-md relative overflow-hidden'
              >
                <div className="absolute top-0 left-0 w-1 h-0 bg-primary group-hover:h-full transition-all duration-500" />
                <step.icon className='w-10 h-10 text-primary mb-8 opacity-60 group-hover:opacity-100 transition-opacity' />
                <h3 className='text-xs uppercase tracking-[0.2em] font-bold mb-4 text-on_surface'>{step.title}</h3>
                <p className='text-on_surface_variant text-sm font-light leading-relaxed'>{step.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </motion.div>
    </section>
  )
}

interface Feature {
  icon: LucideIcon
  title: string
  desc: string
}

function Features() {
  const features: Feature[] = [
    { icon: Brain, title: 'MULTI-AGENT ORCHESTRATION', desc: 'Parallel execution of specialized AI entities across authentication, network, and vulnerability vectors.' },
    { icon: Terminal, title: 'AUTONOMOUS LOG SCANNING', desc: 'Deep-horizon analysis of system archives to identify SQLi, XSS, and advanced persistent threat patterns.' },
    { icon: Zap, title: 'INCREMENTAL INTELLIGENCE', desc: 'Real-time delta scanning of system logs to detect emerging anomalies with zero-latency response logic.' },
    { icon: Search, title: 'NETWORK PATTERN ANALYSIS', desc: 'High-density surveillance of endpoint connectivity and packet flows to map unconventional traffic vectors.' },
    { icon: Shield, title: 'AUTHENTICATION AUDIT', desc: 'Rigorous evaluation of identity security architectures and permission flows for bypass and escalation risks.' },
    { icon: Target, title: 'SUPER AGENT CORRELATION', desc: 'A centralized cognitive layer that synthesizes multi-agent findings into a unified, actionable security roadmap.' },
    { icon: Cpu, title: 'LOCAL LLM INTEGRATION', desc: 'Full utilization of local Ollama processing for private, secure intelligence without data leakage risks.' },
    { icon: FileText, title: 'EDITORIAL AUDIT REPORTS', desc: 'Professional technical reporting providing absolute clarity and remediation logic for complex vulnerabilities.' },
    { icon: Activity, title: 'VULNERABILITY ASSESSMENT', desc: 'Comprehensive mapping of architectural weaknesses through autonomous offensive simulations and impact analysis.' },
  ]
  return (
    <section id='features' className='relative py-32 md:py-64 px-6 bg-surface_container_lowest overflow-hidden'>
      <motion.div className='relative z-10 max-w-7xl mx-auto' initial='hidden' whileInView='visible' viewport={{ once: true, margin: '-100px' }} variants={staggerContainer}>
        <div className='flex flex-col items-center mb-32 md:mb-48 relative text-center'>
          <motion.h2 
            initial={{ opacity: 0, scale: 0.9, y: '-50%', x: '-50%' }}
            whileInView={{ opacity: 0.03, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 2, ease: 'easeOut' }}
            className='hidden md:block text-[12vw] font-bold tracking-[0.05em] font-display leading-none text-white select-none absolute top-1/2 left-1/2 whitespace-nowrap z-0 uppercase pointer-events-none text-center'
          >
            CORE CAPABILITIES
          </motion.h2>
          <motion.h2 variants={fadeInUp} className='text-3xl md:text-5xl lg:text-[5rem] font-bold mb-8 font-display z-10 leading-[0.9] relative'>DEEP SPECTRUM <br className='md:hidden' /><span className='text-gradient uppercase'>ANALYSIS</span></motion.h2>
          <motion.p variants={fadeInUp} className='text-on_surface_variant max-w-2xl font-light text-sm md:text-lg px-4 opacity-80 relative z-10'>Engineered for high-stakes security auditing through autonomous observation.</motion.p>
        </div>
        
        <div className='grid md:grid-cols-2 lg:grid-cols-3 gap-y-20 md:gap-y-32 gap-x-12 md:gap-x-20'>
          {features.map((feature, i) => (
            <motion.div key={i} variants={fadeInUp} className='flex flex-col items-center md:items-start text-center md:text-left group relative'>
              <div className='flex items-center gap-6 mb-8'>
                <div className='w-px h-12 bg-gradient-to-b from-primary to-transparent rounded-full group-hover:h-16 transition-all duration-500' />
                <feature.icon className='w-8 h-8 text-primary opacity-30 group-hover:opacity-100 transition-all duration-500 group-hover:scale-110' />
              </div>
              <h3 className='text-[11px] uppercase tracking-[0.3em] font-bold mb-6 text-on_surface group-hover:text-primary transition-colors'>{feature.title}</h3>
              <p className='text-on_surface_variant text-sm md:text-base font-light leading-relaxed max-w-sm opacity-70 group-hover:opacity-100 transition-opacity'>{feature.desc}</p>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </section>
  )
}

function Footer() {
  const teamMembers = ['Abhilash K M', 'Akshay Kumar', 'Anish Shetty', 'Arnav Eluri']
  return (
    <footer className='relative py-24 md:py-32 px-6 bg-surface_container_lowest border-t border-outline_variant/5'>
      <div className='relative z-10 max-w-7xl mx-auto'>
        <div className='flex flex-col md:flex-row justify-between items-start gap-16 mb-24 md:mb-32'>
          <motion.div initial={{ opacity: 0, x: -20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}>
            <div className='flex items-center gap-4 mb-2'>
              <div className='w-12 h-12 bg-primary rounded-md flex items-center justify-center ambient-glow'>
                <Shield className='w-6 h-6 text-[#000]' />
              </div>
              <span className='text-3xl font-bold font-display tracking-tight text-on_surface'>SECUX<span className='text-primary opacity-50'>.</span></span>
            </div>
            <p className='text-on_surface_variant font-light text-xs tracking-widest opacity-60'>EDITORIAL SECURITY INTELLIGENCE</p>
            <p className='text-on_surface_variant font-light text-sm mt-4 max-w-md opacity-40 leading-relaxed'>
              SecuX is a high-performance, AI-driven cybersecurity orchestration platform. It utilizes a network of specialized AI agents to perform deep security audits, reconstruct complex attack chains, and provide actionable intelligence from raw system telemetry.
            </p>
          </motion.div>
        </div>
        
        <div className='flex flex-col lg:flex-row justify-between items-center gap-8 md:gap-12 pt-12 md:pt-16 border-t border-outline_variant/5'>
          <div className='flex flex-wrap justify-center gap-8 md:gap-12'>
            {teamMembers.map((member, i) => (
              <motion.span 
                key={i} 
                whileHover={{ scale: 1.1, color: '#00B7B5' }}
                className='text-[10px] font-bold uppercase tracking-widest text-on_surface_variant opacity-40 hover:opacity-100 transition-all cursor-pointer'
              >
                {member}
              </motion.span>
            ))}
          </div>
          <p className='text-[10px] font-light text-on_surface_variant opacity-30 text-center lg:text-right uppercase tracking-[0.2em]'>© 2026 REVA UNIVERSITY. Bengaluru.</p>
        </div>
      </div>
    </footer>
  )
}

function Navbar({ isLoaded }: { isLoaded: boolean }) {
  const [isScrolled, setIsScrolled] = useState(false)
  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 50)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])
  
  return (
    <motion.nav 
      initial={{ y: -100 }}
      animate={isLoaded ? { y: 0 } : { y: -100 }}
      transition={{ duration: 1, ease: [0.22, 1, 0.36, 1], delay: 0.5 }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${isScrolled ? 'bg-surface/90 backdrop-blur-2xl py-6' : 'py-10'}`}
    >
      <div className='max-w-7xl mx-auto px-6 md:px-12 flex items-center justify-between'>
        <div className='flex items-center gap-4'>
          <div className='w-10 h-10 bg-primary rounded-md flex items-center justify-center ambient-glow'>
            <Shield className='w-6 h-6 text-[#000]' />
          </div>
          <span className='text-2xl font-bold font-display tracking-tight text-on_surface'>SECUX</span>
        </div>
        <div className='hidden md:flex items-center gap-8 lg:gap-16'>
          <a href='#features' className='text-[10px] uppercase tracking-[0.4em] font-bold text-on_surface_variant hover:text-primary transition-colors'>FEATURES</a>

          <motion.a 
            href="/secux_backend.zip"
            download="secux_backend.zip"
            whileHover={{ scale: 1.05 }} 
            whileTap={{ scale: 0.95 }} 
            className='hidden md:block text-[10px] uppercase tracking-[0.4em] font-black text-[#000] bg-primary px-8 py-3 rounded-md ambient-glow transition-all cursor-pointer'
          >
            DOWNLOAD
          </motion.a>
        </div>
        <div className='md:hidden'>
          <div className='pulse-indicator' />
        </div>
      </div>
    </motion.nav>
  )
}

function App() {
  const [isLoading, setIsLoading] = useState(true)

  return (
    <div className='relative selection:bg-primary selection:text-[#000]'>
      <AnimatePresence>
        {isLoading && (
          <Preloader onComplete={() => setIsLoading(false)} />
        )}
      </AnimatePresence>

      <BackgroundEffects />
      <CursorGlow />
      <Navbar isLoaded={!isLoading} />
      
      <main>
        <Hero isLoaded={!isLoading} />
        <HowItWorks />
        <Features />
      </main>
      
      <Footer />
    </div>
  )
}

export default App
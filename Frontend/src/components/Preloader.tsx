import { motion, AnimatePresence } from 'framer-motion'
import { useEffect, useState } from 'react'
import { Shield } from 'lucide-react'

const loadingSteps = [
  "INITIALIZING CORE VECTORS",
  "BOOTING SECUX AGENTS",
  "MAPPING SYSTEM TOPOLOGY",
  "ENABLING SURVEILLANCE MATRIX",
  "ESTABLISHING SECURE PIPELINE"
]

export default function Preloader({ onComplete }: { onComplete: () => void }) {
  const [progress, setProgress] = useState(0)
  const [currentStep, setCurrentStep] = useState(0)

  useEffect(() => {
    const timer = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(timer)
          setTimeout(onComplete, 500)
          return 100
        }
        return prev + 1
      })
    }, 30)

    return () => clearInterval(timer)
  }, [onComplete])

  useEffect(() => {
    const stepInterval = setInterval(() => {
      setCurrentStep(prev => (prev + 1) % loadingSteps.length)
    }, 800)
    return () => clearInterval(stepInterval)
  }, [])

  return (
    <motion.div 
      initial={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.8, ease: "easeInOut" } }}
      className="fixed inset-0 z-[100] bg-surface_container_lowest flex flex-col items-center justify-center p-6"
    >
      <motion.div 
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5 }}
        className="w-16 h-16 bg-primary rounded-md flex items-center justify-center ambient-glow mb-12"
      >
        <Shield className="w-8 h-8 text-on_primary_fixed" />
      </motion.div>

      <div className="w-full max-w-xs md:max-w-md">
        <div className="flex justify-between items-end mb-4">
          <div className="flex flex-col">
            <span className="text-[10px] uppercase tracking-[0.3em] text-primary font-bold mb-1">System Status</span>
            <AnimatePresence mode="wait">
              <motion.span 
                key={currentStep}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 10 }}
                transition={{ duration: 0.3 }}
                className="text-[11px] uppercase tracking-[0.2em] text-on_surface_variant opacity-60 font-mono"
              >
                {loadingSteps[currentStep]}
              </motion.span>
            </AnimatePresence>
          </div>
          <span className="text-2xl font-display font-bold text-primary">{progress}%</span>
        </div>

        <div className="h-[2px] w-full bg-surface_container relative overflow-hidden">
          <motion.div 
            className="absolute top-0 left-0 h-full bg-primary"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ ease: "linear" }}
          />
        </div>
        
        <div className="mt-8 flex justify-center gap-2">
            {[...Array(5)].map((_, i) => (
                <motion.div
                    key={i}
                    animate={{
                        opacity: [0.2, 1, 0.2],
                        scale: [1, 1.2, 1]
                    }}
                    transition={{
                        duration: 1,
                        repeat: Infinity,
                        delay: i * 0.2
                    }}
                    className="w-1 h-1 bg-primary rounded-full"
                />
            ))}
        </div>
      </div>

      <div className="absolute bottom-12 text-[10px] uppercase tracking-[0.5em] text-on_surface_variant opacity-20 font-bold">
        SecuX Editorial Intelligence
      </div>
    </motion.div>
  )
}

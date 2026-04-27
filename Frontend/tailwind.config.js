/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        surface: '#000000',
        surface_container_lowest: '#050505',
        surface_container_low: '#0A0A0A',
        surface_container: '#0F0F0F',
        surface_container_high: '#141414',
        surface_container_highest: '#1A1A1A',
        primary: '#00B7B5',
        primary_container: '#005461',
        on_primary_fixed: '#FFFFFF',
        secondary: '#005461',
        tertiary: '#00B7B5',
        error: '#FFB4AB',
        on_surface: '#FFFFFF',
        on_surface_variant: '#E0E0E0',
        outline_variant: '#005461',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        display: ['Space Grotesk', 'sans-serif'],
      },
      borderRadius: {
        md: '0.375rem',
      },
    },
  },
  plugins: [],
}

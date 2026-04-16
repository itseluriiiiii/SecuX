/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        surface: '#131313',
        surface_container_lowest: '#0E0E0E',
        surface_container_low: '#181818',
        surface_container: '#201F1F',
        surface_container_high: '#282827',
        surface_container_highest: '#353534',
        primary: '#FFC793',
        primary_container: '#FFA133',
        on_primary_fixed: '#251900',
        secondary: '#A0C9FF',
        tertiary: '#FFB4AB',
        error: '#FFB4AB',
        on_surface: '#E5E2E1',
        on_surface_variant: '#D0C4B8',
        outline_variant: '#544435',
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

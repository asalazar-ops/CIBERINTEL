# To_Do — Mejoras de Dashboard

Backlog de mejoras de UX/UI del frontend, a partir de una exploración de [src/App.jsx](src/App.jsx).
La primera ronda (feedback visual: toasts, modal de confirmación, loading/error states, hook de
fetch centralizado) ya está implementada — ver `src/components/Toast.jsx`, `ConfirmDialog.jsx`,
`Spinner.jsx`, `ErrorBanner.jsx` y `src/hooks/useApiFetch.js`.

Ningún ítem de este backlog está iniciado todavía.

- [ ] **Responsive / mobile**
  Sin `@media` queries en todo el proyecto; layout fijo `100vw`/`100vh` con sidebar de 240px fijo
  ([src/App.jsx:1711](src/App.jsx#L1711)); no funcional en tablet/móvil.

- [ ] **Accesibilidad**
  Cero `aria-*`/`role` en `App.jsx`. Elementos interactivos como `<div onClick>` sin soporte de
  teclado: `ThreatCard` ([:92](src/App.jsx#L92)), nav superior ([:1762](src/App.jsx#L1762)), menú
  de usuario/logout ([:1775](src/App.jsx#L1775)). Modales (`ConfirmDialog` incluido) sin focus
  trap ni cierre con `Escape`. Posibles fallos de contraste WCAG en textos secundarios
  (`#475569` sobre `#0f172a`).

- [ ] **Sistema de diseño / tokens**
  Cientos de valores de color hardcodeados repetidos en `style={{}}` sin ninguna fuente única de
  verdad; sin componentes compartidos de layout (`Button`, `Modal`, `Table`) — cada vista
  reimplementa los suyos con estilos inline.

- [ ] **Limpieza menor**
  `App.css` no está importado por ningún componente (`App.jsx` duplica sus keyframes inline en un
  `<style>` embebido) — código muerto a limpiar cuando se toque esa zona.

- [ ] **`useApiFetch` en el resto de las vistas**
  El hook se aplicó como piloto en `AssetsView` y el tab "Behavior" de `EndpointsView`. El resto
  de fetches dispersos (Threats, Dashboard, panel de gestión de datos) siguen con el patrón
  manual `useState + try/catch/finally`.

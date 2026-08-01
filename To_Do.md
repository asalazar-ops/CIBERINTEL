# To_Do — Mejoras de Dashboard (rama `Dashboad`)

Documento de planificación. Ningún ítem de esta lista está iniciado todavía.

## Contexto

Todo el frontend vive en un único archivo, [src/App.jsx](src/App.jsx) (1920 líneas, 13 componentes internos), sin librería de UI (solo `lucide-react` para iconos; todo el styling es inline `style={{}}`) y sin cliente HTTP centralizado — hay 24+ llamadas `fetch()` dispersas, cada una manejando su propio loading/error de forma distinta e inconsistente.

Esta rama (`Dashboad`) se dedica exclusivamente a revisar y mejorar la experiencia del dashboard, sin tocar la infraestructura backend/Vercel ya migrada en `main`.

**Prioridad acordada**: feedback visual (loading states + manejo de errores) — es el área con más impacto perceptible y más inconsistencias encontradas en la exploración del código actual. El resto de hallazgos queda registrado como backlog futuro.

---

## Sección 1 — Feedback visual (prioridad actual)

- [ ] **1. Sistema de notificaciones (toasts)**
  Reemplazar todos los `alert()` de error por un componente propio.
  - Problema actual: `alert()` nativo bloquea el hilo y rompe la estética de la app. Ocurrencias en [src/App.jsx:656](src/App.jsx#L656), [:665](src/App.jsx#L665), [:685](src/App.jsx#L685), [:697](src/App.jsx#L697) (`AssetsView`); [:1177](src/App.jsx#L1177), [:1191](src/App.jsx#L1191) (`EndpointsView`); [:1522](src/App.jsx#L1522), [:1528](src/App.jsx#L1528) (purga de datos).
  - Propuesta: `src/components/Toast.jsx` (posición fija, auto-dismiss, variantes success/error/info) + un hook/Context (`useToast`) para dispararlo desde cualquier vista sin prop-drilling.

- [ ] **2. Modal de confirmación reutilizable**
  Reemplazar los `confirm()` nativos en acciones destructivas (eliminar asset, eliminar endpoint, purgar datos).
  - Propuesta: `src/components/ConfirmDialog.jsx` genérico con título/mensaje/acción configurable.

- [ ] **3. Loading states consistentes**
  Definir un patrón único y aplicarlo donde falta indicador de carga.
  - Problema actual: `TopIndicators` ([:431](src/App.jsx#L431)), `AnalysisView` ([:1040](src/App.jsx#L1040)) y el botón de refresh global ([:1712](src/App.jsx#L1712)) sí muestran spinner; la carga inicial de `AssetsView` y la tabla principal de `EndpointsView` no muestran nada — aparecen vacías hasta que llega la respuesta. No hay skeletons en ningún lado.
  - Propuesta: `src/components/Spinner.jsx` (o `Skeleton.jsx`) reutilizable, aplicado de forma consistente en las vistas que hoy carecen de él.

- [ ] **4. Errores visibles por vista**
  Extender el único banner de error que existe hoy (Dashboard, alimentado solo por `loadNews`, [src/App.jsx:1731-1733](src/App.jsx#L1731-L1733)) a las demás vistas que hoy fallan en silencio.
  - Fetches hoy silenciosos (solo `console.error`, sin feedback visible): `fetchAssets` ([:633](src/App.jsx#L633)), `loadEndpoints` ([:1541](src/App.jsx#L1541)), `loadSummary` de Analysis ([:1030](src/App.jsx#L1030)), `loadBehavior` ([:1173](src/App.jsx#L1173)), los tres paneles OTX del dashboard (`fetchIndicators`/`fetchActors`/`fetchIndustries`).
  - Propuesta: componente `ErrorBanner.jsx` reutilizable, o integrarlo directamente al sistema de toasts del ítem 1.

- [ ] **5. Centralizar el manejo de fetch**
  Evaluar un hook simple (`useApiFetch` o similar) que estandarice loading/error/data, evitando seguir repitiendo el mismo trío `useState + try/catch/finally` en cada componente.
  - Es la base que hace sostenibles los 4 ítems anteriores — conviene resolverlo primero o en paralelo.
  - Precedente ya existente a extender: el interceptor global de 401 vía monkey-patch de `window.fetch` ([src/App.jsx:1449-1459](src/App.jsx#L1449-L1459)) — mismo principio de "un solo punto que reacciona a fallos de red", aplicado hoy solo a 401.

---

## Sección 2 — Backlog futuro (registrado, sin desarrollar todavía)

- **Responsive / mobile**: sin `@media` queries en todo el proyecto; layout fijo `100vw`/`100vh` con sidebar de 240px fijo ([src/App.jsx:1651-1654](src/App.jsx#L1651-L1654)); no funcional en tablet/móvil.
- **Accesibilidad**: cero `aria-*`/`role` en `App.jsx`; elementos interactivos como `<div onClick>` sin soporte de teclado (`ThreatCard` [:92](src/App.jsx#L92), nav superior [:1705-1707](src/App.jsx#L1705-L1707), menú de usuario [:1717](src/App.jsx#L1717)); modales sin focus trap ni `Escape` para cerrar; posibles fallos de contraste WCAG en textos secundarios (`#475569` sobre `#0f172a`).
- **Sistema de diseño / tokens**: cientos de valores de color hardcodeados repetidos en `style={{}}` sin ninguna fuente única de verdad; sin componentes compartidos (`Button`, `Modal`, `Table`) — cada vista reimplementa los suyos.
- **Limpieza menor**: `App.css` no está importado por ningún componente ([src/App.jsx:1622-1634](src/App.jsx#L1622-L1634) duplica sus keyframes inline) — código muerto a limpiar cuando se toque esta zona.

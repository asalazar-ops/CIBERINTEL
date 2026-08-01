import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Estandariza el trío loading/error/data que hoy se repite a mano en cada
 * componente (ver src/App.jsx: fetchAssets, loadEndpoints, loadSummary,
 * loadBehavior, y los tres paneles OTX). No reemplaza fetch() ni cambia el
 * backend — solo centraliza el manejo de estado alrededor de una llamada.
 *
 * Dos modos de uso:
 *  - Automático: pasar `url` para que se dispare solo al montar (y cuando
 *    cambien las `deps`), como reemplazo directo de un `useEffect(() => {
 *    fetch(...) }, [])`.
 *  - Manual: dejar `url` en null y llamar a `run(url, options)` desde un
 *    handler (click, submit) — para POST/DELETE/PUT disparados por el usuario.
 *
 * `run` siempre devuelve { data, error } en vez de lanzar, para que el
 * caller decida si necesita reaccionar (ej. cerrar un modal solo si no hubo
 * error) sin tener que envolver cada llamada en su propio try/catch.
 */
export function useApiFetch(url = null, { deps = [], skip = false } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const requestId = useRef(0);

  const run = useCallback(async (runUrl, options) => {
    const id = ++requestId.current;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(runUrl, options);
      let body = null;
      try { body = await res.json(); } catch { /* respuesta sin cuerpo JSON */ }

      if (!res.ok) {
        const message = body?.error || `Error del servidor: ${res.status}`;
        throw new Error(message);
      }

      // Ignora respuestas de una petición anterior si ya salió una más nueva
      // (evita condiciones de carrera en refresh rápido / cambios de filtro).
      if (id === requestId.current) {
        setData(body);
        setLoading(false);
      }
      return { data: body, error: null };
    } catch (err) {
      const message = err.message?.includes('fetch') ? 'Sin conexión al servidor.' : err.message;
      if (id === requestId.current) {
        setError(message);
        setLoading(false);
      }
      return { data: null, error: message };
    }
  }, []);

  useEffect(() => {
    if (url && !skip) run(url);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, skip, ...deps]);

  return { data, error, loading, run, setData };
}

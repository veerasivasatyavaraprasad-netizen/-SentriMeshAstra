import { useEffect, useRef, useState } from "react";
import { getApiBaseUrl } from "./runtimeConfig";

const API_BASE = getApiBaseUrl();
const WS_BASE = API_BASE.replace(/^http/, "ws");

/** Opens one WebSocket per active tenant (see app/routers/ws.py) and bumps
 * a counter on every push from the agent pipeline. Pages watch that
 * counter to refetch immediately — real-time, not polling. Reconnects
 * automatically with backoff if the connection drops. */
export function useTenantEventStream(tenantId) {
  const [version, setVersion] = useState(0);
  const [connected, setConnected] = useState(false);
  const retryCountRef = useRef(0);

  useEffect(() => {
    if (!tenantId) {
      setConnected(false);
      return undefined;
    }

    let socket;
    let retryTimer;
    let stopped = false;

    function connect() {
      const token = localStorage.getItem("sma_token");
      if (!token || stopped) return;

      socket = new WebSocket(`${WS_BASE}/ws/tenants/${tenantId}?token=${encodeURIComponent(token)}`);

      socket.onopen = () => {
        setConnected(true);
        retryCountRef.current = 0;
      };
      socket.onmessage = () => {
        setVersion((v) => v + 1);
      };
      socket.onclose = () => {
        setConnected(false);
        if (stopped) return;
        const delay = Math.min(15000, 500 * 2 ** retryCountRef.current);
        retryCountRef.current += 1;
        retryTimer = setTimeout(connect, delay);
      };
      socket.onerror = () => {
        socket.close();
      };
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(retryTimer);
      if (socket) {
        socket.onclose = null; // don't schedule a reconnect for our own cleanup close
        socket.close();
      }
    };
  }, [tenantId]);

  return { version, connected };
}

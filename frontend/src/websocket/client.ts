type WebSocketEventName =
  | "open"
  | "close"
  | "error"
  | "message"
  | "reconnecting";

type WebSocketListener = (...args: unknown[]) => void;

class EventBus {
  private listeners = new Map<WebSocketEventName, Set<WebSocketListener>>();

  on(event: WebSocketEventName, listener: WebSocketListener): void {
    const current = this.listeners.get(event);
    if (current) {
      current.add(listener);
      return;
    }

    this.listeners.set(event, new Set([listener]));
  }

  off(event: WebSocketEventName, listener?: WebSocketListener): void {
    const current = this.listeners.get(event);
    if (!current) {
      return;
    }

    if (!listener) {
      this.listeners.delete(event);
      return;
    }

    current.delete(listener);
    if (current.size === 0) {
      this.listeners.delete(event);
    }
  }

  emit(event: WebSocketEventName, ...args: unknown[]): void {
    const current = this.listeners.get(event);
    if (!current || current.size === 0) {
      return;
    }

    for (const listener of current) {
      listener(...args);
    }
  }

  removeAllListeners(): void {
    this.listeners.clear();
  }
}

export class WebSocketClient {
  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly events = new EventBus();

  constructor(
    private readonly url: string,
    private readonly reconnectDelayMs = 3000,
  ) {}

  connect(): void {
    if (
      this.socket &&
      (this.socket.readyState === WebSocket.CONNECTING ||
        this.socket.readyState === WebSocket.OPEN)
    ) {
      return;
    }

    this.clearReconnectTimer();
    this.socket = new WebSocket(this.url);

    this.socket.onopen = () => {
      this.events.emit("open");
    };

    this.socket.onmessage = (event) => {
      this.events.emit("message", event.data, event);
    };

    this.socket.onerror = (event) => {
      this.events.emit("error", event);
    };

    this.socket.onclose = (event) => {
      this.socket = null;
      this.events.emit("close", event);

      if (event.code !== 1000) {
        this.scheduleReconnect();
      }
    };
  }

  send(data: string | Blob | ArrayBufferLike | ArrayBufferView): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket is not connected");
    }

    this.socket.send(data);
  }

  disconnect(code = 1000, reason = "Client disconnected"): void {
    this.clearReconnectTimer();
    if (!this.socket) {
      return;
    }

    const activeSocket = this.socket;
    this.socket = null;
    activeSocket.close(code, reason);
  }

  on(event: WebSocketEventName, listener: WebSocketListener): void {
    this.events.on(event, listener);
  }

  off(event: WebSocketEventName, listener?: WebSocketListener): void {
    this.events.off(event, listener);
  }

  removeAllListeners(): void {
    this.events.removeAllListeners();
  }

  get readyState(): number {
    return this.socket?.readyState ?? WebSocket.CLOSED;
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null) {
      return;
    }

    this.events.emit("reconnecting", this.reconnectDelayMs);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.reconnectDelayMs);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer === null) {
      return;
    }

    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }
}

export default WebSocketClient;

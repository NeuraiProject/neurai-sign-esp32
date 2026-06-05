/**
 * Transport-agnostic NeuraiHW protocol layer.
 *
 * `SerialProtocol` implements the full NeuraiHW JSON command/response protocol
 * — the chunked-write firmware workaround, line buffering, JSON parsing, the
 * response queue and the various timeout strategies — on top of a byte-level
 * {@link IByteChannel}. This is the shared logic behind every transport: the
 * Web Serial `SerialConnection` and the React Native USB channel both reuse it,
 * so the platform-specific code only has to move raw bytes.
 *
 * If you build your own channel, you do NOT need to replicate the 256-byte /
 * 8 ms chunked writes — that lives here and applies to every channel.
 */

import type { DeviceResponse, IByteChannel, INeuraiTransport } from "./types.js";

export class SerialProtocol implements INeuraiTransport {
  private channel: IByteChannel;
  private responseQueue: DeviceResponse[] = [];
  private decoder = new TextDecoder();
  private encoder = new TextEncoder();
  private buffer = "";
  private opened = false;

  constructor(channel: IByteChannel) {
    this.channel = channel;
    this.channel.onData((chunk) => this.handleBytes(chunk));
  }

  get connected(): boolean {
    return this.opened && this.channel.isOpen;
  }

  async open(): Promise<void> {
    await this.channel.open();
    this.opened = true;

    // The device emits several plain-text boot lines before the first JSON
    // message; wait for it to settle, then drop anything buffered so far.
    await this.delay(1200);
    this.responseQueue = [];
    this.buffer = "";
  }

  async close(): Promise<void> {
    this.opened = false;
    await this.channel.close();
    this.responseQueue = [];
    this.buffer = "";
  }

  async sendCommand(command: Record<string, unknown>, timeoutMs = 65000): Promise<DeviceResponse> {
    await this.writeCommand(command, timeoutMs);

    const response = await this.waitForResponse(timeoutMs);
    if (!response) {
      throw new Error("Device response timeout");
    }

    return response;
  }

  async sendCommandFinal(command: Record<string, unknown>, timeoutMs = 65000): Promise<DeviceResponse> {
    await this.writeCommand(command, timeoutMs);

    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const response = await this.waitForResponse(timeoutMs - (Date.now() - startTime));
      if (!response) {
        throw new Error("Device response timeout");
      }
      if (response.status === "processing") {
        continue;
      }
      return response;
    }

    throw new Error("Device response timeout");
  }

  /**
   * Like {@link sendCommandFinal}, but the timeout window is reset on every
   * `processing` heartbeat instead of being a single global deadline. Suited to
   * long, multi-step operations (e.g. PQ ML-DSA signing of several inputs),
   * where each input may take many seconds and the device pings between steps.
   *
   * @param perResponseTimeoutMs max time to wait for the *next* message (reset per heartbeat)
   * @param maxTotalMs hard ceiling across the whole operation (safety net)
   */
  async sendCommandHeartbeat(
    command: Record<string, unknown>,
    perResponseTimeoutMs = 30000,
    maxTotalMs = 600000
  ): Promise<DeviceResponse> {
    await this.writeCommand(command, perResponseTimeoutMs);

    const startTime = Date.now();
    for (;;) {
      if (Date.now() - startTime > maxTotalMs) {
        throw new Error("Device response timeout");
      }
      const response = await this.waitForResponse(perResponseTimeoutMs);
      if (!response) {
        throw new Error("Device response timeout");
      }
      if (response.status === "processing") {
        // Heartbeat: keep waiting; the per-response window resets next iteration.
        continue;
      }
      return response;
    }
  }

  private async writeCommand(command: Record<string, unknown>, timeoutMs: number): Promise<void> {
    if (!this.channel.isOpen) {
      throw new Error("Serial port not connected");
    }

    this.responseQueue = [];

    const json = JSON.stringify(command);
    console.debug("[NeuraiESP32 Serial] Sending command", {
      action: command.action,
      payloadLength: json.length + 1,
      timeoutMs,
    });

    await this.writeChunked(json);
    // The newline terminator is sent separately, after all chunks, so the
    // firmware only processes the command once the full JSON has arrived.
    await this.channel.write(this.encoder.encode("\n"));
  }

  private handleBytes(chunk: Uint8Array): void {
    this.buffer += this.decoder.decode(chunk, { stream: true });

    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() ?? "";

    for (const rawLine of lines) {
      const line = rawLine.trim().replace(/\r/g, "");
      if (line.length === 0) continue;

      if (line.startsWith("{")) {
        try {
          const data = JSON.parse(line) as DeviceResponse;
          console.debug("[NeuraiESP32 Serial] JSON line received", data);
          this.responseQueue.push(data);
        } catch {
          console.debug("[NeuraiESP32 Serial] Invalid JSON line", line);
        }
      } else {
        console.debug("[NeuraiESP32 Serial] Non-JSON serial line", line);
      }
    }
  }

  private waitForResponse(timeoutMs: number): Promise<DeviceResponse | null> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const check = () => {
        if (this.responseQueue.length > 0) {
          const response = this.responseQueue.shift()!;
          console.debug("[NeuraiESP32 Serial] Response dequeued", {
            waitedMs: Date.now() - startTime,
            pendingResponses: this.responseQueue.length,
            status: response.status,
          });
          resolve(response);
        } else if (Date.now() - startTime > timeoutMs) {
          console.error("[NeuraiESP32 Serial] Response timeout", {
            timeoutMs,
            queuedResponses: this.responseQueue.length,
          });
          resolve(null);
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    });
  }

  /**
   * Split an outgoing message into small chunks. The ESP32 CDC serial buffer can
   * lose data when the host sends a large payload in a single write, so every
   * message is written in 256-byte chunks with an 8 ms pause between each one.
   */
  private async writeChunked(data: string, chunkSize = 256, pauseMs = 8): Promise<void> {
    const bytes = this.encoder.encode(data);
    const totalChunks = Math.ceil(bytes.length / chunkSize) || 1;
    const startedAt = Date.now();

    console.debug("[NeuraiESP32 Serial][writeChunked] start", {
      totalBytes: bytes.length,
      chunkSize,
      pauseMs,
      totalChunks,
    });

    for (let offset = 0, chunkIndex = 0; offset < bytes.length; offset += chunkSize, chunkIndex += 1) {
      const chunk = bytes.subarray(offset, offset + chunkSize);

      const writeStartedAt = Date.now();
      await this.channel.write(chunk);
      const writeMs = Date.now() - writeStartedAt;

      let actualPauseMs = 0;
      if (pauseMs > 0 && offset + chunkSize < bytes.length) {
        const pauseStartedAt = Date.now();
        await this.delay(pauseMs);
        actualPauseMs = Date.now() - pauseStartedAt;
      }

      console.debug("[NeuraiESP32 Serial][writeChunked] chunk", {
        chunkIndex: chunkIndex + 1,
        totalChunks,
        chunkBytes: chunk.length,
        writeMs,
        pauseMs: actualPauseMs,
      });
    }

    console.debug("[NeuraiESP32 Serial][writeChunked] complete", {
      totalBytes: bytes.length,
      totalChunks,
      totalMs: Date.now() - startedAt,
    });
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

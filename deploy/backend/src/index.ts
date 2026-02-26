import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  BACKEND_CONTAINER: DurableObjectNamespace<BackendContainer>;
}

export class BackendContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "5m";

  override get envVars(): Record<string, string> {
    return Object.fromEntries(
      Object.entries(this.ctx.env).filter(
        ([key]) =>
          key !== "BACKEND_CONTAINER" && typeof this.ctx.env[key] === "string"
      )
    ) as Record<string, string>;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const container = getContainer(
      env.BACKEND_CONTAINER.idFromName("backend"),
      env.BACKEND_CONTAINER
    );
    return container.fetch(request);
  },
};

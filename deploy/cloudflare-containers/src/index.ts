import { Container } from "@cloudflare/containers";

const CACHE_INSTANCE = "singleton";
const CACHE_PORT = 8081;
const DEMO_RP = "2af138a8-59ea-4a84-aea3-666cafdb1369";

type CacheEnv = {
  AUGENMASS_CACHE_ADMIN_TOKEN?: string;
  AUGENMASS_CACHE_ALLOWED_RPS?: string;
  AUGENMASS_CACHE_CONTAINER: DurableObjectNamespace<AugenmassCacheContainer>;
  AUGENMASS_CACHE_MAX_ENTRIES?: string;
  AUGENMASS_CACHE_TIMEOUT_SECS?: string;
  AUGENMASS_CACHE_TTL_SECS?: string;
  AUGENMASS_CACHE_UPSTREAM?: string;
};

export class AugenmassCacheContainer extends Container {
  defaultPort = CACHE_PORT;
  requiredPorts = [CACHE_PORT];
  sleepAfter = "2h";
  enableInternet = true;
  pingEndpoint = "/api/health";
}

export default {
  async fetch(request: Request, env: CacheEnv): Promise<Response> {
    if (!env.AUGENMASS_CACHE_ADMIN_TOKEN) {
      return new Response("AUGENMASS_CACHE_ADMIN_TOKEN must be set as a Worker secret.", {
        status: 503,
        headers: { "content-type": "text/plain; charset=utf-8" }
      });
    }

    const container = env.AUGENMASS_CACHE_CONTAINER.getByName(CACHE_INSTANCE);
    await container.startAndWaitForPorts({
      ports: [CACHE_PORT],
      startOptions: {
        envVars: cacheEnvVars(env)
      }
    });
    return container.fetch(request);
  }
};

function cacheEnvVars(env: CacheEnv): Record<string, string> {
  return {
    AUGENMASS_CACHE_ADMIN_TOKEN: env.AUGENMASS_CACHE_ADMIN_TOKEN ?? "",
    AUGENMASS_CACHE_ALLOWED_RPS: env.AUGENMASS_CACHE_ALLOWED_RPS ?? DEMO_RP,
    AUGENMASS_CACHE_DB: "/data/augenmass-cache.sqlite",
    AUGENMASS_CACHE_HOST: "0.0.0.0",
    AUGENMASS_CACHE_MAX_ENTRIES: env.AUGENMASS_CACHE_MAX_ENTRIES ?? "512",
    AUGENMASS_CACHE_PORT: String(CACHE_PORT),
    AUGENMASS_CACHE_TIMEOUT_SECS: env.AUGENMASS_CACHE_TIMEOUT_SECS ?? "10",
    AUGENMASS_CACHE_TTL_SECS: env.AUGENMASS_CACHE_TTL_SECS ?? "3600",
    AUGENMASS_CACHE_UPSTREAM: env.AUGENMASS_CACHE_UPSTREAM ?? "https://sandbox.eudi-wallet.org/api"
  };
}

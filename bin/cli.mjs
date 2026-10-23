#!/usr/bin/env node

// src/cli-source.ts
import fs5 from "node:fs";
import path5 from "node:path";

// src/agents/polyglot/detector.ts
function detectRemoteTechStack(headers) {
  const getH = (name) => (headers.get(name) || "").toLowerCase();
  const serverHeader = headers.get("server") || "";
  const xPowered = headers.get("x-powered-by") || "";
  const via = headers.get("via") || "";
  const sLower = serverHeader.toLowerCase();
  const vLower = via.toLowerCase();
  let server = "Servidor Web Oculto / Personalizado";
  let cdnOrProxy;
  let frameworkHint;
  let versionExposed = false;
  if (sLower.includes("cloudflare") || headers.get("cf-ray") || headers.get("cf-cache-status")) {
    cdnOrProxy = "Cloudflare Edge Global CDN";
    server = "Cloudflare Edge";
  } else if (vLower.includes("cloudfront") || headers.get("x-amz-cf-id") || headers.get("x-amz-cf-pop")) {
    cdnOrProxy = "AWS CloudFront CDN";
    server = "Amazon Web Services (CloudFront)";
  } else if (vLower.includes("fastly") || headers.get("x-served-by")?.includes("cache-") || headers.get("fastly-restarts")) {
    cdnOrProxy = "Fastly Real-Time Edge";
    server = "Fastly Edge Network";
  } else if (headers.get("x-akamai-transformed") || sLower.includes("akamaighost")) {
    cdnOrProxy = "Akamai Intelligent Edge";
    server = "Akamai Edge Platform";
  } else if (headers.get("x-vercel-id") || headers.get("x-vercel-cache") || sLower.includes("vercel")) {
    cdnOrProxy = "Vercel Edge Network";
    server = "Vercel Serverless Edge";
  } else if (headers.get("x-nf-request-id") || sLower.includes("netlify")) {
    cdnOrProxy = "Netlify Global Edge";
    server = "Netlify Edge Server";
  } else if (vLower.includes("varnish") || headers.get("x-varnish")) {
    cdnOrProxy = "Varnish Cache Reverse Proxy";
  }
  if (sLower.includes("nginx")) {
    server = serverHeader;
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("apache")) {
    server = serverHeader;
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("caddy")) {
    server = "Caddy Modern Web Server";
  } else if (sLower.includes("litespeed") || sLower.includes("openlitespeed")) {
    server = "LiteSpeed High-Performance Web Server";
  } else if (sLower.includes("traefik")) {
    server = "Traefik Cloud Native Edge Router";
  } else if (sLower.includes("envoy") || headers.get("x-envoy-upstream-service-time")) {
    server = "Envoy Proxy (Service Mesh / Cloud Native)";
  } else if (sLower.includes("openresty")) {
    server = "OpenResty (Nginx + Lua Engine)";
  } else if (sLower.includes("microsoft-iis") || sLower.includes("iis")) {
    server = serverHeader || "Microsoft IIS Web Server";
    if (/\d+\.\d+/.test(serverHeader)) versionExposed = true;
  } else if (sLower.includes("gunicorn") || sLower.includes("uvicorn")) {
    server = "Python WSGI/ASGI Server (Gunicorn/Uvicorn)";
  } else if (sLower.includes("kestrel")) {
    server = "Kestrel (.NET Core Web Server)";
  } else if (sLower.includes("kong")) {
    server = "Kong API Gateway";
  } else if (serverHeader && server === "Servidor Web Oculto / Personalizado") {
    server = serverHeader;
  }
  const xpLower = xPowered.toLowerCase();
  if (xpLower.includes("next.js") || headers.get("x-nextjs-cache")) frameworkHint = "Next.js (React Fullstack)";
  else if (xpLower.includes("express")) frameworkHint = "Express.js (Node.js)";
  else if (xpLower.includes("php")) frameworkHint = xPowered;
  else if (xpLower.includes("asp.net")) frameworkHint = "ASP.NET (.NET)";
  else if (xpLower.includes("nuxt")) frameworkHint = "Nuxt.js (Vue Fullstack)";
  else if (headers.get("x-drupal-cache")) frameworkHint = "Drupal CMS (PHP)";
  else if (headers.get("x-pingback")?.includes("xmlrpc.php")) frameworkHint = "WordPress CMS (PHP)";
  else if (headers.get("x-django-version")) frameworkHint = "Django (Python)";
  return {
    server,
    frameworkHint,
    cdnOrProxy,
    rawServerHeader: serverHeader || void 0,
    versionExposed
  };
}

// src/lib/security/cookie-cors-analyzer.ts
function analyzeSetCookieHeader(cookieStr) {
  const parts = cookieStr.split(";").map((p) => p.trim());
  const [nameValue, ...attributes] = parts;
  const name = nameValue.split("=")[0] || "";
  const attrLower = attributes.map((a) => a.toLowerCase());
  const isHttpOnly = attrLower.some((a) => a === "httponly");
  const isSecure = attrLower.some((a) => a === "secure");
  let sameSite = "Missing";
  const sameSiteAttr = attributes.find((a) => a.toLowerCase().startsWith("samesite="));
  if (sameSiteAttr) {
    const val = sameSiteAttr.split("=")[1]?.trim().toLowerCase();
    if (val === "strict") sameSite = "Strict";
    else if (val === "lax") sameSite = "Lax";
    else if (val === "none") sameSite = "None";
  }
  const issues = [];
  let prefixType = "none";
  let hasPrefix = false;
  if (name.startsWith("__Host-")) {
    prefixType = "__Host-";
    hasPrefix = true;
  } else if (name.startsWith("__Secure-")) {
    prefixType = "__Secure-";
    hasPrefix = true;
  }
  if (!isHttpOnly) {
    issues.push("Aus\xEAncia da flag 'HttpOnly': Cookie vulner\xE1vel a exfiltra\xE7\xE3o via Cross-Site Scripting (XSS).");
  }
  if (!isSecure) {
    issues.push("Aus\xEAncia da flag 'Secure': Cookie pode ser transmitido em conex\xF5es HTTP inseguras.");
  }
  if (sameSite === "Missing" || sameSite === "None") {
    issues.push("Configura\xE7\xE3o frouxa de SameSite: Cookie vulner\xE1vel a ataques de Cross-Site Request Forgery (CSRF).");
  }
  if (prefixType === "__Host-") {
    if (!isSecure) {
      issues.push("Prefixo __Host- exige flag 'Secure' ativa.");
    }
  }
  let severity = "PASSED";
  if (!isHttpOnly && !isSecure) severity = "HIGH";
  else if (!isHttpOnly || !isSecure) severity = "MEDIUM";
  else if (sameSite === "Missing") severity = "LOW";
  return {
    name,
    isHttpOnly,
    isSecure,
    sameSite,
    hasPrefix,
    prefixType,
    issues,
    severity
  };
}
function analyzeCorsHeaders(headers) {
  const getHeader = (key) => {
    if (typeof headers.get === "function") {
      return headers.get(key);
    }
    const rec = headers;
    const lowerKey = key.toLowerCase();
    for (const [k, v] of Object.entries(rec)) {
      if (k.toLowerCase() === lowerKey) return v;
    }
    return null;
  };
  const allowOrigin = getHeader("access-control-allow-origin") || void 0;
  const allowCredsStr = getHeader("access-control-allow-credentials");
  const allowCredentials = allowCredsStr?.toLowerCase() === "true";
  const allowMethodsStr = getHeader("access-control-allow-methods");
  const allowMethods = allowMethodsStr ? allowMethodsStr.split(",").map((m) => m.trim()) : void 0;
  const exposeHeadersStr = getHeader("access-control-expose-headers");
  const exposeHeaders = exposeHeadersStr ? exposeHeadersStr.split(",").map((h) => h.trim()) : void 0;
  const maxAgeStr = getHeader("access-control-max-age");
  const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : void 0;
  const vary = getHeader("vary") || "";
  const issues = [];
  let hasWildcardWithCredentials = false;
  let hasInsecureOriginReflection = false;
  let isMissingVaryOrigin = false;
  if (allowOrigin === "*" && allowCredentials) {
    hasWildcardWithCredentials = true;
    issues.push("CORS Cr\xEDtico: 'Access-Control-Allow-Origin: *' combinado com 'Access-Control-Allow-Credentials: true' permite roubo de credenciais cross-origin.");
  }
  if (allowOrigin === "null") {
    issues.push("CORS Inseguro: 'Access-Control-Allow-Origin: null' pode ser explorado via iframes 'sandboxed' maliciosos.");
  }
  if (allowOrigin && allowOrigin !== "*" && !vary.toLowerCase().includes("origin")) {
    isMissingVaryOrigin = true;
    issues.push("Cache Poisoning Risk: Falta o cabe\xE7alho 'Vary: Origin' quando origens din\xE2micas s\xE3o permitidas.");
  }
  let severity = "PASSED";
  if (hasWildcardWithCredentials || allowOrigin === "null") severity = "HIGH";
  else if (issues.length > 0) severity = "MEDIUM";
  return {
    allowOrigin,
    allowCredentials,
    allowMethods,
    exposeHeaders,
    maxAge,
    hasWildcardWithCredentials,
    hasInsecureOriginReflection,
    isMissingVaryOrigin,
    issues,
    severity
  };
}
function runBurpHeaderAudit(headers, rawCookies = []) {
  const cookieResults = rawCookies.map(analyzeSetCookieHeader);
  const corsResult = analyzeCorsHeaders(headers);
  const findingsCount = cookieResults.filter((c) => c.severity !== "PASSED").length + (corsResult.severity !== "PASSED" ? 1 : 0);
  return {
    cookies: cookieResults,
    cors: corsResult,
    findingsCount
  };
}

// src/lib/security/attack-chain-analyzer.ts
function buildAttackChainGraph(targetUrl, defenses) {
  const nodes = [];
  const edges = [];
  const primaryPath = [];
  const priorities = [];
  if (defenses.serverVersionExposed) {
    nodes.push({
      id: "node-recon-server",
      stage: "RECON",
      title: "Identifica\xE7\xE3o de Vers\xE3o de Servidor Web (Server Fingerprinting)",
      description: "O cabe\xE7alho 'Server' exp\xF5e a vers\xE3o exata do software, permitindo mapeamento de CVEs conhecidas.",
      vector: "Banner Grabbing / Version Header",
      mitreTechnique: "T1592.002 (Gather Victim Host Information: Software)"
    });
    primaryPath.push("Identifica\xE7\xE3o de Vers\xE3o");
  }
  if (!defenses.hasCsp) {
    nodes.push({
      id: "node-xss-injection",
      stage: "INITIAL_ACCESS",
      title: "Inje\xE7\xE3o de Scripts Maliciosos (Cross-Site Scripting - XSS)",
      description: "A aus\xEAncia de Content-Security-Policy permite execu\xE7\xE3o irrestrita de scripts no contexto da v\xEDtima.",
      vector: "DOM / Reflected / Stored XSS",
      mitreTechnique: "T1189 (Drive-by Compromise / Browser Exploitation)"
    });
    primaryPath.push("Inje\xE7\xE3o de Script (XSS)");
    priorities.push("Configurar Content-Security-Policy (CSP) com restri\xE7\xE3o default-src e nonce/hashes.");
    if (nodes.some((n) => n.id === "node-recon-server")) {
      edges.push({
        fromNodeId: "node-recon-server",
        toNodeId: "node-xss-injection",
        condition: "Atacante seleciona payloads compat\xEDveis com a vers\xE3o do servidor.",
        likelihood: "HIGH"
      });
    }
  }
  if (!defenses.hasCsp && !defenses.hasSecureCookies) {
    nodes.push({
      id: "node-session-hijack",
      stage: "EXECUTION",
      title: "Exfiltra\xE7\xE3o de Cookies e Sequestro de Sess\xE3o (Session Hijacking)",
      description: "Cookies de autentica\xE7\xE3o sem a flag HttpOnly s\xE3o lidos via document.cookie pelo script XSS e enviados para servidor C2.",
      vector: "Document Cookie Exfiltration",
      mitreTechnique: "T1539 (Steal Web Session Cookie)"
    });
    primaryPath.push("Roubo de Cookie (Session Hijacking)");
    priorities.push("Habilitar flag HttpOnly e prefixos __Host- em todos os cookies de sess\xE3o.");
    edges.push({
      fromNodeId: "node-xss-injection",
      toNodeId: "node-session-hijack",
      condition: "Script malicioso executa document.cookie no navegador da v\xEDtima.",
      likelihood: "HIGH"
    });
  }
  if (!defenses.hasXFrameOptions) {
    nodes.push({
      id: "node-clickjacking",
      stage: "INITIAL_ACCESS",
      title: "Sequestro de Interface e A\xE7\xF5es Invis\xEDveis (Clickjacking)",
      description: "P\xE1ginas autenticadas podem ser incorporadas em iframes transparentes para induzir cliques involunt\xE1rios.",
      vector: "Transparent iFrame Overlay",
      mitreTechnique: "T1204.001 (User Execution: Malicious Link / UI Redress)"
    });
    priorities.push("Adicionar 'X-Frame-Options: DENY' e diretiva CSP 'frame-ancestors 'none''.");
    if (primaryPath.length === 0) {
      primaryPath.push("Clickjacking / UI Redressing");
    }
  }
  if (!defenses.hasHsts) {
    nodes.push({
      id: "node-hsts-downgrade",
      stage: "INITIAL_ACCESS",
      title: "Intercepta\xE7\xE3o de Tr\xE1fego e Downgrade para HTTP (SSL Strip)",
      description: "A falta de HSTS permite que atacantes na mesma rede interceptem a primeira requisi\xE7\xE3o e forcem HTTP plano.",
      vector: "ARP Spoofing / SSL Striping",
      mitreTechnique: "T1557.001 (Man-in-the-Middle: LLMNR/NBT-NS & SSL Strip)"
    });
    priorities.push("Habilitar 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.");
  }
  let maxImpactLevel = "LOW";
  if (nodes.some((n) => n.id === "node-session-hijack")) {
    nodes.push({
      id: "node-account-takeover",
      stage: "IMPACT",
      title: "Tomada Completa de Conta & Acesso Administrativo (Account Takeover)",
      description: "Atacante utiliza a sess\xE3o roubada para assumir identidade leg\xEDtima e acessar dados internos.",
      vector: "Authenticated Impersonation",
      mitreTechnique: "T1078 (Valid Accounts)"
    });
    primaryPath.push("Comprometimento de Conta (Account Takeover)");
    maxImpactLevel = "CRITICAL";
    edges.push({
      fromNodeId: "node-session-hijack",
      toNodeId: "node-account-takeover",
      condition: "Atacante replica token em cabe\xE7alho Authorization/Cookie.",
      likelihood: "HIGH"
    });
  } else if (nodes.some((n) => n.id === "node-xss-injection") || nodes.some((n) => n.id === "node-clickjacking")) {
    maxImpactLevel = "HIGH";
  } else if (nodes.length > 0) {
    maxImpactLevel = "MEDIUM";
  }
  const riskSummary = primaryPath.length > 1 ? `Cadeia de Ataque Detectada: ${primaryPath.join(" \u2794 ")}` : nodes.length > 0 ? `Superf\xEDcie de Risco Identificada com ${nodes.length} vetores potenciais de invas\xE3o.` : "Nenhum vetor cr\xEDtico de encadeamento de ataque detectado nas camadas de borda.";
  return {
    target: targetUrl,
    riskSummary,
    primaryAttackPath: primaryPath,
    nodes,
    edges,
    maxImpactLevel,
    tacticalDefensePriority: priorities
  };
}

// src/scanner/universal-web-scanner.ts
function generateRemediationSnippets(serverName) {
  const snippets = [];
  snippets.push({
    serverType: "NGINX (/etc/nginx/conf.d/security.conf)",
    snippet: `add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "microphone=(self), camera=(), geolocation=(), payment=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';" always;
server_tokens off;`
  });
  snippets.push({
    serverType: "APACHE (.htaccess / httpd.conf)",
    snippet: `<IfModule mod_headers.c>
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "microphone=(self), camera=(), geolocation=(), payment=()"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';"
</IfModule>
ServerSignature Off
ServerTokens Prod`
  });
  snippets.push({
    serverType: "VERCEL (vercel.json)",
    snippet: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "microphone=(self), camera=(), geolocation=(), payment=()" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; object-src 'none';" }
      ]
    }
  ]
}`
  });
  snippets.push({
    serverType: "PYTHON FASTAPI (main.py)",
    snippet: `from fastapi import FastAPI, Response, Request
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        return response

app.add_middleware(SecurityHeadersMiddleware)`
  });
  snippets.push({
    serverType: "NODE.JS EXPRESS (app.js / server.ts)",
    snippet: `import express from "express";
import helmet from "helmet";

const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: "deny" },
  noSniff: true,
}));`
  });
  snippets.push({
    serverType: "GO FIBER (main.go)",
    snippet: `package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/helmet"
)

func main() {
    app := fiber.New()
    app.Use(helmet.New(helmet.Config{
        XFrameOptions: "DENY",
        ContentTypeNosniff: "nosniff",
        HSTSMaxAge: 31536000,
        ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none';",
        ReferrerPolicy: "strict-origin-when-cross-origin",
    }))
    app.Listen(":3000")
}`
  });
  snippets.push({
    serverType: "PYTHON DJANGO (settings.py)",
    snippet: `SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")`
  });
  snippets.push({
    serverType: "PHP LARAVEL (app/Http/Middleware/SecurityHeaders.php)",
    snippet: `public function handle($request, Closure $next)
{
    $response = $next($request);
    $response->headers->set('X-Frame-Options', 'DENY');
    $response->headers->set('X-Content-Type-Options', 'nosniff');
    $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
    $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';");
    return $response;
}`
  });
  snippets.push({
    serverType: "JAVA SPRING BOOT (SecurityConfig.java)",
    snippet: `@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .frameOptions(frame -> frame.deny())
        .contentTypeOptions(Customizer.withDefaults())
        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"))
    );
    return http.build();
}`
  });
  snippets.push({
    serverType: "C# ASP.NET CORE (Program.cs)",
    snippet: `app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none';");
    await next();
});`
  });
  return snippets;
}
async function auditUniversalEndpoint(targetUrl) {
  const url = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
  let res;
  try {
    res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: AbortSignal.timeout(5e3)
    });
  } catch (err) {
    const msg = (err?.message || "").toLowerCase();
    const causeMsg = String(err?.cause?.message || err?.cause?.code || "").toLowerCase();
    if (msg.includes("abort") || msg.includes("timeout")) {
      throw new Error("Tempo limite de conex\xE3o esgotado (timeout). O servidor alvo demorou a responder.");
    }
    if (msg.includes("fetch failed") || causeMsg.includes("enotfound") || causeMsg.includes("eai_again")) {
      throw new Error("N\xE3o foi poss\xEDvel localizar o endere\xE7o (DNS/Dom\xEDnio n\xE3o encontrado). Verifique se o dom\xEDnio foi digitado corretamente.");
    }
    if (causeMsg.includes("econnrefused")) {
      throw new Error("Conex\xE3o recusada pelo servidor de destino.");
    }
    throw new Error(err?.message || "Falha ao conectar com o servidor alvo.");
  }
  const headers = res.headers;
  const finalUrl = res.url || url;
  const stack = detectRemoteTechStack(headers);
  const cspEnforcing = headers.get("content-security-policy");
  const cspReportOnly = headers.get("content-security-policy-report-only");
  const cspValue = cspEnforcing || cspReportOnly;
  const xFrame = headers.get("x-frame-options");
  const nosniff = headers.get("x-content-type-options");
  const perm = headers.get("permissions-policy");
  const hsts = headers.get("strict-transport-security");
  const referrer = headers.get("referrer-policy");
  const coop = headers.get("cross-origin-opener-policy");
  const rawSetCookies = [];
  if (typeof headers.getSetCookie === "function") {
    rawSetCookies.push(...headers.getSetCookie());
  } else {
    const sc = headers.get("set-cookie");
    if (sc) rawSetCookies.push(sc);
  }
  const burpInspection = runBurpHeaderAudit(headers, rawSetCookies);
  const attackChain = buildAttackChainGraph(finalUrl, {
    hasCsp: !!cspEnforcing,
    hasXFrameOptions: !!xFrame,
    hasHsts: !!hsts,
    hasNosniff: !!nosniff,
    hasPermissionsPolicy: !!perm,
    hasSecureCookies: burpInspection.cookies.length === 0 || burpInspection.cookies.every((c) => c.isHttpOnly && c.isSecure),
    hasStrictCors: burpInspection.cors.severity === "PASSED",
    serverVersionExposed: stack.versionExposed
  });
  const isSecure = !!(cspEnforcing && xFrame && nosniff && perm && hsts);
  const snippets = generateRemediationSnippets(stack.server);
  return {
    targetUrl: finalUrl,
    httpStatus: res.status,
    serverDetected: stack.server,
    frameworkDetected: stack.frameworkHint,
    cdnOrProxy: stack.cdnOrProxy,
    versionExposed: stack.versionExposed,
    securityHeaders: {
      csp: {
        present: !!cspValue,
        value: cspValue || void 0,
        isReportOnly: !cspEnforcing && !!cspReportOnly
      },
      xFrameOptions: { present: !!xFrame, value: xFrame || void 0 },
      xContentTypeOptions: { present: !!nosniff, value: nosniff || void 0 },
      permissionsPolicy: { present: !!perm, value: perm || void 0 },
      hsts: { present: !!hsts, value: hsts || void 0 },
      referrerPolicy: { present: !!referrer, value: referrer || void 0 },
      coop: { present: !!coop, value: coop || void 0 }
    },
    burpInspection,
    attackChain,
    remediationSnippets: snippets,
    overallStatus: isSecure ? "SECURE" : "ACTION_REQUIRED"
  };
}

// src/lib/security/captcha.ts
var CAPTCHA_TTL_MS = 120 * 1e3;

// src/lib/security/token.ts
var DEFAULT_SECRET = process.env.SUPABASE_JWT_SECRET || process.env.RATE_LIMIT_SECRET || "default-secret-jwt-key-min-32-chars";

// src/lib/security/dns-security-analyzer.ts
function parseSpfRecord(txtRecords) {
  const spfRaw = txtRecords.find((r) => r.toLowerCase().startsWith("v=spf1"));
  if (!spfRaw) {
    return {
      present: false,
      hasWildcardPass: false,
      lookupCountEstimate: 0,
      isCompliant: false,
      verdict: "Aus\xEAncia de SPF: Qualquer servidor no mundo pode forjar emails em nome do dom\xEDnio.",
      issues: ["Crie uma entrada TXT com 'v=spf1 ... -all' autorizando apenas seus servidores de email leg\xEDtimos."]
    };
  }
  const parts = spfRaw.split(/\s+/);
  let qualifier = "~all";
  const issues = [];
  let lookupCount = 0;
  for (const part of parts) {
    const pLower = part.toLowerCase();
    if (pLower.startsWith("include:") || pLower.startsWith("a") || pLower.startsWith("mx") || pLower.startsWith("ptr:") || pLower.startsWith("exists:")) {
      lookupCount++;
    }
    if (pLower === "-all") qualifier = "-all";
    else if (pLower === "~all") qualifier = "~all";
    else if (pLower === "?all") qualifier = "?all";
    else if (pLower === "+all" || pLower === "all") qualifier = "+all";
  }
  const hasWildcardPass = qualifier === "+all";
  if (hasWildcardPass) {
    issues.push("VULNERABILIDADE CR\xCDTICA: '+all' autoriza qualquer IP na internet a enviar emails em seu nome.");
  }
  if (qualifier === "?all") {
    issues.push("Qualificador neutro '?all' n\xE3o instrui servidores a rejeitarem mensagens n\xE3o autorizadas.");
  }
  if (lookupCount > 10) {
    issues.push(`Excesso de Lookups DNS (${lookupCount} > 10). Excede o limite da RFC 7208 e pode invalidar o SPF (PermError).`);
  }
  const isCompliant = (qualifier === "-all" || qualifier === "~all") && !hasWildcardPass && lookupCount <= 10;
  let verdict = "SPF configurado corretamente com restri\xE7\xE3o de remetentes.";
  if (hasWildcardPass) verdict = "SPF Perigoso (+all): Permite spoofing irrestrito de email.";
  else if (qualifier === "-all") verdict = "SPF Blindado (HardFail -all): Rejei\xE7\xE3o estrita de remetentes n\xE3o autorizados.";
  else if (qualifier === "~all") verdict = "SPF Moderado (SoftFail ~all): Mensagens n\xE3o autorizadas s\xE3o marcadas como spam.";
  return {
    present: true,
    rawRecord: spfRaw,
    qualifier,
    hasWildcardPass,
    lookupCountEstimate: lookupCount,
    isCompliant,
    verdict,
    issues
  };
}
function parseDmarcRecord(txtRecords) {
  const dmarcRaw = txtRecords.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
  if (!dmarcRaw) {
    return {
      present: false,
      percentage: 0,
      isEnforcing: false,
      verdict: "Aus\xEAncia de DMARC: Dom\xEDnio desprotegido contra ataques de Business Email Compromise (BEC) e Phishing.",
      issues: ["Configure uma entrada TXT em '_dmarc.seudominio.com' com pol\xEDtica 'v=DMARC1; p=reject; rua=mailto:dmarc@seudominio.com'."]
    };
  }
  const tags = dmarcRaw.split(";").map((t) => t.trim());
  let policy = "none";
  let subdomainPolicy;
  let percentage = 100;
  let aggregateReportUri;
  let forensicReportUri;
  const issues = [];
  for (const tag of tags) {
    const [key, val] = tag.split("=").map((s) => s?.trim());
    if (!key || !val) continue;
    const kLower = key.toLowerCase();
    const vLower = val.toLowerCase();
    if (kLower === "p") {
      if (vLower === "reject") policy = "reject";
      else if (vLower === "quarantine") policy = "quarantine";
      else policy = "none";
    }
    if (kLower === "sp") {
      if (vLower === "reject") subdomainPolicy = "reject";
      else if (vLower === "quarantine") subdomainPolicy = "quarantine";
      else subdomainPolicy = "none";
    }
    if (kLower === "pct") {
      percentage = parseInt(val, 10) || 100;
    }
    if (kLower === "rua") aggregateReportUri = val;
    if (kLower === "ruf") forensicReportUri = val;
  }
  if (policy === "none") {
    issues.push("Pol\xEDtica DMARC 'p=none' atua apenas como telemetria e N\xC3O bloqueia emails falsificados.");
  }
  if (percentage < 100) {
    issues.push(`Apenas ${percentage}% das mensagens sofrem aplica\xE7\xE3o da regra DMARC.`);
  }
  if (!aggregateReportUri) {
    issues.push("Nenhum endere\xE7o 'rua' configurado para receber relat\xF3rios agregados de tentativas de spoofing.");
  }
  const isEnforcing = policy === "reject" || policy === "quarantine";
  let verdict = "DMARC Ativo em Modo de Bloqueio.";
  if (policy === "reject") verdict = "DMARC M\xE1ximo (p=reject): Emails falsificados s\xE3o terminantemente descartados.";
  else if (policy === "quarantine") verdict = "DMARC M\xE9dio (p=quarantine): Emails falsificados s\xE3o isolados em quarentena/spam.";
  else verdict = "DMARC Apenas Monitoramento (p=none): N\xE3o impede envio de emails falsos.";
  return {
    present: true,
    rawRecord: dmarcRaw,
    policy,
    subdomainPolicy,
    percentage,
    aggregateReportUri,
    forensicReportUri,
    isEnforcing,
    verdict,
    issues
  };
}
async function queryDohRecords(domain, type) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(3500)
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!data.Answer || !Array.isArray(data.Answer)) return [];
    return data.Answer.map((a) => {
      let dataStr = String(a.data || "");
      if (dataStr.startsWith('"') && dataStr.endsWith('"')) {
        dataStr = dataStr.slice(1, -1);
      }
      return dataStr;
    });
  } catch {
    return [];
  }
}
async function auditDomainDnsSecurity(domainInput) {
  const cleanDomain = domainInput.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim().toLowerCase();
  const [domainTxt, dmarcTxt, mxRecords, dsRecords] = await Promise.all([
    queryDohRecords(cleanDomain, "TXT"),
    queryDohRecords(`_dmarc.${cleanDomain}`, "TXT"),
    queryDohRecords(cleanDomain, "MX"),
    queryDohRecords(cleanDomain, "DS")
  ]);
  const spf = parseSpfRecord(domainTxt);
  const dmarc = parseDmarcRecord(dmarcTxt);
  const dnssecActive = dsRecords.length > 0;
  const hasMxRecords = mxRecords.length > 0;
  let score = 0;
  const recommendations = [];
  if (spf.present && spf.isCompliant) {
    score += spf.qualifier === "-all" ? 40 : 30;
  } else if (spf.present) {
    score += 15;
  } else {
    recommendations.push("Publicar registro SPF (TXT) com '-all' para autenticar provedores de envio.");
  }
  if (dmarc.present && dmarc.isEnforcing) {
    score += dmarc.policy === "reject" ? 45 : 35;
  } else if (dmarc.present) {
    score += 15;
    recommendations.push("Evoluir a pol\xEDtica DMARC de 'p=none' para 'p=quarantine' ou 'p=reject'.");
  } else {
    recommendations.push("Configurar registro DMARC (_dmarc) para prote\xE7\xE3o ativa contra Phishing e BEC.");
  }
  if (dnssecActive) {
    score += 15;
  } else {
    recommendations.push("Ativar DNSSEC no registrador do dom\xEDnio para prote\xE7\xE3o contra envenenamento de cache DNS.");
  }
  score = Math.min(100, score);
  let overallStatus = "CRITICAL";
  if (score >= 80) overallStatus = "SECURE";
  else if (score >= 50) overallStatus = "WARNING";
  return {
    domain: cleanDomain,
    hasMxRecords,
    mxServers: mxRecords,
    spf,
    dmarc,
    dnssecActive,
    emailSecurityScore: score,
    overallStatus,
    recommendations
  };
}

// src/lib/security/crypto-entropy-analyzer.ts
function calculatePasswordEntropy(password) {
  const len = password.length;
  if (len === 0) {
    return {
      entropyBits: 0,
      charsetSize: 0,
      length: 0,
      strengthCategory: "VERY_WEAK",
      estimatedCrackTimeGpuCluster: "Instant\xE2neo (0s)",
      recommendations: ["Forne\xE7a uma senha n\xE3o vazia."]
    };
  }
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 33;
  const entropyBits = Math.round(len * Math.log2(charset || 1));
  const recommendations = [];
  let strength = "VERY_WEAK";
  let crackTime = "Instant\xE2neo (< 1 segundo)";
  if (entropyBits < 36) {
    strength = "VERY_WEAK";
    crackTime = "Menos de 1 segundo";
    recommendations.push("Aumente o comprimento da senha para pelo menos 14 caracteres.");
  } else if (entropyBits < 56) {
    strength = "WEAK";
    crackTime = "Alguns minutos / horas em GPU cluster (RTX 4090)";
    recommendations.push("Adicione caracteres especiais, n\xFAmeros e letras mai\xFAsculas.");
  } else if (entropyBits < 72) {
    strength = "FAIR";
    crackTime = "Alguns meses a anos";
    recommendations.push("Considere utilizar uma frase-senha (passphrase) de 4+ palavras aleat\xF3rias.");
  } else if (entropyBits < 96) {
    strength = "STRONG";
    crackTime = "Centenas de anos (Resistente a ataques de for\xE7a bruta)";
  } else {
    strength = "VERY_STRONG";
    crackTime = "Milh\xF5es de anos (Seguran\xE7a criptogr\xE1fica de n\xEDvel militar)";
  }
  return {
    entropyBits,
    charsetSize: charset,
    length: len,
    strengthCategory: strength,
    estimatedCrackTimeGpuCluster: crackTime,
    recommendations
  };
}

// src/lib/security/local-secret-scanner.ts
import fs2 from "node:fs";
import path2 from "node:path";

// src/lib/security/custom-rule-loader.ts
import fs from "node:fs";
import path from "node:path";
function compileCustomRules(definitions) {
  const compiled = [];
  for (const def of definitions) {
    if (!def.id || !def.pattern || !def.description) continue;
    try {
      const regex = new RegExp(def.pattern, def.flags || "");
      compiled.push({
        id: def.id,
        category: def.category || "API_KEY",
        description: def.description,
        regex,
        severity: def.severity || "HIGH"
      });
    } catch (err) {
      console.warn(`[RULES] Aviso: Padr\xE3o regex inv\xE1lido na regra customizada '${def.id}': ${err.message}`);
    }
  }
  return compiled;
}
function loadCustomSecurityRules(targetDir = process.cwd()) {
  const rulesJsonPath = path.resolve(targetDir, "obsidiansec.rules.json");
  const configJsonPath = path.resolve(targetDir, "obsidiansec.config.json");
  try {
    if (fs.existsSync(rulesJsonPath)) {
      const raw = fs.readFileSync(rulesJsonPath, "utf-8");
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : parsed.rules || [];
      return compileCustomRules(list);
    }
  } catch (err) {
    console.warn(`[RULES] Aviso: Falha ao ler ${rulesJsonPath}: ${err.message}`);
  }
  try {
    if (fs.existsSync(configJsonPath)) {
      const raw = fs.readFileSync(configJsonPath, "utf-8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.customRules)) {
        return compileCustomRules(parsed.customRules);
      }
    }
  } catch {
  }
  return [];
}
function mergeSecretPatterns(basePatterns, customPatterns) {
  const customIds = new Set(customPatterns.map((p) => p.id));
  const filteredBase = basePatterns.filter((p) => !customIds.has(p.id));
  return [...filteredBase, ...customPatterns];
}

// src/lib/security/local-secret-scanner.ts
var SECRET_PATTERNS = [
  // ═══════════════════════════════════════════════════════════════
  // CLOUD PROVIDERS (AWS, GCP, Azure)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "aws-access-key",
    category: "API_KEY",
    description: "AWS Access Key ID",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: "CRITICAL"
  },
  {
    id: "aws-secret-key",
    category: "API_KEY",
    description: "AWS Secret Access Key",
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/,
    severity: "CRITICAL"
  },
  {
    id: "google-api-key",
    category: "API_KEY",
    description: "Google Cloud / Firebase API Key (AIza...)",
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    severity: "HIGH"
  },
  {
    id: "gcp-service-account",
    category: "API_KEY",
    description: "GCP Service Account Private Key ID",
    regex: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/,
    severity: "CRITICAL"
  },
  {
    id: "azure-storage-key",
    category: "API_KEY",
    description: "Azure Storage Account Key (Base64 88 chars)",
    regex: /(?:AccountKey|AZURE_STORAGE_KEY|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/]{86}==)['"]?/,
    severity: "CRITICAL"
  },
  {
    id: "azure-client-secret",
    category: "API_KEY",
    description: "Azure AD Client Secret",
    regex: /(?:AZURE_CLIENT_SECRET|client_secret)\s*[=:]\s*['"]([a-zA-Z0-9~._\-]{34,})['"]/,
    severity: "CRITICAL"
  },
  // ═══════════════════════════════════════════════════════════════
  // AI / ML PROVIDERS
  // ═══════════════════════════════════════════════════════════════
  {
    id: "openai-api-key",
    category: "API_KEY",
    description: "OpenAI API Key (sk-...)",
    regex: /\b(sk-[a-zA-Z0-9_-]{32,})\b/,
    severity: "CRITICAL"
  },
  // ═══════════════════════════════════════════════════════════════
  // PAYMENTS & COMMERCE
  // ═══════════════════════════════════════════════════════════════
  {
    id: "stripe-secret-key",
    category: "API_KEY",
    description: "Stripe Secret / Restricted Key (sk_live / rk_live)",
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "shopify-api-key",
    category: "API_KEY",
    description: "Shopify Admin API Token (shpat_)",
    regex: /\b(shpat_[a-fA-F0-9]{32})\b/,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // GIT PLATFORMS (GitHub, GitLab, Bitbucket)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "github-pat",
    category: "API_KEY",
    description: "GitHub Personal Access Token (PAT)",
    regex: /\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "gitlab-pat",
    category: "API_KEY",
    description: "GitLab Personal Access Token (glpat-)",
    regex: /\b(glpat-[0-9A-Za-z\-_]{20,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "bitbucket-app-password",
    category: "API_KEY",
    description: "Bitbucket App Password (ATBB)",
    regex: /\b(ATBB[A-Za-z0-9]{32,})\b/,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // MESSAGING & CHAT (Slack, Discord, Telegram, Twitter)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "slack-bot-token",
    category: "API_KEY",
    description: "Slack Bot / User / App Token (xoxb-, xoxp-, xoxa-)",
    regex: /\b(xox[bporsca]-[0-9a-zA-Z-]{10,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "slack-webhook",
    category: "API_KEY",
    description: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}/,
    severity: "HIGH"
  },
  {
    id: "discord-bot-token",
    category: "API_KEY",
    description: "Discord Bot Token",
    regex: /\b([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "discord-webhook",
    category: "API_KEY",
    description: "Discord Webhook URL",
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/,
    severity: "HIGH"
  },
  {
    id: "telegram-bot-token",
    category: "API_KEY",
    description: "Telegram Bot Token",
    regex: /\b(\d{8,10}:[A-Za-z0-9_-]{35})\b/,
    severity: "HIGH"
  },
  {
    id: "twitter-bearer",
    category: "API_KEY",
    description: "Twitter / X API Bearer Token",
    regex: /\b(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{20,})\b/,
    severity: "HIGH"
  },
  {
    id: "facebook-access-token",
    category: "API_KEY",
    description: "Facebook / Meta Access Token",
    regex: /\b(EAA[A-Za-z0-9]{100,})\b/,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // EMAIL & COMMUNICATION (Twilio, SendGrid, Mailgun)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "twilio-api-key",
    category: "API_KEY",
    description: "Twilio Account SID",
    regex: /\b(AC[0-9a-fA-F]{32})\b/,
    severity: "CRITICAL"
  },
  {
    id: "sendgrid-api-key",
    category: "API_KEY",
    description: "SendGrid API Key (SG.)",
    regex: /\b(SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,})\b/,
    severity: "HIGH"
  },
  {
    id: "mailgun-api-key",
    category: "API_KEY",
    description: "Mailgun API Key (key-)",
    regex: /\b(key-[0-9a-zA-Z]{32})\b/,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // HOSTING & DEVOPS (Heroku, DigitalOcean, Vercel, Netlify, Docker)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "heroku-api-key",
    category: "API_KEY",
    description: "Heroku API Key (UUID)",
    regex: /(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?/,
    severity: "HIGH"
  },
  {
    id: "digitalocean-pat",
    category: "API_KEY",
    description: "DigitalOcean Personal Access Token",
    regex: /\b(dop_v1_[a-f0-9]{64})\b/,
    severity: "CRITICAL"
  },
  {
    id: "vercel-token",
    category: "API_KEY",
    description: "Vercel Deployment Token",
    regex: /(?:VERCEL_TOKEN|vercel_token)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?/,
    severity: "HIGH"
  },
  {
    id: "netlify-token",
    category: "API_KEY",
    description: "Netlify Access Token",
    regex: /(?:NETLIFY_AUTH_TOKEN|netlify_token)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{40,})['"]?/,
    severity: "HIGH"
  },
  {
    id: "docker-hub-token",
    category: "API_KEY",
    description: "Docker Hub Access Token (dckr_pat_)",
    regex: /\b(dckr_pat_[A-Za-z0-9_-]{24,})\b/,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // PACKAGE REGISTRIES (NPM, PyPI, NuGet)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "npm-auth-token",
    category: "API_KEY",
    description: "NPM Auth Token",
    regex: /\/\/registry\.npmjs\.org\/:_authToken=([^\s'"]+)/,
    severity: "CRITICAL"
  },
  {
    id: "pypi-api-token",
    category: "API_KEY",
    description: "PyPI API Token (pypi-)",
    regex: /\b(pypi-[A-Za-z0-9_]{16,})\b/,
    severity: "HIGH"
  },
  {
    id: "nuget-api-key",
    category: "API_KEY",
    description: "NuGet API Key (oy2)",
    regex: /\b(oy2[a-z0-9]{43})\b/,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // DATABASES & INFRASTRUCTURE (Supabase, PlanetScale, Cloudflare, Vault)
  // ═══════════════════════════════════════════════════════════════
  {
    id: "supabase-key",
    category: "API_KEY",
    description: "Supabase Service Role Key (JWT)",
    regex: /(?:SUPABASE_SERVICE_ROLE_KEY|supabase_key)\s*[=:]\s*['"]?(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})['"]?/,
    severity: "CRITICAL"
  },
  {
    id: "cloudflare-api-token",
    category: "API_KEY",
    description: "Cloudflare API Token",
    regex: /(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare_api_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?/,
    severity: "CRITICAL"
  },
  {
    id: "datadog-api-key",
    category: "API_KEY",
    description: "Datadog API Key",
    regex: /(?:DD_API_KEY|DATADOG_API_KEY|datadog_api_key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/,
    severity: "HIGH"
  },
  {
    id: "hashicorp-vault-token",
    category: "API_KEY",
    description: "HashiCorp Vault Token (hvs.)",
    regex: /\b(hvs\.[A-Za-z0-9_-]{24,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "linear-api-key",
    category: "API_KEY",
    description: "Linear API Key (lin_api_)",
    regex: /\b(lin_api_[A-Za-z0-9]{40})\b/,
    severity: "HIGH"
  },
  {
    id: "planetscale-password",
    category: "API_KEY",
    description: "PlanetScale Database Password (pscale_pw_)",
    regex: /\b(pscale_pw_[A-Za-z0-9_-]{32,})\b/,
    severity: "CRITICAL"
  },
  {
    id: "sentry-dsn",
    category: "API_KEY",
    description: "Sentry DSN (contains auth key)",
    regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io\/\d+/,
    severity: "MEDIUM"
  },
  // ═══════════════════════════════════════════════════════════════
  // PRIVATE KEYS & CERTIFICATES
  // ═══════════════════════════════════════════════════════════════
  {
    id: "ssh-private-key",
    category: "PRIVATE_KEY",
    description: "SSH / RSA / OpenSSL Private Key",
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    severity: "CRITICAL"
  },
  {
    id: "pkcs8-private-key",
    category: "PRIVATE_KEY",
    description: "PKCS#8 Encrypted Private Key",
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
    severity: "CRITICAL"
  },
  {
    id: "pgp-private-key",
    category: "PRIVATE_KEY",
    description: "PGP Private Key Block",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: "CRITICAL"
  },
  // ═══════════════════════════════════════════════════════════════
  // CREDENTIALS & CONNECTIONS
  // ═══════════════════════════════════════════════════════════════
  {
    id: "db-connection-string",
    category: "CREDENTIAL",
    description: "Database Connection String with Password",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+/,
    severity: "HIGH"
  },
  {
    id: "password-assignment",
    category: "CREDENTIAL",
    description: "Hardcoded Password in Variable Assignment",
    regex: /(?:password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]{4,}['"]/i,
    severity: "HIGH"
  },
  {
    id: "jwt-hardcoded",
    category: "CREDENTIAL",
    description: "Hardcoded JWT Secret in Code",
    regex: /(?:jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    severity: "HIGH"
  },
  // ═══════════════════════════════════════════════════════════════
  // DANGEROUS CODE PATTERNS
  // ═══════════════════════════════════════════════════════════════
  {
    id: "dangerous-eval",
    category: "DANGEROUS_CODE",
    description: "Dynamic Code Execution (eval)",
    regex: /\beval\s*\([^\)]+\)/,
    severity: "MEDIUM"
  }
];
var SENSITIVE_FILENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.staging",
  ".env.development",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "credentials.json",
  "serviceAccountKey.json",
  ".npmrc",
  ".pypirc",
  ".htpasswd",
  "wp-config.php",
  "application.yml",
  "secrets.yml",
  "vault.json",
  "docker-compose.override.yml"
];
var IGNORED_DIRS = /* @__PURE__ */ new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".cache",
  ".vercel",
  ".obsidiansec"
]);
var IGNORED_EXTENSIONS = /* @__PURE__ */ new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".mp4",
  ".mp3",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".map",
  ".lock"
]);
function redactSecret(match) {
  if (match.length <= 8) return "********";
  return match.slice(0, 4) + "..." + match.slice(-4);
}
function scanDirectoryForSecrets(targetDir, maxFiles = 1e3, options) {
  const startTime = Date.now();
  const findings = [];
  let filesCount = 0;
  const custom = options?.customPatterns || loadCustomSecurityRules(targetDir);
  const activePatterns = custom.length > 0 ? mergeSecretPatterns(SECRET_PATTERNS, custom) : SECRET_PATTERNS;
  function walk(currentDir, depth = 0) {
    if (depth > 6 || filesCount >= maxFiles) return;
    let entries = [];
    try {
      entries = fs2.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path2.join(currentDir, entry.name);
      const relPath = path2.relative(targetDir, fullPath);
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith(".gemini")) {
          walk(fullPath, depth + 1);
        }
      } else if (entry.isFile()) {
        const ext = path2.extname(entry.name).toLowerCase();
        if (IGNORED_EXTENSIONS.has(ext)) continue;
        filesCount++;
        if (SENSITIVE_FILENAMES.includes(entry.name)) {
          findings.push({
            ruleId: "sensitive-file-exposed",
            category: "SENSITIVE_FILE",
            description: `Sensitive credentials or environment file exposed: ${entry.name}`,
            filePath: relPath,
            lineNumber: 1,
            snippet: `Sensitive file detected on disk: ${entry.name}`,
            severity: entry.name.includes(".env") ? "HIGH" : "CRITICAL"
          });
        }
        try {
          const stat = fs2.statSync(fullPath);
          if (stat.size > 1024 * 500) continue;
          const content = fs2.readFileSync(fullPath, "utf-8");
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            for (const pattern of activePatterns) {
              const match = line.match(pattern.regex);
              if (match) {
                const rawMatch = match[1] || match[0];
                const cleanSnippet = line.replace(rawMatch, redactSecret(rawMatch)).trim();
                findings.push({
                  ruleId: pattern.id,
                  category: pattern.category,
                  description: pattern.description,
                  filePath: relPath,
                  lineNumber: i + 1,
                  snippet: cleanSnippet.slice(0, 140),
                  severity: pattern.severity
                });
              }
            }
          }
        } catch {
        }
      }
    }
  }
  walk(targetDir, 0);
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;
  return {
    directory: targetDir,
    totalFilesScanned: filesCount,
    findings,
    criticalCount,
    highCount,
    mediumCount,
    isClean: findings.length === 0,
    scanDurationMs: Date.now() - startTime
  };
}

// src/lib/security/jwt-token-analyzer.ts
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64").toString("utf-8");
}
function auditJwtToken(tokenStr) {
  const clean = tokenStr.trim();
  const parts = clean.split(".");
  if (parts.length !== 3) {
    return {
      rawToken: clean,
      isValidStructure: false,
      header: {},
      payload: {},
      signaturePresent: false,
      algorithm: "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Formato de token JWT inv\xE1lido. Deve conter 3 partes separadas por ponto (Header.Payload.Signature)." }],
      securityScore: 0,
      status: "CRITICAL"
    };
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  let header = {};
  let payload = {};
  try {
    header = JSON.parse(base64UrlDecode(headerPart));
  } catch {
    return {
      rawToken: clean,
      isValidStructure: false,
      header: {},
      payload: {},
      signaturePresent: !!signaturePart,
      algorithm: "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Falha ao decodificar o cabe\xE7alho Base64URL do JWT." }],
      securityScore: 0,
      status: "CRITICAL"
    };
  }
  try {
    payload = JSON.parse(base64UrlDecode(payloadPart));
  } catch {
    return {
      rawToken: clean,
      isValidStructure: false,
      header,
      payload: {},
      signaturePresent: !!signaturePart,
      algorithm: header.alg || "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Falha ao decodificar o payload Base64URL do JWT." }],
      securityScore: 0,
      status: "CRITICAL"
    };
  }
  const issues = [];
  const algorithm = String(header.alg || "none").toUpperCase();
  const signaturePresent = signaturePart.length > 0;
  if (algorithm === "NONE" || !signaturePresent) {
    issues.push({
      severity: "CRITICAL",
      message: "Vulnerabilidade Cr\xEDtica 'alg: none': Token sem assinatura criptogr\xE1fica, permitindo forja irrestrita de identidade."
    });
  }
  if (algorithm === "HS256") {
    issues.push({
      severity: "LOW",
      message: "Algoritmo sim\xE9trico HS256: Requer segredo com no m\xEDnimo 256 bits de entropia. Prefira algoritmos assim\xE9tricos (RS256/ES256/EdDSA)."
    });
  }
  const nowInSeconds = Math.floor(Date.now() / 1e3);
  let isExpired = false;
  let expiresInSeconds;
  const hasExpiration = typeof payload.exp === "number";
  if (!hasExpiration) {
    issues.push({
      severity: "HIGH",
      message: "Aus\xEAncia do claim 'exp' (Token Infinito): Tokens sem expira\xE7\xE3o permanecem v\xE1lidos permanentemente se vazados."
    });
  } else {
    expiresInSeconds = payload.exp - nowInSeconds;
    if (expiresInSeconds <= 0) {
      isExpired = true;
      issues.push({
        severity: "MEDIUM",
        message: `Token expirado h\xE1 ${Math.abs(expiresInSeconds)} segundos.`
      });
    }
  }
  const sensitiveKeys = ["password", "senha", "credit_card", "secret", "cvv", "cpf", "ssn"];
  for (const k of Object.keys(payload)) {
    if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
      issues.push({
        severity: "HIGH",
        message: `Vazamento de PII/Segredo no payload: O claim '${k}' est\xE1 exposto em texto claro (JWT n\xE3o \xE9 criptografado, apenas assinado).`
      });
    }
  }
  let score = 100;
  for (const iss of issues) {
    if (iss.severity === "CRITICAL") score -= 60;
    else if (iss.severity === "HIGH") score -= 25;
    else if (iss.severity === "MEDIUM") score -= 15;
    else if (iss.severity === "LOW") score -= 5;
  }
  score = Math.max(0, score);
  let status = "CRITICAL";
  if (score >= 80) status = "SECURE";
  else if (score >= 50) status = "WARNING";
  return {
    rawToken: clean,
    isValidStructure: true,
    header,
    payload,
    signaturePresent,
    algorithm,
    isExpired,
    expiresInSeconds,
    hasExpiration,
    issues,
    securityScore: score,
    status
  };
}

// src/lib/security/subdomain-recon-analyzer.ts
async function discoverSubdomains(domainInput) {
  const startTime = Date.now();
  const cleanDomain = domainInput.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim().toLowerCase();
  if (!cleanDomain) {
    return {
      domain: "",
      totalFound: 0,
      subdomains: [],
      durationMs: 0,
      source: "crt.sh",
      status: "ERROR",
      error: "Dom\xEDnio inv\xE1lido fornecido."
    };
  }
  const url = `https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6e3);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "ObsidianSec-PassiveRecon/1.1 (+https://obsidiansec.dev)",
        Accept: "application/json"
      }
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return {
        domain: cleanDomain,
        totalFound: 0,
        subdomains: [],
        durationMs: Date.now() - startTime,
        source: "crt.sh",
        status: "ERROR",
        error: `Servi\xE7o de Certificate Transparency retornou HTTP ${res.status}.`
      };
    }
    const data = await res.json();
    if (!Array.isArray(data)) {
      return {
        domain: cleanDomain,
        totalFound: 0,
        subdomains: [],
        durationMs: Date.now() - startTime,
        source: "crt.sh",
        status: "EMPTY"
      };
    }
    const uniqueSubs = /* @__PURE__ */ new Set();
    for (const entry of data) {
      const nameValue = String(entry.name_value || "");
      const lines = nameValue.split("\n");
      for (const line of lines) {
        const sub = line.trim().toLowerCase();
        if (sub && sub.endsWith(cleanDomain) && !sub.includes("@")) {
          const normalized = sub.startsWith("*.") ? sub.slice(2) : sub;
          if (normalized) uniqueSubs.add(normalized);
        }
      }
    }
    const sortedSubs = Array.from(uniqueSubs).sort((a, b) => a.localeCompare(b));
    return {
      domain: cleanDomain,
      totalFound: sortedSubs.length,
      subdomains: sortedSubs,
      durationMs: Date.now() - startTime,
      source: "Certificate Transparency Logs (crt.sh)",
      status: sortedSubs.length > 0 ? "SUCCESS" : "EMPTY"
    };
  } catch (err) {
    return {
      domain: cleanDomain,
      totalFound: 0,
      subdomains: [],
      durationMs: Date.now() - startTime,
      source: "crt.sh",
      status: "ERROR",
      error: err.message?.includes("abort") ? "Tempo limite esgotado ao consultar logs p\xFAblicos de certificados." : `Erro na consulta de subdom\xEDnios: ${err.message || "Falha de rede"}`
    };
  }
}

// src/lib/security/waf-detector-analyzer.ts
var WAF_SIGNATURES = [
  {
    id: "cloudflare",
    name: "Cloudflare Web Application Firewall",
    vendor: "Cloudflare, Inc.",
    headerMatches: [
      { name: "server", valuePattern: /cloudflare/i },
      { name: "cf-ray" },
      { name: "cf-cache-status" }
    ],
    cookieMatches: [/_cfuvid/i, /cf_clearance/i, /__cfduid/i],
    bodyMatches: [/Attention Required! \| Cloudflare/i, /CLOUDFLARE_ERROR_500S_BOX/i, /Cloudflare Ray ID/i]
  },
  {
    id: "aws-waf",
    name: "AWS WAF / Amazon CloudFront Shield",
    vendor: "Amazon Web Services (AWS)",
    headerMatches: [
      { name: "x-amzn-requestid" },
      { name: "x-amz-cf-id" },
      { name: "x-amzn-errortype", valuePattern: /waf/i }
    ],
    cookieMatches: [/aws-waf-token/i, /AWSALB/i, /AWSALBCORS/i],
    bodyMatches: [/Request blocked by AWS WAF/i, /<title>AWS WAF/i, /The request could not be satisfied/i]
  },
  {
    id: "modsecurity",
    name: "ModSecurity (Trustwave / OWASP Core Rule Set)",
    vendor: "OWASP / Trustwave",
    headerMatches: [
      { name: "server", valuePattern: /mod_security|modsecurity/i },
      { name: "x-mod-security" }
    ],
    bodyMatches: [/This error was generated by Mod_Security/i, /OWASP_CRS/i, /blocked by ModSecurity/i],
    statusCodes: [403, 406, 501]
  },
  {
    id: "imperva",
    name: "Imperva Incapsula WAF",
    vendor: "Imperva, Inc.",
    headerMatches: [
      { name: "x-cdn", valuePattern: /incapsula|imperva/i },
      { name: "x-iinfo" }
    ],
    cookieMatches: [/incap_ses_/i, /visid_incap_/i, /nlbi_/i, /___utmvc/i],
    bodyMatches: [/Request unsuccessful\. Incapsula incident ID/i, /_Incapsula_Resource/i]
  },
  {
    id: "akamai",
    name: "Akamai Kona Site Defender / App Protector",
    vendor: "Akamai Technologies",
    headerMatches: [
      { name: "server", valuePattern: /AkamaiGHost|Ghost/i },
      { name: "x-akamai-transformed" },
      { name: "x-akamai-request-id" }
    ],
    cookieMatches: [/ak_bmsc/i, /bm_sz/i, /bm_sv/i],
    bodyMatches: [/Access Denied - Akamai/i, /Reference&#32;&#35;/i, /AkamaiGHost/i]
  },
  {
    id: "azure-waf",
    name: "Microsoft Azure Front Door / Application Gateway WAF",
    vendor: "Microsoft Corporation",
    headerMatches: [
      { name: "x-azure-ref" },
      { name: "x-azure-fdid" },
      { name: "server", valuePattern: /Microsoft-Azure-Application-Gateway/i }
    ],
    cookieMatches: [/ApplicationGatewayAffinity/i],
    bodyMatches: [/Azure Front Door/i, /The request is blocked\. Azure Front Door/i]
  },
  {
    id: "sucuri",
    name: "Sucuri CloudProxy WAF",
    vendor: "Sucuri (GoDaddy)",
    headerMatches: [
      { name: "server", valuePattern: /sucuri/i },
      { name: "x-sucuri-id" },
      { name: "x-sucuri-cache" }
    ],
    cookieMatches: [/sucuri_cloudproxy/i],
    bodyMatches: [/Access Denied - Sucuri Website Firewall/i, /Questions\? cloudproxy@sucuri\.net/i]
  },
  {
    id: "f5-bigip",
    name: "F5 BIG-IP Application Security Manager (ASM)",
    vendor: "F5 Networks",
    headerMatches: [
      { name: "server", valuePattern: /BigIP|BIG-IP/i },
      { name: "x-cnection" }
    ],
    cookieMatches: [/BIGipServer/i, /TS[a-zA-Z0-9]{6,}/i],
    bodyMatches: [/The requested URL was rejected\. Please consult with your administrator/i]
  },
  {
    id: "fastly",
    name: "Fastly CDN & Edge Cloud WAF",
    vendor: "Fastly, Inc.",
    headerMatches: [
      { name: "x-fastly-request-id" },
      { name: "server", valuePattern: /Fastly/i },
      { name: "x-served-by", valuePattern: /cache-/i }
    ],
    bodyMatches: [/Fastly error: unknown domain/i]
  },
  {
    id: "barracuda",
    name: "Barracuda Web Application Firewall",
    vendor: "Barracuda Networks",
    headerMatches: [
      { name: "server", valuePattern: /Barracuda/i }
    ],
    cookieMatches: [/barra_counter_session/i],
    bodyMatches: [/Barracuda Web Application Firewall/i]
  },
  {
    id: "fortinet-fortiweb",
    name: "Fortinet FortiWeb WAF",
    vendor: "Fortinet",
    headerMatches: [
      { name: "server", valuePattern: /FortiWeb/i }
    ],
    cookieMatches: [/FORTIWAFSID/i, /cookiesession1/i],
    bodyMatches: [/FortiWeb Web Application Firewall/i, /fgd_icon/i]
  },
  {
    id: "citrix-netscaler",
    name: "Citrix NetScaler AppFirewall",
    vendor: "Citrix / Cloud Software Group",
    headerMatches: [
      { name: "via", valuePattern: /NS-CACHE/i },
      { name: "x-nsprotect" },
      { name: "server", valuePattern: /NetScaler/i }
    ],
    cookieMatches: [/ns_af/i, /citrix_ns_id/i, /NSC_/i],
    bodyMatches: [/NS Transaction/i]
  },
  {
    id: "radware",
    name: "Radware AppWall / DefensePro",
    vendor: "Radware",
    headerMatches: [
      { name: "x-sl-compstate" },
      { name: "server", valuePattern: /Radware/i }
    ],
    bodyMatches: [/Radware Unauthorized Activity/i, /Your transaction ID/i]
  },
  {
    id: "denyall",
    name: "DenyAll Web Application Firewall",
    vendor: "Rohde & Schwarz",
    headerMatches: [
      { name: "server", valuePattern: /DenyAll/i }
    ],
    cookieMatches: [/sessioncookie/i],
    bodyMatches: [/Condition Intercepted/i]
  },
  {
    id: "stackpath",
    name: "StackPath Edge WAF",
    vendor: "StackPath",
    headerMatches: [
      { name: "x-sp-waf" },
      { name: "server", valuePattern: /StackPath/i },
      { name: "x-sp-url" }
    ],
    bodyMatches: [/StackPath Firewall/i, /You performed an action that triggered this service/i]
  },
  {
    id: "wallarm",
    name: "Wallarm Cloud WAF / WAAP",
    vendor: "Wallarm Inc.",
    headerMatches: [
      { name: "server", valuePattern: /wallarm/i },
      { name: "x-wallarm-waf-check" }
    ],
    bodyMatches: [/Wallarm blocked/i]
  },
  {
    id: "wordfence",
    name: "Wordfence WordPress Firewall",
    vendor: "Defiant Inc.",
    bodyMatches: [/Generated by Wordfence/i, /Your access to this site has been limited by the site owner/i, /wfwaf-/i]
  },
  {
    id: "sonicwall",
    name: "SonicWall Web Application Firewall",
    vendor: "SonicWall",
    headerMatches: [
      { name: "server", valuePattern: /SonicWALL/i }
    ],
    bodyMatches: [/This request is blocked by the SonicWall/i, /Web Site Blocked/i, /nsa_banner/i]
  },
  {
    id: "paloalto-prisma",
    name: "Palo Alto Prisma Cloud WAAS",
    vendor: "Palo Alto Networks",
    headerMatches: [
      { name: "server", valuePattern: /PanW/i },
      { name: "x-pan-vss" }
    ],
    bodyMatches: [/Access has been blocked by Prisma/i]
  },
  {
    id: "vercel-edge",
    name: "Vercel Edge Firewall",
    vendor: "Vercel",
    headerMatches: [
      { name: "server", valuePattern: /Vercel/i },
      { name: "x-vercel-id" },
      { name: "x-vercel-cache" }
    ]
  },
  {
    id: "reblaze",
    name: "Reblaze Cloud WAF",
    vendor: "Reblaze Technologies",
    headerMatches: [
      { name: "server", valuePattern: /Reblaze/i },
      { name: "rbzid" }
    ],
    cookieMatches: [/rbzid/i, /rbzsessionid/i],
    bodyMatches: [/Access Denied \(Reblaze\)/i]
  },
  {
    id: "alibaba-waf",
    name: "Alibaba Cloud WAF (Tengine)",
    vendor: "Alibaba Cloud",
    headerMatches: [
      { name: "server", valuePattern: /Tengine/i },
      { name: "eagleid" }
    ],
    cookieMatches: [/aliyungf_tc/i],
    bodyMatches: [/errors\.aliyun\.com/i, /Aliyun Web Application Firewall/i]
  }
];
async function detectWaf(targetUrl) {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = `https://${url}`;
  }
  const indicators = [];
  let detectedWaf = null;
  let phase = "NONE";
  let confidence = "NONE";
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4e3);
    const baselineRes = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ChimeraGuard/1.2",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });
    clearTimeout(timeout);
    const headers = baselineRes.headers;
    const rawSetCookies = [];
    if (typeof headers.getSetCookie === "function") {
      rawSetCookies.push(...headers.getSetCookie());
    } else {
      const sc = headers.get("set-cookie");
      if (sc) rawSetCookies.push(sc);
    }
    const cookieStr = rawSetCookies.join("; ");
    for (const waf of WAF_SIGNATURES) {
      if (waf.headerMatches) {
        for (const hm of waf.headerMatches) {
          const val = headers.get(hm.name);
          if (val !== null) {
            if (!hm.valuePattern || hm.valuePattern.test(val)) {
              indicators.push(`Cabe\xE7alho identificador: '${hm.name}: ${val.slice(0, 50)}'`);
              detectedWaf = waf;
              confidence = "HIGH";
              phase = "PASSIVE";
            }
          }
        }
      }
      if (waf.cookieMatches) {
        for (const cm of waf.cookieMatches) {
          if (cm.test(cookieStr)) {
            indicators.push(`Cookie exclusivo de WAF: padr\xE3o '${cm.source}'`);
            detectedWaf = waf;
            confidence = "HIGH";
            phase = "PASSIVE";
          }
        }
      }
    }
  } catch (err) {
    indicators.push(`Aviso na inspe\xE7\xE3o passiva: ${err.message}`);
  }
  if (!detectedWaf) {
    try {
      const parsed = new URL(url);
      parsed.searchParams.set("chimera_waf_probe", "<script>alert('chimeraguard_probe')</script>");
      const probeController = new AbortController();
      const probeTimeout = setTimeout(() => probeController.abort(), 4e3);
      const probeRes = await fetch(parsed.toString(), {
        method: "GET",
        signal: probeController.signal,
        headers: {
          "User-Agent": "ChimeraGuard-WAF-Probe/1.2 (+https://chimera-guard.vercel.app)"
        }
      });
      clearTimeout(probeTimeout);
      const status = probeRes.status;
      const body = await probeRes.text();
      const headers = probeRes.headers;
      if (status === 403 || status === 406 || status === 429 || status === 501) {
        for (const waf of WAF_SIGNATURES) {
          if (waf.bodyMatches) {
            for (const bm of waf.bodyMatches) {
              if (bm.test(body)) {
                indicators.push(`Padr\xE3o de bloqueio de WAF detectado no corpo da resposta: '${bm.source}'`);
                detectedWaf = waf;
                confidence = "HIGH";
                phase = "ACTIVE_PROBE";
                break;
              }
            }
          }
        }
        if (!detectedWaf) {
          detectedWaf = {
            id: "generic-waf",
            name: "Firewall / WAF Gen\xE9rico (Bloqueio Detectado)",
            vendor: "Desconhecido / Provedor Customizado"
          };
          indicators.push(`A requisi\xE7\xE3o de teste retornou HTTP ${status} (Bloqueio de ataque sint\xE9tico).`);
          confidence = "MEDIUM";
          phase = "ACTIVE_PROBE";
        }
      }
    } catch {
    }
  }
  const isDetected = detectedWaf !== null;
  const wafName = isDetected ? detectedWaf.name : "Nenhum WAF Detectado (Exposi\xE7\xE3o Direta ao Servidor)";
  const vendor = isDetected ? detectedWaf.vendor : "Servidor Web Convencional";
  let recommendation = "WAF ativo e monitorando requisi\xE7\xF5es de borda.";
  if (!isDetected) {
    recommendation = "Recomendado colocar a aplica\xE7\xE3o atr\xE1s de um WAF (ex: Cloudflare WAF, AWS WAF ou ModSecurity) para mitigar ataques automatizados de inje\xE7\xE3o SQL, XSS e botnets.";
  }
  return {
    targetUrl: url,
    detected: isDetected,
    wafName,
    vendor,
    confidence,
    detectionPhase: phase,
    indicators,
    recommendation,
    durationMs: Date.now() - startTime
  };
}

// src/lib/security/tcp-port-scanner.ts
import net from "node:net";
var CRITICAL_PORTS = [
  // ═══════════════════════════════════════════════════════════════
  // REMOTE ACCESS
  // ═══════════════════════════════════════════════════════════════
  { port: 21, service: "FTP (File Transfer Protocol)", category: "REMOTE_ACCESS", riskLevel: "HIGH", exposureRisk: "Credenciais e arquivos transmitidos em texto claro sem criptografia.", mitigation: "Desativar FTP e utilizar SFTP (porta 22) ou FTPS com TLS." },
  { port: 22, service: "SSH (Secure Shell)", category: "REMOTE_ACCESS", riskLevel: "MEDIUM", exposureRisk: "Alvo cont\xEDnuo de botnets de for\xE7a bruta e varreduras automatizadas.", mitigation: "Desabilitar autentica\xE7\xE3o por senha e restringir a IPs confi\xE1veis ou VPN." },
  { port: 135, service: "MS-RPC / DCOM (Windows)", category: "REMOTE_ACCESS", riskLevel: "HIGH", exposureRisk: "Vetor de ataques WMI e DCOM para movimenta\xE7\xE3o lateral em redes Windows.", mitigation: "Bloquear na borda de rede e restringir a dom\xEDnios AD internos." },
  { port: 139, service: "NetBIOS Session Service", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Enumera\xE7\xE3o de compartilhamentos, usu\xE1rios e vulnerabilidades EternalBlue (MS17-010).", mitigation: "Desativar NetBIOS over TCP/IP e bloquear portas 137-139 na borda." },
  { port: 389, service: "LDAP (Lightweight Directory Access)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Enumera\xE7\xE3o de usu\xE1rios do Active Directory e ataques de credential stuffing.", mitigation: "Utilizar LDAPS (636) com TLS e restringir a rede interna." },
  { port: 445, service: "SMB/CIFS (Server Message Block)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Vetor de ransomware WannaCry/NotPetya e movimenta\xE7\xE3o lateral.", mitigation: "Bloquear SMB na borda da internet e aplicar patches de seguran\xE7a." },
  { port: 636, service: "LDAPS (LDAP over TLS)", category: "REMOTE_ACCESS", riskLevel: "MEDIUM", exposureRisk: "Diret\xF3rio corporativo exposto, mesmo com TLS, permite enumera\xE7\xE3o.", mitigation: "Restringir a VPN ou rede corporativa interna." },
  { port: 2049, service: "NFS (Network File System)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Montagem remota de volumes sem autentica\xE7\xE3o pode expor todo o filesystem.", mitigation: "Restringir exports do NFS a IPs espec\xEDficos com Kerberos." },
  { port: 3389, service: "RDP (Windows Remote Desktop)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Vetor #1 de acesso inicial para grupos de ransomware corporativo.", mitigation: "Bloquear na borda da nuvem e utilizar VPN com MFA ou Azure Bastion." },
  { port: 5900, service: "VNC Remote Desktop", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Controle remoto total da m\xE1quina, frequentemente sem criptografia.", mitigation: "Desativar VNC ou tunear via SSH/VPN com senha forte." },
  // ═══════════════════════════════════════════════════════════════
  // LEGACY INSECURE
  // ═══════════════════════════════════════════════════════════════
  { port: 23, service: "Telnet (Terminal Remoto Legado)", category: "LEGACY_INSECURE", riskLevel: "CRITICAL", exposureRisk: "Protocolo inseguro sem criptografia. Vetor de botnets IoT (Mirai).", mitigation: "Desativar imediatamente o servi\xE7o Telnet e migrar para SSH." },
  { port: 25, service: "SMTP (Simple Mail Transfer Protocol)", category: "LEGACY_INSECURE", riskLevel: "HIGH", exposureRisk: "Open relay pode ser explorado para envio de spam e phishing em massa.", mitigation: "Restringir a redes internas ou utilizar servi\xE7o de email gerenciado (SES, SendGrid)." },
  { port: 110, service: "POP3 (Post Office Protocol)", category: "LEGACY_INSECURE", riskLevel: "HIGH", exposureRisk: "Protocolo legado que transmite credenciais em texto claro.", mitigation: "Migrar para POP3S (porta 995) ou IMAPS (porta 993)." },
  { port: 111, service: "RPCBind / SunRPC", category: "LEGACY_INSECURE", riskLevel: "CRITICAL", exposureRisk: "Enumera\xE7\xE3o de servi\xE7os NFS/NIS e execu\xE7\xE3o remota via RPC exploits.", mitigation: "Desativar RPCBind na borda e bloquear no firewall." },
  { port: 143, service: "IMAP (Internet Message Access)", category: "LEGACY_INSECURE", riskLevel: "HIGH", exposureRisk: "Credenciais de email transmitidas sem criptografia.", mitigation: "Migrar para IMAPS (porta 993) com TLS obrigat\xF3rio." },
  // ═══════════════════════════════════════════════════════════════
  // WEB
  // ═══════════════════════════════════════════════════════════════
  { port: 53, service: "DNS (Domain Name System)", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Servidor DNS exposto pode sofrer ataques de amplifica\xE7\xE3o DDoS e cache poisoning.", mitigation: "Restringir consultas recursivas e habilitar DNSSEC." },
  { port: 80, service: "HTTP (Web Server)", category: "WEB", riskLevel: "INFO", exposureRisk: "Porta web padr\xE3o (deve redirecionar para HTTPS).", mitigation: "Configurar redirecionamento 301 permanente para HTTPS com HSTS." },
  { port: 443, service: "HTTPS (Web Seguro)", category: "WEB", riskLevel: "INFO", exposureRisk: "Porta web segura padr\xE3o.", mitigation: "Manter certificados TLS atualizados e habilitar HTTP/2 e TLS 1.3." },
  { port: 993, service: "IMAPS (IMAP Secure)", category: "WEB", riskLevel: "INFO", exposureRisk: "Servi\xE7o de email seguro (porta padr\xE3o).", mitigation: "Manter certificados TLS atualizados." },
  { port: 995, service: "POP3S (POP3 Secure)", category: "WEB", riskLevel: "INFO", exposureRisk: "Servi\xE7o de email seguro (porta padr\xE3o).", mitigation: "Manter certificados TLS atualizados." },
  { port: 4443, service: "HTTPS Alternativo", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Porta alternativa usada por pain\xE9is de administra\xE7\xE3o web.", mitigation: "Proteger com autentica\xE7\xE3o forte e certificado TLS v\xE1lido." },
  { port: 5e3, service: "Docker Registry / Flask Dev", category: "WEB", riskLevel: "HIGH", exposureRisk: "Docker Registry sem auth permite push/pull de imagens maliciosas.", mitigation: "Habilitar autentica\xE7\xE3o TLS m\xFAtua e restringir acesso." },
  { port: 5601, service: "Kibana Dashboard", category: "WEB", riskLevel: "HIGH", exposureRisk: "Dashboard Kibana exposto revela dados indexados no Elasticsearch.", mitigation: "Proteger com X-Pack Security ou proxy reverso com autentica\xE7\xE3o." },
  { port: 6443, service: "Kubernetes API Server", category: "WEB", riskLevel: "CRITICAL", exposureRisk: "Acesso ao Kubernetes API permite controle total do cluster e containers.", mitigation: "Restringir com RBAC, network policies e API server privado." },
  { port: 8080, service: "HTTP-Alt / Proxy / Dev Server", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Porta frequentemente usada para pain\xE9is de administra\xE7\xE3o (Tomcat, Jenkins) ou dev.", mitigation: "Proteger com autentica\xE7\xE3o forte e n\xE3o expor ambientes de desenvolvimento." },
  { port: 8443, service: "HTTPS-Alt / Admin Panel", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Porta alternativa HTTPS usada por pain\xE9is de gerenciamento.", mitigation: "Proteger com autentica\xE7\xE3o MFA e certificado TLS v\xE1lido." },
  { port: 9090, service: "Prometheus / Cockpit Admin", category: "WEB", riskLevel: "HIGH", exposureRisk: "Prometheus exposto revela m\xE9tricas internas e topologia de infraestrutura.", mitigation: "Restringir a rede interna e habilitar autentica\xE7\xE3o." },
  { port: 15672, service: "RabbitMQ Management Console", category: "WEB", riskLevel: "HIGH", exposureRisk: "Console de gerenciamento de filas exposto com credenciais padr\xE3o (guest/guest).", mitigation: "Alterar credenciais padr\xE3o e restringir a rede interna." },
  // ═══════════════════════════════════════════════════════════════
  // DATABASES
  // ═══════════════════════════════════════════════════════════════
  { port: 1433, service: "Microsoft SQL Server", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Banco de dados corporativo exposto a ataques de for\xE7a bruta e SQLi remoto.", mitigation: "Isolar em subnet privada e habilitar Always Encrypted." },
  { port: 1521, service: "Oracle Database TNS Listener", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Banco de dados Oracle exposto permite TNS poisoning e enumera\xE7\xE3o de SIDs.", mitigation: "Habilitar Oracle Net Encryption e restringir a rede interna." },
  { port: 2181, service: "Apache ZooKeeper", category: "DATABASE", riskLevel: "HIGH", exposureRisk: "Acesso ao cluster ZooKeeper permite manipula\xE7\xE3o de configura\xE7\xF5es distribu\xEDdas.", mitigation: "Habilitar autentica\xE7\xE3o SASL e isolar em rede privada." },
  { port: 3306, service: "MySQL / MariaDB Database", category: "DATABASE", riskLevel: "HIGH", exposureRisk: "Banco de dados exposto a ataques de for\xE7a bruta contra usu\xE1rio root.", mitigation: "Vincular a 127.0.0.1 ou rede privada interna (VPC Security Group)." },
  { port: 5432, service: "PostgreSQL Database", category: "DATABASE", riskLevel: "HIGH", exposureRisk: "Banco de dados relacional exposto \xE0 internet p\xFAblica.", mitigation: "Configurar pg_hba.conf para rejeitar conex\xF5es externas e isolar em subnet privada." },
  { port: 6379, service: "Redis Cache & Database", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "RCE e exfiltra\xE7\xE3o total de dados via grava\xE7\xE3o de chaves SSH ou dump de mem\xF3ria.", mitigation: "Nunca expor na internet! Habilitar autentica\xE7\xE3o forte e isolar em rede local." },
  { port: 9200, service: "Elasticsearch REST API", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Acesso unauthenticated a logs, dados de clientes e clusters de busca.", mitigation: "Ativar X-Pack Security com TLS e restringir o acesso apenas a backends autorizados." },
  { port: 11211, service: "Memcached", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Amplifica\xE7\xE3o DDoS massiva e exfiltra\xE7\xE3o de dados de cache em mem\xF3ria.", mitigation: "Nunca expor na internet! Vincular a 127.0.0.1 e usar SASL auth." },
  { port: 27017, service: "MongoDB NoSQL Database", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Alvo priorit\xE1rio de ataques automatizados de ransomware de banco de dados.", mitigation: "Ativar autentica\xE7\xE3o SCRAM-SHA-256 e fechar portas no Security Group da nuvem." }
];
function checkTcpPort(host, portDef, timeoutMs = 1500) {
  const start = Date.now();
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isResolved = false;
    const finalize = (status) => {
      if (isResolved) return;
      isResolved = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve({
        port: portDef.port,
        service: portDef.service,
        category: portDef.category,
        riskLevel: portDef.riskLevel,
        status,
        responseTimeMs: Date.now() - start,
        exposureRisk: portDef.exposureRisk,
        mitigation: portDef.mitigation
      });
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finalize("OPEN"));
    socket.once("timeout", () => finalize("FILTERED"));
    socket.once("error", (err) => {
      if (err.code === "ECONNREFUSED") finalize("CLOSED");
      else finalize("FILTERED");
    });
    try {
      socket.connect(portDef.port, host);
    } catch {
      finalize("FILTERED");
    }
  });
}
async function scanHostCriticalPorts(hostInput, timeoutMs = 1500) {
  const startTime = Date.now();
  const cleanHost = hostInput.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim();
  const checks = CRITICAL_PORTS.map((p) => checkTcpPort(cleanHost, p, timeoutMs));
  const results = await Promise.all(checks);
  const openCount = results.filter((r) => r.status === "OPEN").length;
  const filteredCount = results.filter((r) => r.status === "FILTERED").length;
  const closedCount = results.filter((r) => r.status === "CLOSED").length;
  const criticalExposures = results.filter(
    (r) => r.status === "OPEN" && (r.riskLevel === "CRITICAL" || r.riskLevel === "HIGH")
  );
  let overallVerdict = "SECURE";
  if (criticalExposures.some((r) => r.riskLevel === "CRITICAL")) {
    overallVerdict = "CRITICAL";
  } else if (criticalExposures.length > 0) {
    overallVerdict = "WARNING";
  }
  return {
    targetHost: cleanHost,
    totalScanned: results.length,
    openCount,
    filteredCount,
    closedCount,
    criticalExposuresCount: criticalExposures.length,
    results,
    overallVerdict,
    durationMs: Date.now() - startTime
  };
}

// src/lib/config/obsidian-config.ts
import fs3 from "node:fs";
import path3 from "node:path";
var DEFAULT_OBSIDIAN_CONFIG = {
  version: "1.5.0",
  scope: {
    allowlist: [],
    blocklist: ["*.gov.br", "*.mil.br", "*.jus.br"],
    strictMode: false
  },
  ai: {
    enabled: false,
    provider: "offline",
    maxRequestsPerHour: 10,
    cacheTtlHours: 72
  }
};
function loadObsidianConfig(customPath) {
  const defaultFile = fs3.existsSync(path3.resolve(process.cwd(), "chimeraguard.config.json")) ? path3.resolve(process.cwd(), "chimeraguard.config.json") : path3.resolve(process.cwd(), "obsidiansec.config.json");
  const configPath = customPath || defaultFile;
  try {
    if (fs3.existsSync(configPath)) {
      const raw = fs3.readFileSync(configPath, "utf-8");
      const parsed = JSON.parse(raw);
      return {
        version: parsed.version || DEFAULT_OBSIDIAN_CONFIG.version,
        scope: {
          ...DEFAULT_OBSIDIAN_CONFIG.scope,
          ...parsed.scope || {}
        },
        ai: {
          ...DEFAULT_OBSIDIAN_CONFIG.ai,
          ...parsed.ai || {}
        }
      };
    }
  } catch (err) {
    console.warn(`[CONFIG] Aviso: N\xE3o foi poss\xEDvel ler ${configPath}. Usando configura\xE7\xE3o padr\xE3o segura.`);
  }
  return { ...DEFAULT_OBSIDIAN_CONFIG };
}
function generateDefaultConfigFile(targetDir = process.cwd()) {
  const targetPath = path3.resolve(targetDir, "chimeraguard.config.json");
  const template = {
    "$schema": "https://obsidiansec.dev/schema.json",
    "version": "1.2.2",
    "scope": {
      "strictMode": false,
      "allowlist": [
        "localhost",
        "127.0.0.1",
        "staging.yourdomain.com",
        "*.yourdomain.com"
      ],
      "blocklist": [
        "*.gov.br",
        "*.mil.br",
        "*.jus.br"
      ]
    },
    "ai": {
      "enabled": false,
      "provider": "offline",
      "maxRequestsPerHour": 10,
      "cacheTtlHours": 72
    }
  };
  fs3.writeFileSync(targetPath, JSON.stringify(template, null, 2), "utf-8");
  return targetPath;
}

// src/lib/security/scope-guard.ts
function normalizeTargetToHost(target) {
  if (!target || typeof target !== "string") return "";
  let clean = target.trim().toLowerCase();
  if (clean.startsWith("http://")) clean = clean.slice(7);
  if (clean.startsWith("https://")) clean = clean.slice(8);
  clean = clean.split("/")[0].split("?")[0].split("#")[0];
  clean = clean.split(":")[0];
  return clean;
}
function matchesHostPattern(host, pattern) {
  if (!host || !pattern) return false;
  const h = host.toLowerCase().trim();
  const p = pattern.toLowerCase().trim();
  if (h === p) return true;
  if (p.startsWith("*.")) {
    const baseDomain = p.slice(2);
    return h === baseDomain || h.endsWith("." + baseDomain);
  }
  if (p.includes("*")) {
    const regex = new RegExp("^" + p.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
    return regex.test(h);
  }
  return false;
}
function validateTargetScope(target, config = DEFAULT_OBSIDIAN_CONFIG) {
  const host = normalizeTargetToHost(target);
  if (!host) {
    return {
      allowed: false,
      target,
      normalizedHost: "",
      errorCode: "INVALID_TARGET",
      reason: "Alvo inv\xE1lido ou n\xE3o foi poss\xEDvel extrair o hostname."
    };
  }
  const blocklist = config.scope.blocklist || [];
  for (const blockPattern of blocklist) {
    if (matchesHostPattern(host, blockPattern)) {
      return {
        allowed: false,
        target,
        normalizedHost: host,
        matchedRule: blockPattern,
        errorCode: "SCOPE_BLOCKED",
        reason: `Alvo '${host}' bloqueado pela regra de exclus\xE3o: '${blockPattern}'.`
      };
    }
  }
  const allowlist = config.scope.allowlist || [];
  const strictMode = config.scope.strictMode;
  if (strictMode || allowlist.length > 0) {
    let matchedAllowRule;
    for (const allowPattern of allowlist) {
      if (matchesHostPattern(host, allowPattern)) {
        matchedAllowRule = allowPattern;
        break;
      }
    }
    if (!matchedAllowRule) {
      return {
        allowed: false,
        target,
        normalizedHost: host,
        errorCode: "SCOPE_NOT_IN_ALLOWLIST",
        reason: `Alvo '${host}' n\xE3o consta na lista de escopos autorizados (allowlist) em obsidiansec.config.json.`
      };
    }
    return {
      allowed: true,
      target,
      normalizedHost: host,
      matchedRule: matchedAllowRule,
      reason: `Alvo autorizado pela regra de escopo: '${matchedAllowRule}'.`
    };
  }
  return {
    allowed: true,
    target,
    normalizedHost: host,
    reason: "Alvo dentro do escopo geral (permissivo por padr\xE3o)."
  };
}

// src/lib/security/ssl-tls-analyzer.ts
import tls from "node:tls";
import net2 from "node:net";
import { URL as URL2 } from "node:url";
async function analyzeSslTls(targetUrl) {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;
  const parsed = new URL2(url);
  const hostname = parsed.hostname;
  const port = parseInt(parsed.port) || 443;
  const issues = [];
  return new Promise((resolve) => {
    let resolved = false;
    const finalize = (report) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timeout);
      resolve(report);
    };
    const timeout = setTimeout(() => {
      if (socket) socket.destroy();
      finalize({
        targetUrl: url,
        valid: false,
        issuer: "N/A",
        subject: "N/A",
        subjectAltNames: [],
        validFrom: "N/A",
        validTo: "N/A",
        daysUntilExpiry: -1,
        isExpired: true,
        isExpiringSoon: true,
        serialNumber: "N/A",
        fingerprint256: "N/A",
        protocol: "N/A",
        signatureAlgorithm: "N/A",
        isSelfSigned: false,
        grade: "F",
        issues: [{ severity: "CRITICAL", message: "Connection timed out \u2014 unable to establish TLS handshake." }],
        durationMs: Date.now() - startTime
      });
    }, 5e3);
    const isIp = net2.isIP(hostname) !== 0;
    const connectOptions = {
      host: hostname,
      port,
      rejectUnauthorized: false,
      ...isIp ? {} : { servername: hostname }
    };
    let socket;
    try {
      socket = tls.connect(connectOptions, () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol() || "unknown";
        const authorized = socket.authorized;
        const validFrom = cert.valid_from || "N/A";
        const validTo = cert.valid_to || "N/A";
        const validToDate = new Date(validTo);
        const now = /* @__PURE__ */ new Date();
        const daysUntilExpiry = Math.floor((validToDate.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24));
        const isExpired = daysUntilExpiry < 0;
        const isExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;
        const issuerCN = cert.issuer?.CN || cert.issuer?.O || "Unknown";
        const subjectCN = cert.subject?.CN || "Unknown";
        const isSelfSigned = issuerCN === subjectCN && (!cert.issuer?.O || cert.issuer?.O === cert.subject?.O);
        const san = cert.subjectaltname ? cert.subjectaltname.split(", ").map((s) => s.replace("DNS:", "")) : [];
        const sigAlg = cert.sigalg || "unknown";
        const serial = cert.serialNumber || "N/A";
        const fp256 = cert.fingerprint256 || "N/A";
        if (isExpired) issues.push({ severity: "CRITICAL", message: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago.` });
        else if (isExpiringSoon) issues.push({ severity: "HIGH", message: `Certificate expires in ${daysUntilExpiry} days \u2014 renewal required.` });
        if (isSelfSigned) issues.push({ severity: "HIGH", message: "Self-signed certificate detected \u2014 not trusted by browsers." });
        if (!authorized && !isSelfSigned && !isExpired) issues.push({ severity: "MEDIUM", message: "Certificate chain validation failed." });
        if (protocol === "TLSv1" || protocol === "TLSv1.1") {
          issues.push({ severity: "CRITICAL", message: `Deprecated protocol ${protocol} in use \u2014 vulnerable to POODLE/BEAST.` });
        }
        if (sigAlg && (sigAlg.includes("sha1") || sigAlg.includes("md5"))) {
          issues.push({ severity: "HIGH", message: `Weak signature algorithm: ${sigAlg}. Migrate to SHA-256+.` });
        }
        if (san.length === 0) issues.push({ severity: "LOW", message: "No Subject Alternative Names (SAN) found." });
        let grade = "A+";
        if (isExpired) grade = "F";
        else if (isSelfSigned) grade = "F";
        else if (protocol === "TLSv1" || protocol === "TLSv1.1") grade = "C";
        else if (isExpiringSoon) grade = "C";
        else if (daysUntilExpiry < 90) grade = "A";
        else if (issues.some((i) => i.severity === "HIGH")) grade = "B";
        socket.destroy();
        finalize({
          targetUrl: url,
          valid: !isExpired && authorized,
          issuer: issuerCN,
          subject: subjectCN,
          subjectAltNames: san,
          validFrom,
          validTo,
          daysUntilExpiry,
          isExpired,
          isExpiringSoon,
          serialNumber: serial,
          fingerprint256: fp256,
          protocol,
          signatureAlgorithm: sigAlg,
          isSelfSigned,
          grade,
          issues,
          durationMs: Date.now() - startTime
        });
      });
      socket.on("error", (err) => {
        finalize({
          targetUrl: url,
          valid: false,
          issuer: "N/A",
          subject: "N/A",
          subjectAltNames: [],
          validFrom: "N/A",
          validTo: "N/A",
          daysUntilExpiry: -1,
          isExpired: true,
          isExpiringSoon: true,
          serialNumber: "N/A",
          fingerprint256: "N/A",
          protocol: "N/A",
          signatureAlgorithm: "N/A",
          isSelfSigned: false,
          grade: "F",
          issues: [{ severity: "CRITICAL", message: `TLS connection failed: ${err.message}` }],
          durationMs: Date.now() - startTime
        });
      });
    } catch (err) {
      finalize({
        targetUrl: url,
        valid: false,
        issuer: "N/A",
        subject: "N/A",
        subjectAltNames: [],
        validFrom: "N/A",
        validTo: "N/A",
        daysUntilExpiry: -1,
        isExpired: true,
        isExpiringSoon: true,
        serialNumber: "N/A",
        fingerprint256: "N/A",
        protocol: "N/A",
        signatureAlgorithm: "N/A",
        isSelfSigned: false,
        grade: "F",
        issues: [{ severity: "CRITICAL", message: `TLS initialization failed: ${err.message}` }],
        durationMs: Date.now() - startTime
      });
    }
  });
}

// src/lib/security/tech-fingerprint-analyzer.ts
var FINGERPRINT_RULES = [
  // Servers
  { name: "Nginx", category: "SERVER", headerCheck: { name: "server", pattern: /nginx/i }, confidence: "HIGH" },
  { name: "Apache", category: "SERVER", headerCheck: { name: "server", pattern: /Apache/i }, confidence: "HIGH" },
  { name: "Microsoft IIS", category: "SERVER", headerCheck: { name: "server", pattern: /Microsoft-IIS/i }, confidence: "HIGH" },
  { name: "Caddy", category: "SERVER", headerCheck: { name: "server", pattern: /Caddy/i }, confidence: "HIGH" },
  { name: "LiteSpeed", category: "SERVER", headerCheck: { name: "server", pattern: /LiteSpeed/i }, confidence: "HIGH" },
  { name: "Express.js", category: "SERVER", headerCheck: { name: "x-powered-by", pattern: /Express/i }, confidence: "HIGH" },
  // CDNs
  { name: "Cloudflare CDN", category: "CDN", headerCheck: { name: "cf-ray" }, confidence: "HIGH" },
  { name: "Fastly CDN", category: "CDN", headerCheck: { name: "x-fastly-request-id" }, confidence: "HIGH" },
  { name: "Akamai CDN", category: "CDN", headerCheck: { name: "x-akamai-transformed" }, confidence: "HIGH" },
  { name: "AWS CloudFront", category: "CDN", headerCheck: { name: "x-amz-cf-id" }, confidence: "HIGH" },
  { name: "Vercel Edge Network", category: "CDN", headerCheck: { name: "x-vercel-id" }, confidence: "HIGH" },
  { name: "Netlify", category: "CDN", headerCheck: { name: "x-nf-request-id" }, confidence: "HIGH" },
  // Frameworks (HTML body)
  { name: "Next.js", category: "FRAMEWORK", bodyPattern: /__NEXT_DATA__|_next\/static/i, confidence: "HIGH" },
  { name: "React", category: "JS_LIBRARY", bodyPattern: /data-reactroot|__react|react-root|reactDOM/i, confidence: "HIGH" },
  { name: "Vue.js", category: "JS_LIBRARY", bodyPattern: /__VUE__|v-app|vue-app|vue\.min\.js|vue\.js/i, confidence: "HIGH" },
  { name: "Nuxt.js", category: "FRAMEWORK", bodyPattern: /__NUXT__|_nuxt\//i, confidence: "HIGH" },
  { name: "Angular", category: "FRAMEWORK", bodyPattern: /ng-app|ng-version|angular\.min\.js|angular\.js/i, confidence: "HIGH" },
  { name: "Svelte", category: "FRAMEWORK", bodyPattern: /svelte-|__svelte/i, confidence: "MEDIUM" },
  { name: "Gatsby", category: "FRAMEWORK", bodyPattern: /gatsby-/i, confidence: "MEDIUM" },
  { name: "Remix", category: "FRAMEWORK", bodyPattern: /__remix|remix-run/i, confidence: "MEDIUM" },
  // CMS
  { name: "WordPress", category: "CMS", bodyPattern: /wp-content|wp-includes|wp-json/i, confidence: "HIGH" },
  { name: "Drupal", category: "CMS", bodyPattern: /Drupal\.settings|drupal\.js|sites\/default/i, confidence: "HIGH" },
  { name: "Joomla", category: "CMS", bodyPattern: /\/media\/system\/js\/|com_content|Joomla!/i, confidence: "HIGH" },
  { name: "Ghost CMS", category: "CMS", bodyPattern: /ghost-url|ghost\.js/i, confidence: "HIGH" },
  { name: "Shopify", category: "CMS", bodyPattern: /cdn\.shopify\.com|Shopify\.theme/i, confidence: "HIGH" },
  { name: "Squarespace", category: "CMS", bodyPattern: /squarespace\.com|sqsp/i, confidence: "HIGH" },
  { name: "Wix", category: "CMS", bodyPattern: /wix\.com|_wixCIDX/i, confidence: "HIGH" },
  // Backend Languages
  { name: "PHP", category: "LANGUAGE", headerCheck: { name: "x-powered-by", pattern: /PHP/i }, confidence: "HIGH" },
  { name: "ASP.NET", category: "LANGUAGE", headerCheck: { name: "x-powered-by", pattern: /ASP\.NET/i }, confidence: "HIGH" },
  { name: "Django", category: "FRAMEWORK", bodyPattern: /csrfmiddlewaretoken/i, confidence: "MEDIUM" },
  { name: "Ruby on Rails", category: "FRAMEWORK", headerCheck: { name: "x-request-id" }, bodyPattern: /csrf-token.*authenticity_token/i, confidence: "LOW" },
  { name: "Laravel", category: "FRAMEWORK", cookiePattern: /laravel_session|XSRF-TOKEN/i, confidence: "MEDIUM" },
  // JS Libraries
  { name: "jQuery", category: "JS_LIBRARY", bodyPattern: /jquery\.min\.js|jquery\.js|jquery-\d/i, confidence: "HIGH" },
  { name: "Lodash", category: "JS_LIBRARY", bodyPattern: /lodash\.min\.js|lodash\.js/i, confidence: "MEDIUM" },
  { name: "Moment.js", category: "JS_LIBRARY", bodyPattern: /moment\.min\.js|moment\.js/i, confidence: "MEDIUM" },
  // CSS Frameworks
  { name: "Tailwind CSS", category: "CSS_FRAMEWORK", bodyPattern: /tailwindcss|tailwind\.min\.css/i, confidence: "HIGH" },
  { name: "Bootstrap", category: "CSS_FRAMEWORK", bodyPattern: /bootstrap\.min\.css|bootstrap\.min\.js|bootstrap\.css/i, confidence: "HIGH" },
  { name: "Bulma", category: "CSS_FRAMEWORK", bodyPattern: /bulma\.min\.css|bulma\.css/i, confidence: "HIGH" },
  // Analytics
  { name: "Google Analytics", category: "ANALYTICS", bodyPattern: /google-analytics\.com|googletagmanager\.com|gtag\(/i, confidence: "HIGH" },
  { name: "Google Tag Manager", category: "ANALYTICS", bodyPattern: /googletagmanager\.com\/gtm\.js/i, confidence: "HIGH" },
  { name: "Matomo / Piwik", category: "ANALYTICS", bodyPattern: /matomo\.js|piwik\.js/i, confidence: "HIGH" },
  { name: "Plausible Analytics", category: "ANALYTICS", bodyPattern: /plausible\.io/i, confidence: "HIGH" },
  { name: "Hotjar", category: "ANALYTICS", bodyPattern: /hotjar\.com|_hjSettings/i, confidence: "HIGH" },
  { name: "Microsoft Clarity", category: "ANALYTICS", bodyPattern: /clarity\.ms/i, confidence: "HIGH" },
  // Security
  { name: "reCAPTCHA", category: "SECURITY", bodyPattern: /google\.com\/recaptcha|grecaptcha/i, confidence: "HIGH" },
  { name: "hCaptcha", category: "SECURITY", bodyPattern: /hcaptcha\.com|h-captcha/i, confidence: "HIGH" },
  { name: "Cloudflare Turnstile", category: "SECURITY", bodyPattern: /challenges\.cloudflare\.com\/turnstile/i, confidence: "HIGH" }
];
async function fingerprintTechStack(targetUrl) {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;
  const detections = [];
  const detectedNames = /* @__PURE__ */ new Set();
  let serverHeader = "Unknown";
  let poweredBy = "N/A";
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4e3);
    const res = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ObsidianSec/1.2.2" }
    });
    clearTimeout(timeout);
    const headers = res.headers;
    const body = await res.text();
    serverHeader = headers.get("server") || "Unknown";
    poweredBy = headers.get("x-powered-by") || "N/A";
    const rawSetCookies = [];
    if (typeof headers.getSetCookie === "function") {
      rawSetCookies.push(...headers.getSetCookie());
    } else {
      const sc = headers.get("set-cookie");
      if (sc) rawSetCookies.push(sc);
    }
    const cookieStr = rawSetCookies.join("; ");
    for (const rule of FINGERPRINT_RULES) {
      if (detectedNames.has(rule.name)) continue;
      let matched = false;
      let evidence = "";
      if (rule.headerCheck) {
        const val = headers.get(rule.headerCheck.name);
        if (val !== null) {
          if (!rule.headerCheck.pattern || rule.headerCheck.pattern.test(val)) {
            matched = true;
            evidence = `Header: ${rule.headerCheck.name}: ${val.slice(0, 60)}`;
          }
        }
      }
      if (!matched && rule.bodyPattern) {
        const bodyMatch = body.match(rule.bodyPattern);
        if (bodyMatch) {
          matched = true;
          evidence = `HTML pattern: ${bodyMatch[0].slice(0, 50)}`;
        }
      }
      if (!matched && rule.cookiePattern && rule.cookiePattern.test(cookieStr)) {
        matched = true;
        evidence = `Cookie pattern: ${rule.cookiePattern.source}`;
      }
      if (matched) {
        detectedNames.add(rule.name);
        detections.push({
          name: rule.name,
          category: rule.category,
          confidence: rule.confidence,
          evidence
        });
      }
    }
  } catch (err) {
    detections.push({
      name: "Connection Error",
      category: "SERVER",
      confidence: "LOW",
      evidence: `Failed to connect: ${err.message}`
    });
  }
  return {
    targetUrl: url,
    detections,
    totalDetected: detections.length,
    serverHeader,
    poweredBy,
    durationMs: Date.now() - startTime
  };
}

// src/lib/security/http-method-analyzer.ts
var METHOD_DEFINITIONS = [
  { method: "GET", risky: false, riskLevel: "INFO", description: "Standard read method (expected to be enabled)." },
  { method: "POST", risky: false, riskLevel: "INFO", description: "Standard write method (expected to be enabled)." },
  { method: "HEAD", risky: false, riskLevel: "INFO", description: "Metadata-only request (expected to be enabled)." },
  { method: "OPTIONS", risky: false, riskLevel: "INFO", description: "CORS preflight / method discovery (may reveal allowed methods)." },
  { method: "PUT", risky: true, riskLevel: "HIGH", description: "File upload without auth \u2014 may allow arbitrary file writes on server." },
  { method: "DELETE", risky: true, riskLevel: "HIGH", description: "Resource deletion without auth \u2014 may allow removing server files." },
  { method: "PATCH", risky: false, riskLevel: "LOW", description: "Partial resource update (typically behind auth, low risk)." },
  { method: "TRACE", risky: true, riskLevel: "CRITICAL", description: "Cross-Site Tracing (XST) attack vector \u2014 reflects cookies and auth headers." }
];
async function testMethod(url, method, timeout) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, {
      method,
      signal: controller.signal,
      redirect: "manual",
      headers: { "User-Agent": "ChimeraGuard-Method-Probe/1.2.2" }
    });
    clearTimeout(timer);
    return { statusCode: res.status, error: false };
  } catch {
    return { statusCode: 0, error: true };
  }
}
async function analyzeHttpMethods(targetUrl) {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;
  const results = [];
  const allowedMethods = [];
  const riskyMethods = [];
  const tests = METHOD_DEFINITIONS.map(async (def) => {
    const { statusCode, error } = await testMethod(url, def.method, 3e3);
    const isMethodNotAllowed = statusCode === 405 || statusCode === 501 || error;
    const allowed = !isMethodNotAllowed;
    if (allowed) allowedMethods.push(def.method);
    if (allowed && def.risky) riskyMethods.push(def.method);
    results.push({
      method: def.method,
      statusCode,
      allowed,
      risky: def.risky && allowed,
      riskLevel: def.risky && allowed ? def.riskLevel : "INFO",
      description: def.description
    });
  });
  await Promise.all(tests);
  const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  results.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);
  let overallStatus = "SECURE";
  if (riskyMethods.includes("TRACE")) overallStatus = "CRITICAL";
  else if (riskyMethods.length > 0) overallStatus = "WARNING";
  return {
    targetUrl: url,
    allowedMethods,
    riskyMethods,
    results,
    overallStatus,
    durationMs: Date.now() - startTime
  };
}

// src/lib/security/open-redirect-analyzer.ts
var REDIRECT_PARAMS = [
  "url",
  "redirect",
  "redirect_url",
  "redirect_uri",
  "next",
  "return",
  "return_to",
  "returnTo",
  "dest",
  "destination",
  "redir",
  "continue",
  "forward",
  "go",
  "target",
  "out",
  "view",
  "login_url",
  "callback",
  "return_url",
  "checkout_url"
];
var EVIL_DOMAIN = "https://evil.chimeraguard-test.com";
async function testRedirectParam(baseUrl, param) {
  const payload = `${baseUrl}${baseUrl.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(EVIL_DOMAIN)}`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3e3);
    const res = await fetch(payload, {
      method: "GET",
      signal: controller.signal,
      redirect: "manual",
      headers: { "User-Agent": "ChimeraGuard-Redirect-Probe/1.2.2" }
    });
    clearTimeout(timeout);
    const statusCode = res.status;
    const location = res.headers.get("location") || "";
    const isRedirect = statusCode >= 300 && statusCode < 400;
    let isOpenRedirect = false;
    if (isRedirect && location) {
      try {
        const targetHost = new URL(location).hostname;
        const baseHost = new URL(baseUrl).hostname;
        isOpenRedirect = targetHost !== baseHost && location.includes("evil.chimeraguard-test.com");
      } catch {
        isOpenRedirect = location.includes("evil.chimeraguard-test.com");
      }
    }
    return {
      parameter: param,
      payload,
      statusCode,
      redirected: isRedirect,
      redirectedTo: location.slice(0, 200),
      isOpenRedirect,
      riskLevel: isOpenRedirect ? "CRITICAL" : "INFO"
    };
  } catch {
    return {
      parameter: param,
      payload,
      statusCode: 0,
      redirected: false,
      redirectedTo: "",
      isOpenRedirect: false,
      riskLevel: "INFO"
    };
  }
}
async function detectOpenRedirects(targetUrl) {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;
  const tests = REDIRECT_PARAMS.map((param) => testRedirectParam(url, param));
  const results = await Promise.all(tests);
  const vulnerableCount = results.filter((r) => r.isOpenRedirect).length;
  let overallStatus = "SECURE";
  if (vulnerableCount > 0) overallStatus = "VULNERABLE";
  else if (results.some((r) => r.redirected)) overallStatus = "WARNING";
  return {
    targetUrl: url,
    totalTested: results.length,
    vulnerableCount,
    results: results.filter((r) => r.isOpenRedirect || r.redirected),
    overallStatus,
    durationMs: Date.now() - startTime
  };
}

// src/lib/security/sarif-formatter.ts
function mapSeverityToSarifLevel(severity) {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    default:
      return "note";
  }
}
function convertSecretReportToSarif(report, version = "1.4.1") {
  const ruleMap = /* @__PURE__ */ new Map();
  const results = [];
  for (const finding of report.findings) {
    const level = mapSeverityToSarifLevel(finding.severity);
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.category,
        shortDescription: {
          text: finding.description
        },
        defaultConfiguration: {
          level
        },
        helpUri: "https://chimera-guard.vercel.app/docs/rules/" + finding.ruleId
      });
    }
    results.push({
      ruleId: finding.ruleId,
      level,
      message: {
        text: `${finding.description} detected in ${finding.filePath}:${finding.lineNumber}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.filePath.replace(/\\/g, "/")
            },
            region: {
              startLine: finding.lineNumber || 1,
              snippet: {
                text: finding.snippet
              }
            }
          }
        }
      ]
    });
  }
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ChimeraGuard",
            version,
            informationUri: "https://chimera-guard.vercel.app",
            rules: Array.from(ruleMap.values())
          }
        },
        results
      }
    ]
  };
}

// src/lib/security/html-report-generator.ts
function generateHtmlSecurityReport(report, score, grade) {
  const gradeColor = grade === "A+" || grade === "A" ? "#10b981" : grade === "B" ? "#eab308" : grade === "C" ? "#f97316" : "#ef4444";
  const dateStr = (/* @__PURE__ */ new Date()).toLocaleString("en-US", {
    dateStyle: "full",
    timeStyle: "medium"
  });
  const headers = [
    {
      name: "Content-Security-Policy (CSP)",
      present: report.securityHeaders.csp.present,
      value: report.securityHeaders.csp.value,
      desc: "XSS & code injection defense"
    },
    {
      name: "Strict-Transport-Security (HSTS)",
      present: report.securityHeaders.hsts.present,
      value: report.securityHeaders.hsts.value,
      desc: "Forces HTTPS encryption (RFC 6797)"
    },
    {
      name: "X-Frame-Options",
      present: report.securityHeaders.xFrameOptions.present,
      value: report.securityHeaders.xFrameOptions.value,
      desc: "Zero-clickjacking defense"
    },
    {
      name: "X-Content-Type-Options",
      present: report.securityHeaders.xContentTypeOptions.present,
      value: report.securityHeaders.xContentTypeOptions.value,
      desc: "MIME sniffing protection (nosniff)"
    },
    {
      name: "Permissions-Policy",
      present: report.securityHeaders.permissionsPolicy.present,
      value: report.securityHeaders.permissionsPolicy.value,
      desc: "Camera, microphone & geolocation lockdown"
    },
    {
      name: "Referrer-Policy",
      present: report.securityHeaders.referrerPolicy.present,
      value: report.securityHeaders.referrerPolicy.value,
      desc: "URL credential leakage prevention"
    }
  ];
  const headerRows = headers.map((h) => {
    const statusBadge = h.present ? `<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px;">ACTIVE</span>` : `<span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px;">MISSING</span>`;
    return `
        <tr style="border-bottom: 1px solid #27272a;">
          <td style="padding: 12px; font-weight: 600;">${h.name}</td>
          <td style="padding: 12px; color: #a1a1aa; font-size: 12px;">${h.desc}</td>
          <td style="padding: 12px;">${statusBadge}</td>
          <td style="padding: 12px; font-family: monospace; font-size: 11px; color: #d4d4d8; max-width: 300px; word-break: break-all;">
            ${h.value ? h.value.slice(0, 100) + (h.value.length > 100 ? "..." : "") : "\u2014"}
          </td>
        </tr>
      `;
  }).join("");
  const remediationCards = report.remediationSnippets.map(
    (snip) => `
      <div style="background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
        <div style="font-weight: 600; color: #38bdf8; font-size: 13px; margin-bottom: 6px;">\u{1F527} ${snip.serverType}</div>
        <pre style="background: #09090b; padding: 10px; border-radius: 6px; color: #a1a1aa; font-family: monospace; font-size: 11px; overflow-x: auto; margin: 0;"><code>${snip.snippet}</code></pre>
      </div>
    `
  ).join("");
  const attackNodes = report.attackChain.nodes.map(
    (node) => `
      <div style="background: #18181b; border-left: 3px solid ${node.type === "ENTRY_POINT" ? "#ef4444" : node.type === "IMPACT" ? "#dc2626" : "#f97316"}; padding: 10px 14px; border-radius: 0 8px 8px 0; margin-bottom: 8px;">
        <div style="font-weight: 600; font-size: 12px; color: #fafafa;">${node.label}</div>
        <div style="font-size: 11px; color: #a1a1aa;">${node.description}</div>
        ${node.mitreTechnique ? `<span style="display: inline-block; margin-top: 4px; background: #27272a; color: #38bdf8; font-size: 10px; font-family: monospace; padding: 2px 6px; border-radius: 4px;">MITRE ${node.mitreTechnique}</span>` : ""}
      </div>
    `
  ).join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ChimeraGuard Security Audit Report - ${report.targetUrl}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #09090b;
      color: #fafafa;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
    }
    .header-card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .score-badge {
      background: #09090b;
      border: 2px solid ${gradeColor};
      border-radius: 12px;
      padding: 12px 24px;
      text-align: center;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 20px;
    }
    @media (max-width: 768px) {
      .grid { grid-template-columns: 1fr; }
    }
    .card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .footer {
      text-align: center;
      color: #71717a;
      font-size: 12px;
      margin-top: 40px;
    }
  </style>
</head>
<body>
  <div class="container">
    
    <!-- Top Header Card -->
    <div class="header-card">
      <div>
        <div style="font-size: 12px; color: #a1a1aa; letter-spacing: 1px; text-transform: uppercase;">\u{1F6E1}\uFE0F ChimeraGuard DevSecOps Arsenal</div>
        <h1 style="margin: 4px 0 6px 0; font-size: 22px;">Security Audit: <span style="color: #38bdf8;">${report.targetUrl}</span></h1>
        <div style="font-size: 12px; color: #71717a;">Generated on ${dateStr} \u2022 Status HTTP ${report.httpStatus}</div>
      </div>
      <div class="score-badge">
        <div style="font-size: 11px; color: #a1a1aa; text-transform: uppercase;">Security Grade</div>
        <div style="font-size: 38px; font-weight: 800; color: ${gradeColor}; line-height: 1.1;">${grade}</div>
        <div style="font-size: 11px; color: #a1a1aa;">Score: ${score}/100</div>
      </div>
    </div>

    <!-- Infrastructure Overview -->
    <div class="grid">
      <div class="card">
        <h2 style="font-size: 15px; margin: 0 0 12px 0; color: #38bdf8;">\u{1F310} Edge & Infrastructure</h2>
        <div style="font-size: 13px; display: grid; gap: 8px;">
          <div><strong>Web Server:</strong> <span style="color: #a1a1aa;">${report.serverDetected}</span></div>
          <div><strong>Framework:</strong> <span style="color: #a1a1aa;">${report.frameworkDetected || "Not Disclosed (Hardened)"}</span></div>
          <div><strong>CDN / Edge Shield:</strong> <span style="color: #a1a1aa;">${report.cdnOrProxy || "Direct Server Exposure"}</span></div>
          <div><strong>Version Leakage:</strong> <span style="color: ${report.versionExposed ? "#ef4444" : "#10b981"};">${report.versionExposed ? "\u26A0\uFE0F Version Exposed" : "\u2705 Hidden"}</span></div>
        </div>
      </div>

      <div class="card">
        <h2 style="font-size: 15px; margin: 0 0 12px 0; color: #eab308;">\u{1F36A} Session & Cookie Audit</h2>
        <div style="font-size: 13px; display: grid; gap: 8px;">
          <div><strong>Cookies Analyzed:</strong> <span style="color: #a1a1aa;">${report.burpInspection.cookies.length}</span></div>
          <div><strong>CORS Policy:</strong> <span style="color: ${report.burpInspection.cors.severity === "HIGH" ? "#ef4444" : "#10b981"};">${report.burpInspection.cors.severity === "HIGH" ? "\u26A0\uFE0F Insecure / Permissive" : "\u2705 Protected"}</span></div>
          <div><strong>Wildcard with Credentials:</strong> <span style="color: ${report.burpInspection.cors.hasWildcardWithCredentials ? "#ef4444" : "#10b981"};">${report.burpInspection.cors.hasWildcardWithCredentials ? "CRITICAL RISK" : "None"}</span></div>
        </div>
      </div>
    </div>

    <!-- Security Headers Table -->
    <div class="card">
      <h2 style="font-size: 16px; margin: 0 0 16px 0;">\u{1F6E1}\uFE0F Tactical Security Headers Inspection</h2>
      <table>
        <thead>
          <tr style="border-bottom: 2px solid #27272a; text-align: left; color: #71717a; font-size: 11px; text-transform: uppercase;">
            <th style="padding: 8px 12px;">Header</th>
            <th style="padding: 8px 12px;">Defense Purpose</th>
            <th style="padding: 8px 12px;">Status</th>
            <th style="padding: 8px 12px;">Value Detected</th>
          </tr>
        </thead>
        <tbody>
          ${headerRows}
        </tbody>
      </table>
    </div>

    <!-- MITRE ATT&CK Chain -->
    <div class="card">
      <h2 style="font-size: 16px; margin: 0 0 8px 0; color: #f43f5e;">\u{1F578}\uFE0F BloodHound MITRE ATT&CK Exploitation Graph</h2>
      <p style="font-size: 12px; color: #a1a1aa; margin: 0 0 16px 0;">How an adversary can pivot missing defensive headers into active session hijacking and account takeover.</p>
      ${attackNodes}
    </div>

    <!-- Remediation Patches -->
    <div class="card">
      <h2 style="font-size: 16px; margin: 0 0 14px 0; color: #10b981;">\u{1F680} Automated Virtual Patches (Ready to Deploy)</h2>
      <p style="font-size: 12px; color: #a1a1aa; margin: 0 0 16px 0;">Copy and paste these hardened configuration blocks into your web server or edge proxy to immediately achieve Grade A+.</p>
      ${remediationCards}
    </div>

    <!-- Footer -->
    <div class="footer">
      Generated automatically by <strong>ChimeraGuard v1.3.1</strong> // The Autonomous DevSecOps & Edge Security Arsenal.<br>
      <a href="https://github.com/matheus-oliv-dev/ChimeraGuard" style="color: #38bdf8; text-decoration: none;">GitHub Repository</a> \u2022 <a href="https://www.npmjs.com/package/chimeraguard" style="color: #38bdf8; text-decoration: none;">NPM Package</a>
    </div>

  </div>
</body>
</html>`;
}

// src/lib/security/update-notifier.ts
import fs4 from "node:fs";
import path4 from "node:path";
function isNewerVersion(latest, current) {
  const parse = (v) => v.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const [lMaj, lMin, lPatch] = parse(latest);
  const [cMaj, cMin, cPatch] = parse(current);
  if (lMaj > cMaj) return true;
  if (lMaj < cMaj) return false;
  if (lMin > cMin) return true;
  if (lMin < cMin) return false;
  return lPatch > cPatch;
}
function formatUpdateNotification(currentVersion, latestVersion) {
  const ANSI2 = {
    yellow: "\x1B[33m",
    cyan: "\x1B[36m",
    green: "\x1B[32m",
    bold: "\x1B[1m",
    reset: "\x1B[0m"
  };
  return `${ANSI2.yellow}\u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502                                                          \u2502
\u2502   ${ANSI2.bold}Atualiza\xE7\xE3o dispon\xEDvel:${ANSI2.reset} ${currentVersion} \u2192 ${ANSI2.green}${latestVersion}${ANSI2.reset}${ANSI2.yellow}                \u2502
\u2502   Execute: ${ANSI2.cyan}npm install -g chimeraguard${ANSI2.reset}${ANSI2.yellow} para atualizar    \u2502
\u2502                                                          \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518${ANSI2.reset}`;
}
function checkCachedUpdateSync(currentVersion, cacheDir) {
  const dir = cacheDir || (fs4.existsSync(path4.resolve(process.cwd(), ".chimeraguard")) ? path4.resolve(process.cwd(), ".chimeraguard") : path4.resolve(process.cwd(), ".obsidiansec"));
  const cacheFile = path4.join(dir, "version-cache.json");
  try {
    if (fs4.existsSync(cacheFile)) {
      const raw = fs4.readFileSync(cacheFile, "utf-8");
      const data = JSON.parse(raw);
      if (data.latestVersion && isNewerVersion(data.latestVersion, currentVersion)) {
        return formatUpdateNotification(currentVersion, data.latestVersion);
      }
    }
  } catch {
  }
  return null;
}
function triggerBackgroundUpdateCheck(currentVersion, cacheDir) {
  const dir = cacheDir || path4.resolve(process.cwd(), ".obsidiansec");
  const cacheFile = path4.join(dir, "version-cache.json");
  try {
    if (fs4.existsSync(cacheFile)) {
      const raw = fs4.readFileSync(cacheFile, "utf-8");
      const data = JSON.parse(raw);
      const isFresh = Date.now() - data.lastChecked < 24 * 60 * 60 * 1e3;
      if (isFresh) return;
    }
  } catch {
  }
  checkCliUpdate(currentVersion, { cacheDir: dir, timeoutMs: 1200 }).catch(() => {
  });
}
async function checkCliUpdate(currentVersion, options) {
  const timeoutMs = options?.timeoutMs ?? 800;
  const cacheDir = options?.cacheDir || path4.resolve(process.cwd(), ".obsidiansec");
  const cacheFile = path4.join(cacheDir, "version-cache.json");
  try {
    if (fs4.existsSync(cacheFile)) {
      const raw = fs4.readFileSync(cacheFile, "utf-8");
      const data = JSON.parse(raw);
      const isFresh = Date.now() - data.lastChecked < 24 * 60 * 60 * 1e3;
      if (isFresh && data.latestVersion) {
        if (isNewerVersion(data.latestVersion, currentVersion)) {
          return formatUpdateNotification(currentVersion, data.latestVersion);
        }
        return null;
      }
    }
  } catch {
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res = await fetch("https://registry.npmjs.org/chimeraguard/latest", {
      signal: controller.signal,
      headers: { Accept: "application/json" }
    });
    if (!res.ok) {
      res = await fetch("https://registry.npmjs.org/obsidiansec/latest", {
        signal: controller.signal,
        headers: { Accept: "application/json" }
      });
    }
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    const latestVersion = data.version;
    try {
      if (!fs4.existsSync(cacheDir)) fs4.mkdirSync(cacheDir, { recursive: true });
      fs4.writeFileSync(
        cacheFile,
        JSON.stringify({ lastChecked: Date.now(), latestVersion }, null, 2),
        "utf-8"
      );
    } catch {
    }
    if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
      return formatUpdateNotification(currentVersion, latestVersion);
    }
  } catch {
  }
  return null;
}

// src/lib/security/origin-leak-analyzer.ts
var CLOUDFLARE_IPV4_CIDRS = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
  "1.0.0.0/24",
  "1.1.1.0/24"
];
var HIGH_RISK_ORIGIN_SUBDOMAINS = [
  "direct",
  "origin",
  "origin-api",
  "direct-connect",
  "cpanel",
  "whm",
  "webmail",
  "mail",
  "smtp",
  "ftp",
  "ssh",
  "vpn",
  "dev",
  "staging",
  "test",
  "internal",
  "portal",
  "backup",
  "admin"
];
function ipToInt(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10) >>> 0, 0);
}
function ipInCidr(ip, cidr) {
  try {
    const [range, bitsStr] = cidr.split("/");
    const bits = parseInt(bitsStr, 10);
    const mask = bits === 0 ? 0 : ~0 << 32 - bits >>> 0;
    const ipVal = ipToInt(ip);
    const rangeVal = ipToInt(range);
    return (ipVal & mask) === (rangeVal & mask);
  } catch {
    return false;
  }
}
function isCloudflareIp(ip) {
  if (!ip || !ip.includes(".")) return false;
  return CLOUDFLARE_IPV4_CIDRS.some((cidr) => ipInCidr(ip, cidr));
}
function extractSpfIps(spfRecord) {
  if (!spfRecord) return [];
  const matches = spfRecord.match(/ip4:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\/[0-9]+)?)/gi) || [];
  const ips = [];
  for (const m of matches) {
    const raw = m.replace(/^ip4:/i, "").split("/")[0].trim();
    if (!raw.startsWith("127.") && !raw.startsWith("10.") && !raw.startsWith("192.168.") && !raw.startsWith("0.") && !ips.includes(raw)) {
      ips.push(raw);
    }
  }
  return ips;
}
async function queryDohRecords2(name, type, timeoutMs = 2500) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/dns-json" }
    });
    clearTimeout(timer);
    if (!res.ok) return [];
    const data = await res.json();
    if (!data.Answer || !Array.isArray(data.Answer)) return [];
    return data.Answer.map((a) => {
      let str = String(a.data || "");
      if (str.startsWith('"') && str.endsWith('"')) {
        str = str.slice(1, -1);
      }
      return str;
    });
  } catch {
    return [];
  }
}
function generateOriginFirewallPatches(candidateIps = []) {
  const ufwScript = `# ====================================================================
# CHIMERAGUARD DEFENSE PATCH: BLOCK DIRECT ORIGIN ACCESS (UFW)
# Permite tr\xE1fego HTTPS apenas das faixas oficiais da Cloudflare
# ====================================================================
sudo ufw default deny incoming
${CLOUDFLARE_IPV4_CIDRS.map((cidr) => `sudo ufw allow from ${cidr} to any port 443 proto tcp comment "Cloudflare Edge"`).join("\n")}
sudo ufw deny 443/tcp comment "Block direct HTTP/HTTPS bypass"
sudo ufw reload`;
  const nginxSnippet = `# ====================================================================
# CHIMERAGUARD DEFENSE PATCH: NGINX RESTRICTED ORIGIN ACCESS
# Rejeita requisi\xE7\xF5es diretas que n\xE3o vierem do proxy da Cloudflare
# ====================================================================
# Adicione dentro do bloco server { ... } em /etc/nginx/sites-available/
${CLOUDFLARE_IPV4_CIDRS.map((cidr) => `set_real_ip_from ${cidr};`).join("\n")}
real_ip_header CF-Connecting-IP;

# Negar qualquer acesso direto fora da Cloudflare
allow 127.0.0.1;
${CLOUDFLARE_IPV4_CIDRS.map((cidr) => `allow ${cidr};`).join("\n")}
deny all;`;
  return { ufwScript, nginxSnippet };
}
async function analyzeOriginLeak(targetUrl, options) {
  const startTime = Date.now();
  const probeVhost = options?.probeVirtualHost !== false;
  let rawHost = targetUrl.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim().toLowerCase();
  const cleanDomain = rawHost;
  const primaryA = await queryDohRecords2(cleanDomain, "A");
  const primaryIps = primaryA.filter((ip) => /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip));
  const isCloudflare = primaryIps.length > 0 && primaryIps.every(isCloudflareIp);
  const isBehindProxyOrCdn = isCloudflare || primaryIps.some(isCloudflareIp);
  let proxyProvider = "Direct Origin";
  if (isCloudflare) proxyProvider = "Cloudflare";
  else if (isBehindProxyOrCdn) proxyProvider = "Generic CDN";
  const candidateOriginIps = [];
  const spfIpsFound = [];
  const mxHostsFound = [];
  const subdomainsExposed = [];
  const txtRecords = await queryDohRecords2(cleanDomain, "TXT");
  for (const txt of txtRecords) {
    if (txt.toLowerCase().startsWith("v=spf1")) {
      const ips = extractSpfIps(txt);
      for (const ip of ips) {
        if (!spfIpsFound.includes(ip)) spfIpsFound.push(ip);
        if (!isCloudflareIp(ip) && !primaryIps.includes(ip)) {
          candidateOriginIps.push({
            ip,
            sourceVector: "SPF_RECORD",
            isCloudflare: false
          });
        }
      }
    }
  }
  const mxRecords = await queryDohRecords2(cleanDomain, "MX");
  for (const mx of mxRecords) {
    const parts = mx.split(/\s+/);
    const host = (parts.length > 1 ? parts[1] : parts[0]).replace(/\.$/, "");
    if (host && !mxHostsFound.includes(host)) {
      mxHostsFound.push(host);
      if (host.endsWith(cleanDomain)) {
        const mxA = await queryDohRecords2(host, "A");
        for (const ip of mxA) {
          if (!isCloudflareIp(ip) && !primaryIps.includes(ip)) {
            candidateOriginIps.push({
              ip,
              sourceVector: "MX_HOST",
              discoveredHost: host,
              isCloudflare: false
            });
          }
        }
      }
    }
  }
  await Promise.all(
    HIGH_RISK_ORIGIN_SUBDOMAINS.map(async (sub) => {
      const subHost = `${sub}.${cleanDomain}`;
      const subA = await queryDohRecords2(subHost, "A");
      for (const ip of subA) {
        if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
          if (!isCloudflareIp(ip)) {
            subdomainsExposed.push(`${subHost} -> ${ip}`);
            if (!candidateOriginIps.some((c) => c.ip === ip)) {
              candidateOriginIps.push({
                ip,
                sourceVector: "GRAY_CLOUD_SUBDOMAIN",
                discoveredHost: subHost,
                isCloudflare: false
              });
            }
          }
        }
      }
    })
  );
  const confirmedBypassIps = [];
  if (probeVhost && candidateOriginIps.length > 0) {
    const uniqueIps = Array.from(new Set(candidateOriginIps.map((c) => c.ip)));
    await Promise.all(
      uniqueIps.slice(0, 5).map(async (ip) => {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 3e3);
          const res = await fetch(`http://${ip}/`, {
            signal: controller.signal,
            headers: {
              Host: cleanDomain,
              "User-Agent": "ChimeraGuard-Origin-Probe/1.4"
            }
          });
          clearTimeout(timer);
          const candidate = candidateOriginIps.find((c) => c.ip === ip);
          if (candidate) {
            candidate.statusCode = res.status;
            candidate.serverBanner = res.headers.get("server") || void 0;
            if (res.status < 500 && res.status !== 404 && res.status !== 403) {
              candidate.virtualHostMatch = true;
              if (!confirmedBypassIps.includes(ip)) {
                confirmedBypassIps.push(ip);
              }
            }
          }
        } catch {
        }
      })
    );
  }
  let riskScore = 0;
  let overallStatus = "SECURE";
  let summary = "Nenhum vazamento de IP real de origem foi detectado. Borda e proxies protegidos.";
  if (confirmedBypassIps.length > 0) {
    overallStatus = "CRITICAL_BYPASS";
    riskScore = 95;
    summary = `CR\xCDTICO: Vazamento confirmado! O servidor de origem responde diretamente em ${confirmedBypassIps.join(", ")}, ignorando 100% da prote\xE7\xE3o da CDN/WAF.`;
  } else if (candidateOriginIps.length > 0) {
    overallStatus = "WARNING";
    riskScore = 65;
    summary = `ALERTA: Foram descobertos ${candidateOriginIps.length} IPs candidatos fora da CDN via registros SPF/MX/Subdom\xEDnios. Recomenda-se bloquear acesso direto no firewall.`;
  } else if (!isBehindProxyOrCdn) {
    overallStatus = "WARNING";
    riskScore = 50;
    summary = `O dom\xEDnio n\xE3o utiliza servi\xE7o de proxy ou CDN de borda (como Cloudflare). O tr\xE1fego bate diretamente no IP p\xFAblico ${primaryIps.join(", ") || "desconhecido"}.`;
  }
  const durationMs = Date.now() - startTime;
  const firewallPatches = generateOriginFirewallPatches(confirmedBypassIps.length > 0 ? confirmedBypassIps : candidateOriginIps.map((c) => c.ip));
  return {
    targetDomain: cleanDomain,
    isBehindProxyOrCdn,
    proxyProvider,
    primaryIps,
    candidateOriginIps,
    confirmedBypassIps,
    testedVectors: {
      spfInspected: true,
      spfIpsFound,
      mxInspected: true,
      mxHostsFound,
      subdomainsProbed: HIGH_RISK_ORIGIN_SUBDOMAINS.length,
      subdomainsExposed
    },
    overallStatus,
    riskScore,
    summary,
    firewallPatches,
    durationMs
  };
}

// src/lib/security/php-and-vuln-analyzer.ts
function compareSemver(v1, v2) {
  const clean1 = v1.replace(/[^0-9.]/g, "").split(".").map((n) => parseInt(n, 10) || 0);
  const clean2 = v2.replace(/[^0-9.]/g, "").split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(clean1.length, clean2.length);
  for (let i = 0; i < len; i++) {
    const a = clean1[i] ?? 0;
    const b = clean2[i] ?? 0;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}
function evaluatePhpVersionVulnerabilities(version) {
  const cves = [];
  const parts = version.replace(/[^0-9.]/g, "").split(".").map((n) => parseInt(n, 10) || 0);
  const major = parts[0] ?? 0;
  const minor = parts[1] ?? 0;
  const branch = `${major}.${minor}`;
  const isEol = major < 8 || major === 8 && minor <= 1;
  const checkRange = (minBranch, patchedVersion) => {
    if (major < 8 || major === 8 && minor === 0) return true;
    if (branch === minBranch) {
      return compareSemver(version, patchedVersion) < 0;
    }
    return false;
  };
  if (major < 8 || major === 8 && minor === 0 || checkRange("8.1", "8.1.29") || checkRange("8.2", "8.2.20") || checkRange("8.3", "8.3.8")) {
    cves.push({
      cveId: "CVE-2024-4577",
      component: "PHP (PHP-CGI)",
      detectedVersion: version,
      severity: "CRITICAL",
      cvssScore: 9.8,
      title: "PHP-CGI Argument Injection (Best-Fit Character Encoding Bypass)",
      description: "Falha cr\xEDtica onde a convers\xE3o de codifica\xE7\xE3o Best-Fit do Windows transforma caracteres especiais (ex: soft-hyphen 0xAD) em h\xEDfens reais, permitindo inje\xE7\xE3o de argumentos no interpretador php-cgi.exe.",
      patchedVersion: "8.1.29 / 8.2.20 / 8.3.8+",
      remediation: "Atualizar o PHP imediatamente para >= 8.3.14 ou >= 8.2.26, migrar de PHP-CGI para PHP-FPM e bloquear sequ\xEAncias %AD na borda/WAF."
    });
  }
  if (major < 8 || major === 8 && minor === 0 || checkRange("8.1", "8.1.30") || checkRange("8.2", "8.2.24") || checkRange("8.3", "8.3.12")) {
    cves.push({
      cveId: "CVE-2024-8926 / CVE-2024-8927",
      component: "PHP (CGI / FastCGI)",
      detectedVersion: version,
      severity: "CRITICAL",
      cvssScore: 9.8,
      title: "PHP-CGI Protection Bypass & cgi.force_redirect Environment Collision",
      description: "Bypass da mitiga\xE7\xE3o original da CVE-2024-4577 e colis\xE3o de vari\xE1veis de ambiente HTTP que permite contornar a diretiva cgi.force_redirect.",
      patchedVersion: "8.1.30 / 8.2.24 / 8.3.12+",
      remediation: "Atualizar o PHP para >= 8.3.12 ou >= 8.2.24 e desativar completamente o bin\xE1rio php-cgi em diret\xF3rios p\xFAblicos."
    });
    cves.push({
      cveId: "CVE-2024-8925",
      component: "PHP Core (Multipart Parser)",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 7.5,
      title: "Erroneous Multipart Form-Data Boundary Parsing",
      description: "Erro de parsing em limites de requisi\xE7\xF5es multipart/form-data que pode causar corrup\xE7\xE3o ou exposi\xE7\xE3o indevida de dados de buffer em uploads.",
      patchedVersion: "8.1.30 / 8.2.24 / 8.3.12+",
      remediation: "Atualizar o runtime PHP para >= 8.3.12 ou >= 8.2.24."
    });
  }
  if (major < 8 || major === 8 && minor === 0 || checkRange("8.1", "8.1.28") || checkRange("8.2", "8.2.18") || checkRange("8.3", "8.3.5")) {
    cves.push({
      cveId: "CVE-2024-2756",
      component: "PHP Session / Cookie Parser",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 7.5,
      title: "__Host- and __Secure- Cookie Prefix Integrity Bypass",
      description: "A convers\xE3o autom\xE1tica de caracteres '[' e '.' para '_' em vari\xE1veis superglobais $_COOKIE permite sobrescrever cookies protegidos pelos prefixos __Host- e __Secure-.",
      patchedVersion: "8.1.28 / 8.2.18 / 8.3.5+",
      remediation: "Atualizar o PHP e validar nomes de cookies brutos no cabe\xE7alho HTTP Cookie."
    });
  }
  if (major < 8 || major === 8 && minor === 0 || checkRange("8.1", "8.1.29") || checkRange("8.2", "8.2.20") || checkRange("8.3", "8.3.8")) {
    cves.push({
      cveId: "CVE-2024-5458",
      component: "PHP Standard Library (filter_var)",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 7.3,
      title: "filter_var(FILTER_VALIDATE_URL) Validation Bypass (SSRF Vector)",
      description: "Falha na valida\xE7\xE3o de URLs com sintaxe IPv6/userinfo na fun\xE7\xE3o nativa filter_var(), permitindo bypass de filtros anti-SSRF e Open Redirect.",
      patchedVersion: "8.1.29 / 8.2.20 / 8.3.8+",
      remediation: "Atualizar o PHP e utilizar parser estrito de hostnames com allowlist."
    });
  }
  if (major < 8 || major === 8 && minor === 0 || checkRange("8.1", "8.1.31") || checkRange("8.2", "8.2.26") || checkRange("8.3", "8.3.14")) {
    cves.push({
      cveId: "CVE-2024-11234 / CVE-2024-11236",
      component: "PHP Streams / LDAP / PDO",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 8.1,
      title: "HTTP Stream Proxy Header Injection & Integer Overflow in ldap_escape",
      description: "Possibilidade de CRLF injection em conex\xF5es de stream via proxy e estouro de inteiro em fun\xE7\xF5es de escape LDAP/PDO.",
      patchedVersion: "8.1.31 / 8.2.26 / 8.3.14+",
      remediation: "Atualizar o PHP para >= 8.3.14, >= 8.2.26 ou migrar para a branch 8.4.x."
    });
  }
  return { isEol, cves };
}
function evaluateServerBannerVulnerabilities(serverHeader, poweredByHeader) {
  const findings = [];
  const combined = `${serverHeader} ${poweredByHeader}`;
  const apacheMatch = combined.match(/Apache\/(\d+\.\d+\.\d+)/i);
  if (apacheMatch) {
    const ver = apacheMatch[1];
    if (compareSemver(ver, "2.4.62") < 0) {
      findings.push({
        cveId: "CVE-2024-38476 / CVE-2024-40725 / CVE-2024-40898",
        component: "Apache HTTP Server",
        detectedVersion: ver,
        severity: "CRITICAL",
        cvssScore: 9.1,
        title: "Apache mod_rewrite SSRF & Source Code Disclosure Vulnerabilities",
        description: "Vers\xF5es do Apache anteriores \xE0 2.4.62 possuem falhas cr\xEDticas de revela\xE7\xE3o de c\xF3digo-fonte de scripts (CVE-2024-40725) e manipula\xE7\xE3o insegura de respostas de backend/mod_rewrite.",
        patchedVersion: "2.4.62+",
        remediation: "Atualizar o Apache HTTP Server para >= 2.4.62 e configurar 'ServerTokens Prod' e 'ServerSignature Off' no httpd.conf."
      });
    }
  }
  const nginxMatch = combined.match(/nginx\/(\d+\.\d+\.\d+)/i);
  if (nginxMatch) {
    const ver = nginxMatch[1];
    if (compareSemver(ver, "1.26.2") < 0) {
      findings.push({
        cveId: "CVE-2024-7347 / CVE-2024-32760",
        component: "Nginx Web Server",
        detectedVersion: ver,
        severity: "MEDIUM",
        cvssScore: 6.5,
        title: "Nginx HTTP/3 QUIC & MP4 Module Memory Safety Vulnerabilities",
        description: "Vers\xF5es anteriores ao Nginx 1.26.2 / 1.27.1 possuem vulnerabilidades de leitura/escrita de mem\xF3ria no m\xF3dulo ngx_http_mp4_module e no processamento HTTP/3 QUIC.",
        patchedVersion: "1.26.2+ / 1.27.1+",
        remediation: "Atualizar o Nginx para >= 1.26.2 e adicionar 'server_tokens off;' no bloco http do nginx.conf."
      });
    }
  }
  const opensslMatch = combined.match(/OpenSSL\/(\d+\.\d+\.\d+[a-z]?)/i);
  if (opensslMatch) {
    const ver = opensslMatch[1];
    if (ver.startsWith("1.1.1") || ver.startsWith("1.0.")) {
      findings.push({
        cveId: "OPENSSL-EOL-1.1.1",
        component: "OpenSSL",
        detectedVersion: ver,
        severity: "HIGH",
        cvssScore: 7.5,
        title: "OpenSSL 1.1.1 End-of-Life (Sem Suporte de Seguran\xE7a)",
        description: "A s\xE9rie OpenSSL 1.1.1 atingiu o fim de vida \xFAtil (EOL) em setembro de 2023 e n\xE3o recebe corre\xE7\xF5es p\xFAblicas para novas vulnerabilidades criptogr\xE1ficas.",
        patchedVersion: "3.0.15+ / 3.2.3+ / 3.3.2+",
        remediation: "Migrar a biblioteca TLS do servidor para OpenSSL 3.x atualizado."
      });
    } else if (ver.startsWith("3.0.") && compareSemver(ver, "3.0.15") < 0) {
      findings.push({
        cveId: "CVE-2024-6119 / CVE-2024-5535",
        component: "OpenSSL 3.0",
        detectedVersion: ver,
        severity: "HIGH",
        cvssScore: 7.5,
        title: "OpenSSL 3.0 Certificate Name Check & SSL_select_next_proto Buffer Overread",
        description: "Vulnerabilidade na valida\xE7\xE3o de certificados X.509 e leitura fora dos limites em negocia\xE7\xF5es ALPN/NPN em vers\xF5es OpenSSL < 3.0.15.",
        patchedVersion: "3.0.15+",
        remediation: "Atualizar os pacotes libssl/openssl do sistema operacional para >= 3.0.15."
      });
    }
  }
  const iisMatch = combined.match(/Microsoft-IIS\/(\d+\.\d+)/i);
  if (iisMatch) {
    const ver = iisMatch[1];
    if (compareSemver(ver, "10.0") < 0) {
      findings.push({
        cveId: "IIS-LEGACY-EOL",
        component: "Microsoft IIS",
        detectedVersion: ver,
        severity: "HIGH",
        cvssScore: 7.8,
        title: "Legacy Microsoft IIS / Windows Server End-of-Life",
        description: `O servidor exp\xF5e Microsoft-IIS/${ver}, associado ao Windows Server 2008 R2 / 2012, cujo ciclo de suporte estendido foi encerrado.`,
        patchedVersion: "IIS 10.0+ (Windows Server 2019/2022/2025)",
        remediation: "Migrar para Windows Server suportado e remover cabe\xE7alhos Server e X-Powered-By no web.config."
      });
    }
  }
  return findings;
}
var SAFE_EXPOSURE_PROBES = [
  {
    path: "/phpinfo.php",
    id: "PHPINFO_EXPOSED",
    category: "PHP_HARDENING",
    severity: "CRITICAL",
    title: "P\xE1gina de Diagn\xF3stico phpinfo() Exposta Publicamente",
    remediation: "Remover imediatamente o arquivo /phpinfo.php do servidor de produ\xE7\xE3o.",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && (body.includes("<title>phpinfo()</title>") || body.includes("PHP Version") && body.includes("Zend Extension"))) {
        return "P\xE1gina phpinfo() ativa revelando vari\xE1veis de ambiente, extens\xF5es e caminhos internos.";
      }
      return null;
    }
  },
  {
    path: "/info.php",
    id: "INFO_PHP_EXPOSED",
    category: "PHP_HARDENING",
    severity: "CRITICAL",
    title: "Script /info.php Exposto com Diagn\xF3stico do Servidor",
    remediation: "Excluir /info.php do diret\xF3rio p\xFAblico (document_root).",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && (body.includes("<title>phpinfo()</title>") || body.includes("PHP Version") && body.includes("Configuration File (php.ini) Path"))) {
        return "Script /info.php p\xFAblico contendo informa\xE7\xF5es completas do ambiente PHP.";
      }
      return null;
    }
  },
  {
    path: "/.user.ini",
    id: "PHP_USER_INI_EXPOSED",
    category: "PHP_HARDENING",
    severity: "HIGH",
    title: "Arquivo de Configura\xE7\xE3o PHP (/.user.ini) Acess\xEDvel",
    remediation: "Bloquear acesso a arquivos .user.ini e .ini no Nginx/Apache.",
    validateMatch: (status, ct, body) => {
      if (status === 200 && !ct.includes("text/html") && !body.trim().startsWith("<!DOCTYPE") && !body.trim().startsWith("<html") && /(?:display_errors|memory_limit|upload_max_filesize|open_basedir|auto_prepend_file)\s*=/i.test(body)) {
        return "Arquivo /.user.ini p\xFAblico expondo diretivas internas do interpretador PHP.";
      }
      return null;
    }
  },
  {
    path: "/.git/HEAD",
    id: "GIT_REPOSITORY_EXPOSED",
    category: "SENSITIVE_FILE",
    severity: "CRITICAL",
    title: "Reposit\xF3rio Git (/.git/HEAD) Exposto em Produ\xE7\xE3o",
    remediation: "Bloquear acesso ao diret\xF3rio /.git no servidor web (location ~ /\\.git { deny all; }).",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && /^ref:\s+refs\/heads\//m.test(body.trim())) {
        return `Metadados do Git acess\xEDveis publicamente (${body.trim().slice(0, 50)}). Permite reconstru\xE7\xE3o do c\xF3digo-fonte.`;
      }
      return null;
    }
  },
  {
    path: "/.env",
    id: "DOTENV_FILE_EXPOSED",
    category: "SENSITIVE_FILE",
    severity: "CRITICAL",
    title: "Arquivo de Vari\xE1veis de Ambiente (/.env) Exposto",
    remediation: "Mover o arquivo .env para fora da pasta p\xFAblica e bloquear arquivos ocultos (dot-files).",
    validateMatch: (status, ct, body) => {
      if (status === 200 && !ct.includes("text/html") && !body.trim().startsWith("<") && /(?:APP_ENV|APP_KEY|DB_HOST|DB_PASSWORD|DATABASE_URL|AWS_ACCESS_KEY_ID|JWT_SECRET|STRIPE_SECRET)\s*=/i.test(body)) {
        return "Arquivo /.env p\xFAblico contendo chaves de configura\xE7\xE3o e credenciais de banco/API.";
      }
      return null;
    }
  },
  {
    path: "/actuator/health",
    id: "SPRING_ACTUATOR_EXPOSED",
    category: "DEBUG_INTERFACE",
    severity: "MEDIUM",
    title: "Endpoint Spring Boot Actuator (/actuator/health) Exposto",
    remediation: "Restringir management.endpoints.web.exposure.include no application.properties e exigir autentica\xE7\xE3o.",
    validateMatch: (status, ct, body) => {
      if (status === 200 && (ct.includes("application/json") || ct.includes("spring-boot.actuator")) && /"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"/i.test(body)) {
        return "Spring Boot Actuator respondendo publicamente sem autentica\xE7\xE3o.";
      }
      return null;
    }
  },
  {
    path: "/openapi.json",
    id: "OPENAPI_SCHEMA_EXPOSED",
    category: "DEBUG_INTERFACE",
    severity: "LOW",
    title: "Especifica\xE7\xE3o de API (/openapi.json) P\xFAblica em Produ\xE7\xE3o",
    remediation: "Restringir a documenta\xE7\xE3o Swagger/OpenAPI a redes internas ou exigir autentica\xE7\xE3o em produ\xE7\xE3o.",
    validateMatch: (status, ct, body) => {
      if (status === 200 && ct.includes("json") && /"(?:openapi|swagger)"\s*:\s*"[23]\./.test(body)) {
        return "Esquema completo de rotas OpenAPI/Swagger exposto publicamente.";
      }
      return null;
    }
  },
  {
    path: "/server-status",
    id: "APACHE_SERVER_STATUS_EXPOSED",
    category: "DEBUG_INTERFACE",
    severity: "HIGH",
    title: "M\xF3dulo Apache mod_status (/server-status) P\xFAblico",
    remediation: "Restringir o Location /server-status no Apache apenas para localhost (Require local).",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && body.includes("Apache Server Status for") && body.includes("Server uptime:")) {
        return "Painel Apache mod_status p\xFAblico revelando IPs de clientes e URLs internas em processamento.";
      }
      return null;
    }
  },
  {
    path: "/wp-json/wp/v2/users",
    id: "WORDPRESS_REST_USERS_EXPOSED",
    category: "PHP_HARDENING",
    severity: "MEDIUM",
    title: "WordPress REST API (/wp-json/wp/v2/users) Expondo Lista de Usu\xE1rios",
    remediation: "Restringir o endpoint /wp-json/wp/v2/users via filtro rest_endpoints no functions.php ou regra de WAF.",
    validateMatch: (status, ct, body) => {
      if (status === 200 && ct.includes("json") && body.includes('"slug":') && body.includes('"id":')) {
        return "Endpoint REST API /wp-json/wp/v2/users p\xFAblico permitindo enumera\xE7\xE3o de logins de administradores/autores.";
      }
      return null;
    }
  }
];
async function analyzePhpAndWebVulnerabilities(targetUrl) {
  const start = Date.now();
  const normalizedUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
  const parsedUrl = new URL(normalizedUrl);
  const baseOrigin = parsedUrl.origin;
  let phpDetected = false;
  let phpVersion = null;
  let phpIsEol = false;
  let osHint = "UNKNOWN";
  let serverBanner = "Hidden / Not Disclosed";
  let poweredByBanner = "Hidden / Not Disclosed";
  let securityTxtPresent = false;
  const cveFindings = [];
  const exposureFindings = [];
  try {
    const mainRes = await fetch(normalizedUrl, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "ChimeraGuard-SecurityAuditor/1.5 (+https://chimera-guard.vercel.app)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: AbortSignal.timeout(5e3)
    });
    const serverHdr = mainRes.headers.get("server") || "";
    const poweredByHdr = mainRes.headers.get("x-powered-by") || "";
    const setCookieHdr = mainRes.headers.get("set-cookie") || "";
    const debugTokenHdr = mainRes.headers.get("x-debug-token") || mainRes.headers.get("x-debug-token-link") || "";
    const aspnetVerHdr = mainRes.headers.get("x-aspnet-version") || "";
    if (serverHdr) serverBanner = serverHdr;
    if (poweredByHdr) poweredByBanner = poweredByHdr;
    const combinedHeaders = `${serverHdr} ${poweredByHdr}`;
    if (/(?:Win32|Win64|Windows|Microsoft-IIS)/i.test(combinedHeaders)) {
      osHint = "WINDOWS";
    } else if (/(?:Ubuntu|Debian|CentOS|Red Hat|Fedora|Unix|Alpine|FreeBSD)/i.test(combinedHeaders)) {
      osHint = "LINUX_UNIX";
    }
    const phpVerMatch = combinedHeaders.match(/PHP\/(\d+\.\d+\.\d+)/i);
    if (phpVerMatch) {
      phpDetected = true;
      phpVersion = phpVerMatch[1];
      exposureFindings.push({
        id: "PHP_VERSION_EXPOSED",
        category: "PHP_HARDENING",
        severity: "MEDIUM",
        pathOrHeader: `X-Powered-By / Server: PHP/${phpVersion}`,
        title: "Exposi\xE7\xE3o Expl\xEDcita de Vers\xE3o do Runtime PHP",
        evidence: `O servidor anuncia 'PHP/${phpVersion}' nos cabe\xE7alhos HTTP, facilitando o mapeamento automatizado de CVEs.`,
        remediation: "Definir 'expose_php = Off' no arquivo php.ini para ocultar o cabe\xE7alho X-Powered-By."
      });
      const phpEval = evaluatePhpVersionVulnerabilities(phpVersion);
      phpIsEol = phpEval.isEol;
      cveFindings.push(...phpEval.cves);
      if (phpIsEol) {
        exposureFindings.push({
          id: "PHP_EOL_VERSION",
          category: "PHP_HARDENING",
          severity: "HIGH",
          pathOrHeader: `PHP/${phpVersion}`,
          title: `Vers\xE3o do PHP em Fim de Vida \xDAtil (End-of-Life: ${phpVersion})`,
          evidence: `A vers\xE3o PHP ${phpVersion} n\xE3o recebe mais atualiza\xE7\xF5es oficiais de seguran\xE7a da PHP Foundation.`,
          remediation: "Planejar atualiza\xE7\xE3o imediata do runtime para PHP 8.3.x ou PHP 8.4.x."
        });
      }
    } else if (/PHPSESSID/i.test(setCookieHdr) || /\.php(?:\?|$)/i.test(normalizedUrl) || /\bPHP\b/i.test(combinedHeaders)) {
      phpDetected = true;
    }
    if (/PHPSESSID=/i.test(setCookieHdr)) {
      const hasHttpOnly = /HttpOnly/i.test(setCookieHdr);
      const hasSecure = /Secure/i.test(setCookieHdr);
      if (!hasHttpOnly || !hasSecure) {
        exposureFindings.push({
          id: "PHP_SESSION_COOKIE_INSECURE",
          category: "PHP_HARDENING",
          severity: "HIGH",
          pathOrHeader: "Set-Cookie: PHPSESSID",
          title: "Cookie de Sess\xE3o PHPSESSID sem Flags de Blindagem",
          evidence: `O cookie PHPSESSID foi emitido sem ${!hasHttpOnly ? "session.cookie_httponly" : ""} ${!hasSecure ? "session.cookie_secure" : ""}.`.trim(),
          remediation: "Configurar 'session.cookie_httponly = 1', 'session.cookie_secure = 1' e 'session.cookie_samesite = Lax' no php.ini."
        });
      }
    }
    if (phpDetected) {
      exposureFindings.push({
        id: "PHP_SESSION_UPLOAD_PROGRESS_ZERO_DAY",
        category: "PHP_HARDENING",
        severity: "HIGH",
        pathOrHeader: "php.ini: session.upload_progress.enabled",
        title: "Mitiga\xE7\xE3o Cr\xEDtica: Desativar session.upload_progress (CVE-2026-115560 & PHP2Shell)",
        evidence: "O PHP mant\xE9m 'session.upload_progress.enabled = On' por padr\xE3o, permitindo inicializa\xE7\xE3o de arquivos tempor\xE1rios de sess\xE3o no disco e vetor de RCE em CVE-2026-115560.",
        remediation: "Definir 'session.upload_progress.enabled = Off' e 'session.upload_progress.cleanup = On' no php.ini para neutralizar o vetor at\xE9 a publica\xE7\xE3o de patch oficial."
      });
    }
    const serverCves = evaluateServerBannerVulnerabilities(serverHdr, poweredByHdr);
    cveFindings.push(...serverCves);
    if (debugTokenHdr) {
      exposureFindings.push({
        id: "SYMFONY_LARAVEL_PROFILER_EXPOSED",
        category: "DEBUG_INTERFACE",
        severity: "HIGH",
        pathOrHeader: `X-Debug-Token: ${debugTokenHdr}`,
        title: "Profiler de Depura\xE7\xE3o (Symfony/Laravel) Ativo em Produ\xE7\xE3o",
        evidence: `Cabe\xE7alho X-Debug-Token detectado (${debugTokenHdr}), indicando modo APP_DEBUG ativo.`,
        remediation: "Desativar o modo debug em produ\xE7\xE3o (APP_ENV=prod / APP_DEBUG=false)."
      });
    }
    if (aspnetVerHdr) {
      exposureFindings.push({
        id: "ASPNET_VERSION_EXPOSED",
        category: "VERSION_DISCLOSURE",
        severity: "LOW",
        pathOrHeader: `X-AspNet-Version: ${aspnetVerHdr}`,
        title: "Vazamento de Vers\xE3o do .NET Framework",
        evidence: `O cabe\xE7alho X-AspNet-Version revela a vers\xE3o exata da stack (${aspnetVerHdr}).`,
        remediation: 'Adicionar <httpRuntime enableVersionHeader="false" /> no arquivo web.config.'
      });
    }
    if (/Next\.js/i.test(poweredByHdr)) {
      exposureFindings.push({
        id: "NEXTJS_POWERED_BY_EXPOSED",
        category: "VERSION_DISCLOSURE",
        severity: "LOW",
        pathOrHeader: `X-Powered-By: ${poweredByHdr}`,
        title: "Cabe\xE7alho X-Powered-By: Next.js Exposto",
        evidence: "A aplica\xE7\xE3o anuncia explicitamente o uso de Next.js. Certifique-se de estar em vers\xE3o >= 14.2.25 ou >= 15.2.3 (mitiga\xE7\xE3o contra CVE-2025-29927) e remover o cabe\xE7alho.",
        remediation: "Configurar 'poweredByHeader: false' no arquivo next.config.js e bloquear o cabe\xE7alho x-middleware-subrequest no proxy reverso."
      });
    }
    const mainBody = await mainRes.text();
    if (/\/wp-content\/|\/wp-includes\/|wp-json|<meta[^>]+name=["']generator["'][^>]+content=["']WordPress/i.test(mainBody)) {
      phpDetected = true;
      const pluginMatches = mainBody.matchAll(/\/wp-content\/plugins\/([a-zA-Z0-9_-]+)/gi);
      const foundPlugins = Array.from(new Set(Array.from(pluginMatches, (m) => m[1])));
      if (foundPlugins.length > 0) {
        exposureFindings.push({
          id: "WORDPRESS_PLUGINS_ENUMERATED",
          category: "VERSION_DISCLOSURE",
          severity: "LOW",
          pathOrHeader: "/wp-content/plugins/",
          title: `Plugins do WordPress Identificados no HTML (${foundPlugins.length} ativos)`,
          evidence: `Plugins mapeados publicamente: ${foundPlugins.slice(0, 10).join(", ")}${foundPlugins.length > 10 ? "..." : ""}.`,
          remediation: "Manter todos os plugins atualizados com os patches mais recentes e auditar permiss\xF5es de arquivos."
        });
      }
    }
    if (/(?:<b>Fatal error<\/b>:|<b>Warning<\/b>:|<b>Parse error<\/b>:).*? in <b>.*?(?:\.php)<\/b> on line <b>\d+<\/b>/i.test(mainBody)) {
      phpDetected = true;
      exposureFindings.push({
        id: "PHP_DISPLAY_ERRORS_ENABLED",
        category: "PHP_HARDENING",
        severity: "HIGH",
        pathOrHeader: normalizedUrl,
        title: "Diretiva display_errors Ativa (Vazamento de Caminhos e Stack Trace PHP)",
        evidence: "A resposta HTML cont\xE9m mensagens nativas de erro do PHP revelando caminhos internos do sistema de arquivos.",
        remediation: "Definir 'display_errors = Off' e 'log_errors = On' no arquivo php.ini de produ\xE7\xE3o."
      });
    }
    if (/<title>Index of \//i.test(mainBody)) {
      exposureFindings.push({
        id: "DIRECTORY_LISTING_ENABLED",
        category: "DIRECTORY_LISTING",
        severity: "HIGH",
        pathOrHeader: normalizedUrl,
        title: "Listagem Autom\xE1tica de Diret\xF3rios (Directory Indexing) Ativa",
        evidence: "O servidor retorna '<title>Index of /', permitindo navegar pelos arquivos internos.",
        remediation: "Desativar autoindex ('Options -Indexes' no Apache ou 'autoindex off;' no Nginx)."
      });
    }
  } catch {
  }
  const probePromises = SAFE_EXPOSURE_PROBES.map(async (probe) => {
    try {
      const probeUrl = `${baseOrigin}${probe.path}`;
      const res = await fetch(probeUrl, {
        method: "GET",
        redirect: "manual",
        // Evita seguir redirects para páginas de login ou home (anti-falso-positivo)
        headers: {
          "User-Agent": "ChimeraGuard-SecurityAuditor/1.5 (+https://chimera-guard.vercel.app)"
        },
        signal: AbortSignal.timeout(3500)
      });
      if (res.status === 200) {
        const ct = (res.headers.get("content-type") || "").toLowerCase();
        const text = (await res.text()).slice(0, 8192);
        const evidence = probe.validateMatch(res.status, ct, text);
        if (evidence) {
          if (probe.category === "PHP_HARDENING") phpDetected = true;
          exposureFindings.push({
            id: probe.id,
            category: probe.category,
            severity: probe.severity,
            pathOrHeader: probe.path,
            title: probe.title,
            evidence,
            remediation: probe.remediation
          });
        }
      }
    } catch {
    }
  });
  const securityTxtPromise = (async () => {
    try {
      const res = await fetch(`${baseOrigin}/.well-known/security.txt`, {
        method: "GET",
        redirect: "manual",
        headers: {
          "User-Agent": "ChimeraGuard-SecurityAuditor/1.5 (+https://chimera-guard.vercel.app)"
        },
        signal: AbortSignal.timeout(3500)
      });
      if (res.status === 200) {
        const text = await res.text();
        if (/^Contact:/im.test(text)) {
          securityTxtPresent = true;
          if (!/^Expires:/im.test(text)) {
            exposureFindings.push({
              id: "SECURITY_TXT_MISSING_EXPIRES",
              category: "RFC_COMPLIANCE",
              severity: "LOW",
              pathOrHeader: "/.well-known/security.txt",
              title: "Arquivo security.txt sem Diretiva Obrigat\xF3ria Expires (RFC 9116)",
              evidence: "O arquivo /.well-known/security.txt existe, mas n\xE3o cont\xE9m o campo Expires exigido pela RFC 9116.",
              remediation: "Adicionar a diretiva 'Expires: 2027-12-31T23:59:59.000Z' no arquivo security.txt."
            });
          }
          return;
        }
      }
      exposureFindings.push({
        id: "SECURITY_TXT_MISSING",
        category: "RFC_COMPLIANCE",
        severity: "INFO",
        pathOrHeader: "/.well-known/security.txt",
        title: "Pol\xEDtica de Divulga\xE7\xE3o de Vulnerabilidades (security.txt - RFC 9116) Ausente",
        evidence: "O dom\xEDnio n\xE3o publica o arquivo padronizado /.well-known/security.txt para contato de seguran\xE7a.",
        remediation: "Criar o arquivo /.well-known/security.txt com as diretivas Contact: e Expires: conforme a RFC 9116."
      });
    } catch {
    }
  })();
  await Promise.all([...probePromises, securityTxtPromise]);
  let riskScore = 0;
  for (const cve of cveFindings) {
    if (cve.severity === "CRITICAL") riskScore += 45;
    else if (cve.severity === "HIGH") riskScore += 25;
    else if (cve.severity === "MEDIUM") riskScore += 15;
    else riskScore += 5;
  }
  for (const exp of exposureFindings) {
    if (exp.severity === "CRITICAL") riskScore += 40;
    else if (exp.severity === "HIGH") riskScore += 25;
    else if (exp.severity === "MEDIUM") riskScore += 12;
    else if (exp.severity === "LOW") riskScore += 5;
  }
  riskScore = Math.min(100, riskScore);
  let securityGrade = "A+";
  if (riskScore === 0) securityGrade = "A+";
  else if (riskScore <= 10) securityGrade = "A";
  else if (riskScore <= 25) securityGrade = "B";
  else if (riskScore <= 50) securityGrade = "C";
  else if (riskScore <= 75) securityGrade = "D";
  else securityGrade = "F";
  let overallStatus = "SECURE";
  if (riskScore >= 60 || cveFindings.some((c) => c.severity === "CRITICAL") || exposureFindings.some((e) => e.severity === "CRITICAL")) {
    overallStatus = "CRITICAL";
  } else if (riskScore >= 30 || cveFindings.length > 0) {
    overallStatus = "VULNERABLE";
  } else if (riskScore > 0) {
    overallStatus = "WARNING";
  }
  return {
    targetUrl: normalizedUrl,
    phpDetected,
    phpVersion,
    phpIsEol,
    osHint,
    serverBanner,
    poweredByBanner,
    cveFindings,
    exposureFindings,
    securityTxtPresent,
    riskScore,
    securityGrade,
    overallStatus,
    remediationConfig: {
      phpIni: `; Blindagem Recomendada php.ini (ChimeraGuard 2026)
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
allow_url_include = Off
allow_url_fopen = Off
cgi.force_redirect = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
session.use_strict_mode = 1
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,show_source,phpinfo`,
      nginxConf: `# Blindagem Nginx contra PHP-CGI Argument Injection (CVE-2024-4577) e Arquivos Sens\xEDveis
server_tokens off;
location ~ /\\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
}
location ~* /(?:phpinfo|info|test)\\.php$ {
    deny all;
}
if ($query_string ~* "%ad") {
    return 403;
}`,
      apacheConf: `# Blindagem Apache (.htaccess / httpd.conf) contra CVE-2024-4577
ServerTokens Prod
ServerSignature Off
Options -Indexes
RewriteEngine On
RewriteCond %{QUERY_STRING} ^%ad [NC]
RewriteRule .* - [F,L]
<FilesMatch "^\\.(env|git|user\\.ini)|^(phpinfo|info)\\.php$">
    Require all denied
</FilesMatch>`
    },
    durationMs: Date.now() - start
  };
}

// src/cli-source.ts
var CLI_VERSION = "1.6.0";
var args = process.argv.slice(2);
var command = args[0] || "help";
var ANSI = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  green: "\x1B[32m",
  yellow: "\x1B[33m",
  red: "\x1B[31m",
  cyan: "\x1B[36m",
  gray: "\x1B[90m",
  magenta: "\x1B[35m"
};
function printBanner() {
  const isLegacyInvoked = (process.argv[1] || "").toLowerCase().includes("obsidiansec");
  if (isLegacyInvoked && !args.includes("--json") && !args.includes("--sarif") && !args.some((a) => a.startsWith("--format="))) {
    console.log(`${ANSI.yellow}\u26A1 NOTICE: ObsidianSec has officially evolved into ChimeraGuard!${ANSI.reset}`);
    console.log(`${ANSI.yellow}   Both commands work, but 'npx chimeraguard' is now the official CLI.${ANSI.reset}
`);
  }
  console.log(`
${ANSI.bold}${ANSI.cyan}\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551    \u{1F6E1}\uFE0F  CHIMERAGUARD CLI // DEVSECOPS & DEFENSE ARSENAL 2026           \u2551
\u2551    (Formerly ObsidianSec \xB7 Multi-Vector Security Guardian)           \u2551
\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D${ANSI.reset}
`);
  if (!args.includes("--json") && !args.includes("--sarif") && !args.some((a) => a.startsWith("--format="))) {
    const cachedUpdate = checkCachedUpdateSync(CLI_VERSION);
    if (cachedUpdate) console.log(cachedUpdate);
    triggerBackgroundUpdateCheck(CLI_VERSION);
  }
}
async function runAudit() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec audit <url> [--min-grade=A] [--json]${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const config = loadObsidianConfig();
  const scope = validateTargetScope(targetUrl, config);
  if (!scope.allowed) {
    if (isJson) {
      console.log(JSON.stringify({ error: scope.reason, errorCode: scope.errorCode }, null, 2));
    } else {
      printBanner();
      console.error(`${ANSI.red}\u{1F6AB} [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
      console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}`);
      console.log(`Para autorizar este alvo, adicione-o ao 'scope.allowlist' em ${ANSI.bold}obsidiansec.config.json${ANSI.reset}.
`);
    }
    process.exit(1);
  }
  const minGradeArg = args.find((a) => a.startsWith("--min-grade="));
  const minGrade = minGradeArg ? minGradeArg.split("=")[1].toUpperCase() : "B";
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F50D} [1/2] Disparando sondagem t\xE1tica de borda em ${ANSI.bold}${targetUrl}${ANSI.reset}...`);
  try {
    const report = await auditUniversalEndpoint(targetUrl);
    let score = 0;
    const h = report.securityHeaders;
    if (h.csp.present) score += h.csp.isReportOnly ? 15 : 30;
    if (h.xFrameOptions.present) score += 20;
    if (h.hsts.present) score += 20;
    if (h.xContentTypeOptions.present) score += 15;
    if (h.permissionsPolicy.present) score += 15;
    score = Math.min(100, score);
    let grade = "F";
    if (score >= 85) grade = "A+";
    else if (score >= 70) grade = "A";
    else if (score >= 50) grade = "B";
    else if (score >= 30) grade = "C";
    const isHtml = args.includes("--html") || args.includes("--report=html") || args.some((a) => a.startsWith("--html="));
    const htmlArg = args.find((a) => a.startsWith("--html="));
    const htmlPath = htmlArg ? htmlArg.split("=")[1] : "obsidiansec-report.html";
    if (isHtml) {
      const htmlContent = generateHtmlSecurityReport(report, score, grade);
      fs5.writeFileSync(path5.resolve(process.cwd(), htmlPath), htmlContent, "utf-8");
      console.log(`
${ANSI.green}\u{1F4C4} Relat\xF3rio Executivo HTML gerado com sucesso em:${ANSI.reset} ${htmlPath}`);
    }
    if (isJson) {
      console.log(JSON.stringify({ ...report, score, grade }, null, 2));
      process.exit(0);
    }
    const gradeColor = grade === "A+" || grade === "A" ? ANSI.green : grade === "B" ? ANSI.yellow : ANSI.red;
    console.log(`
======================================================================`);
    console.log(`\u{1F4CA} RESULTADO DA AUDITORIA DE SEGURAN\xC7A`);
    console.log(`======================================================================`);
    console.log(`\u2022 Alvo Auditado:           ${report.targetUrl}`);
    console.log(`\u2022 Servidor / Borda:        ${report.serverDetected}`);
    console.log(`\u2022 Score de Blindagem:      ${score} / 100`);
    console.log(`\u2022 Nota Final:              ${gradeColor}${ANSI.bold}GRADE ${grade}${ANSI.reset}`);
    console.log(`\u2022 Status:                  ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "A\xC7\xC3O REQUERIDA"}${ANSI.reset}`);
    console.log(`\u2022 Cadeia de Ataque:        ${report.attackChain.riskSummary}`);
    console.log(`======================================================================
`);
    console.log(`\u{1F6E1}\uFE0F  CONTROLES DE BORDA:`);
    console.log(`  [${h.csp.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] Content-Security-Policy (CSP)`);
    console.log(`  [${h.xFrameOptions.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] X-Frame-Options (Anti-Clickjacking)`);
    console.log(`  [${h.hsts.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] Strict-Transport-Security (HSTS)`);
    console.log(`  [${h.xContentTypeOptions.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] X-Content-Type-Options (nosniff)`);
    console.log(`  [${h.permissionsPolicy.present ? ANSI.green + "\u2713" : ANSI.red + "\u2717"}${ANSI.reset}] Permissions-Policy`);
    console.log(`
======================================================================
`);
    const gradeRanks = { "A+": 5, "A": 4, "B": 3, "C": 2, "F": 1, "ERR": 0 };
    const currentRank = gradeRanks[grade] || 0;
    const requiredRank = gradeRanks[minGrade] || 3;
    if (currentRank < requiredRank) {
      console.error(`${ANSI.red}\u274C [CI/CD Quality Gate]: Reprovado! A nota ${grade} \xE9 inferior \xE0 nota m\xEDnima exigida (${minGrade}).${ANSI.reset}
`);
      process.exit(1);
    }
    console.log(`${ANSI.green}\u2705 [CI/CD Quality Gate]: Aprovado com sucesso! O deploy atende aos requisitos de seguran\xE7a.${ANSI.reset}
`);
    process.exit(0);
  } catch (err) {
    console.error(`
${ANSI.red}\u274C Falha na auditoria:${ANSI.reset} ${err.message}
`);
    process.exit(1);
  }
}
async function runDns() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}\u274C Erro: Dom\xEDnio n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec dns <dominio>${ANSI.reset}`);
    process.exit(1);
  }
  const config = loadObsidianConfig();
  const scope = validateTargetScope(domain, config);
  if (!scope.allowed) {
    printBanner();
    console.error(`${ANSI.red}\u{1F6AB} [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
    console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}
`);
    process.exit(1);
  }
  printBanner();
  console.log(`\u{1F50D} Consultando registros DNS e Anti-Phishing para ${ANSI.bold}${domain}${ANSI.reset}...
`);
  try {
    const report = await auditDomainDnsSecurity(domain);
    console.log(`\u2022 Dom\xEDnio:             ${report.domain}`);
    console.log(`\u2022 Score de Email:      ${report.emailSecurityScore} / 100`);
    console.log(`\u2022 Status:              ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "ALERTA"}${ANSI.reset}`);
    console.log(`\u2022 SPF:                 ${report.spf.present ? ANSI.green + "ATIVO (" + report.spf.qualifier + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`\u2022 DMARC:               ${report.dmarc.present ? ANSI.green + "ATIVO (p=" + report.dmarc.policy + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`\u2022 DNSSEC:              ${report.dnssecActive ? ANSI.green + "ATIVO" : ANSI.gray + "INATIVO"}${ANSI.reset}`);
    console.log(`
======================================================================
`);
  } catch (err) {
    console.error(`
${ANSI.red}\u274C Falha na auditoria DNS:${ANSI.reset} ${err.message}
`);
  }
}
async function runScanDir() {
  const dirInput = args.find((a) => !a.startsWith("-") && a !== "scan-dir" && a !== "scan" && a !== "sast") || process.cwd();
  const isJson = args.includes("--json") || args.some((a) => a.startsWith("--format=json"));
  const isSarif = args.includes("--sarif") || args.some((a) => a.startsWith("--format=sarif"));
  const outputArg = args.find((a) => a.startsWith("--output=") || a.startsWith("-o="));
  const outputPath = outputArg ? outputArg.split("=")[1] : null;
  if (!isJson && !isSarif) printBanner();
  if (!isJson && !isSarif) console.log(`\u{1F50D} Varrendo arquivos e ca\xE7ando segredos em ${ANSI.bold}${dirInput}${ANSI.reset}...
`);
  const report = scanDirectoryForSecrets(dirInput);
  if (isSarif) {
    const sarifDoc = convertSecretReportToSarif(report);
    const serialized = JSON.stringify(sarifDoc, null, 2);
    if (outputPath) {
      fs5.writeFileSync(path5.resolve(process.cwd(), outputPath), serialized, "utf-8");
      console.log(`${ANSI.green}\u2705 Relat\xF3rio SARIF v2.1.0 gerado com sucesso em:${ANSI.reset} ${outputPath}`);
    } else {
      console.log(serialized);
    }
    process.exit(report.isClean ? 0 : 1);
  }
  if (isJson) {
    const serialized = JSON.stringify(report, null, 2);
    if (outputPath) {
      fs5.writeFileSync(path5.resolve(process.cwd(), outputPath), serialized, "utf-8");
      console.log(`${ANSI.green}\u2705 Relat\xF3rio JSON salvo em:${ANSI.reset} ${outputPath}`);
    } else {
      console.log(serialized);
    }
    process.exit(report.isClean ? 0 : 1);
  }
  if (outputPath) {
    fs5.writeFileSync(path5.resolve(process.cwd(), outputPath), JSON.stringify(report, null, 2), "utf-8");
    console.log(`${ANSI.green}\u{1F4C1} C\xF3pia do relat\xF3rio salva em:${ANSI.reset} ${outputPath}
`);
  }
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} RELAT\xD3RIO DO CA\xC7ADOR DE SEGREDOS & SAST LOCAL`);
  console.log(`======================================================================`);
  console.log(`\u2022 Arquivos Analisados:     ${report.totalFilesScanned}`);
  console.log(`\u2022 Dura\xE7\xE3o:                 ${report.scanDurationMs}ms`);
  console.log(`\u2022 Vulnerabilidades:        ${report.isClean ? ANSI.green + "0 (LIMPO)" : ANSI.red + report.findings.length + " ENCONTRADAS"}${ANSI.reset}`);
  console.log(`\u2022 Cr\xEDticas:                ${report.criticalCount > 0 ? ANSI.red + report.criticalCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`\u2022 Altas:                   ${report.highCount > 0 ? ANSI.yellow + report.highCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`======================================================================
`);
  if (report.findings.length > 0) {
    console.log(`\u26A0\uFE0F  VULNERABILIDADES DETECTADAS:`);
    report.findings.forEach((f, idx) => {
      const color = f.severity === "CRITICAL" ? ANSI.red : ANSI.yellow;
      console.log(`
  [#${idx + 1}] ${color}${ANSI.bold}[${f.severity}] ${f.description}${ANSI.reset}`);
      console.log(`      \u{1F4C1} Arquivo: ${ANSI.cyan}${f.filePath}:${f.lineNumber}${ANSI.reset}`);
      console.log(`      \u{1F50D} Trecho:  ${ANSI.gray}${f.snippet}${ANSI.reset}`);
    });
    console.log(`
${ANSI.red}\u274C [SAST Gate]: Foram encontrados segredos sens\xEDveis no c\xF3digo. Remova-os antes de publicar!${ANSI.reset}
`);
    process.exit(1);
  } else {
    console.log(`${ANSI.green}\u2705 [SAST Gate]: Nenhum segredo ou credencial vazada detectada no c\xF3digo!${ANSI.reset}
`);
    process.exit(0);
  }
}
async function runJwt() {
  const token = args[1];
  if (!token) {
    console.error(`${ANSI.red}\u274C Erro: Token JWT n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec jwt <token>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const report = auditJwtToken(token);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.status === "CRITICAL" ? 1 : 0);
  }
  printBanner();
  console.log(`\u{1F39F}\uFE0F AUDITORIA DE SEGURAN\xC7A DE TOKEN JWT
`);
  if (!report.isValidStructure) {
    console.error(`${ANSI.red}\u274C Formato inv\xE1lido de JWT.${ANSI.reset}`);
    report.issues.forEach((i) => console.log(`  - ${i.message}`));
    process.exit(1);
  }
  const statusColor = report.status === "SECURE" ? ANSI.green : report.status === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`\u2022 Algoritmo:           ${ANSI.bold}${report.algorithm}${ANSI.reset}`);
  console.log(`\u2022 Score de Seguran\xE7a:  ${report.securityScore} / 100`);
  console.log(`\u2022 Status:              ${statusColor}${ANSI.bold}${report.status}${ANSI.reset}`);
  console.log(`\u2022 Assinatura Presente: ${report.signaturePresent ? ANSI.green + "SIM" : ANSI.red + "N\xC3O (alg: none)"}${ANSI.reset}`);
  console.log(`\u2022 Expira\xE7\xE3o:           ${report.hasExpiration ? report.isExpired ? ANSI.red + "EXPIRADO" : ANSI.green + "V\xC1LIDO" : ANSI.yellow + "SEM EXPIRA\xC7\xC3O"}${ANSI.reset}`);
  console.log(`
\u{1F4DC} HEADER DECODIFICADO:`);
  console.log(JSON.stringify(report.header, null, 2));
  console.log(`
\u{1F4E6} PAYLOAD (CLAIMS):`);
  console.log(JSON.stringify(report.payload, null, 2));
  if (report.issues.length > 0) {
    console.log(`
\u26A0\uFE0F  RISCOS DETECTADOS:`);
    report.issues.forEach((iss) => {
      const color = iss.severity === "CRITICAL" ? ANSI.red : iss.severity === "HIGH" ? ANSI.yellow : ANSI.gray;
      console.log(`  ${color}[${iss.severity}] ${iss.message}${ANSI.reset}`);
    });
  }
  console.log(`
======================================================================
`);
  process.exit(report.status === "CRITICAL" ? 1 : 0);
}
async function runSubdomains() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}\u274C Erro: Dom\xEDnio n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec subdomains <dominio>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F310} Buscando subdom\xEDnios via Certificate Transparency Logs para ${ANSI.bold}${domain}${ANSI.reset}...
`);
  const report = await discoverSubdomains(domain);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} SUPERF\xCDCIE DE ATAQUE PASSIVA (SUBDOM\xCDNIOS)`);
  console.log(`======================================================================`);
  console.log(`\u2022 Dom\xEDnio Alvo:        ${report.domain}`);
  console.log(`\u2022 Total Descoberto:    ${ANSI.bold}${report.totalFound} subdom\xEDnios \xFAnicos${ANSI.reset}`);
  console.log(`\u2022 Fonte:               ${report.source}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  if (report.subdomains.length > 0) {
    report.subdomains.forEach((s) => console.log(`  ${ANSI.cyan}\u2022${ANSI.reset} ${s}`));
  } else {
    console.log(`  Nenhum subdom\xEDnio adicional encontrado nos registros p\xFAblicos.`);
  }
  console.log(`
======================================================================
`);
}
async function runEntropy() {
  const password = args[1];
  if (!password) {
    console.error(`${ANSI.red}\u274C Erro: Senha n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec entropy <senha>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const entropy = calculatePasswordEntropy(password);
  if (isJson) {
    console.log(JSON.stringify(entropy, null, 2));
    process.exit(0);
  }
  printBanner();
  console.log(`\u{1F511} CALCULADORA DE ENTROPIA SHANNON & HASHCAT
`);
  const strengthColor = entropy.strengthCategory === "VERY_STRONG" || entropy.strengthCategory === "STRONG" ? ANSI.green : entropy.strengthCategory === "FAIR" ? ANSI.yellow : ANSI.red;
  console.log(`\u2022 Tamanho da Senha:    ${entropy.length} caracteres`);
  console.log(`\u2022 Bits de Entropia:    ${ANSI.bold}${entropy.entropyBits} bits${ANSI.reset}`);
  console.log(`\u2022 Charset Estimado:    ${entropy.charsetSize} s\xEDmbolos`);
  console.log(`\u2022 N\xEDvel de For\xE7a:      ${strengthColor}${ANSI.bold}${entropy.strengthCategory}${ANSI.reset}`);
  console.log(`\u2022 Tempo Estimado GPU:  ${ANSI.bold}${entropy.estimatedCrackTimeGpuCluster}${ANSI.reset} (Cluster RTX 4090 / Hashcat)`);
  console.log(`
======================================================================
`);
}
async function runWaf() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec waf <url>${ANSI.reset}`);
    process.exit(1);
  }
  const config = loadObsidianConfig();
  const scope = validateTargetScope(targetUrl, config);
  if (!scope.allowed) {
    printBanner();
    console.error(`${ANSI.red}\u{1F6AB} [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
    console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}
`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F6E1}\uFE0F  Inspecionando assinaturas de WAF e Firewall de Borda para ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await detectWaf(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  const statusColor = report.detected ? ANSI.green : ANSI.yellow;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} DETECTOR DE WAF // WEB APPLICATION FIREWALL (WAFW00F ENGINE)`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo:                ${report.targetUrl}`);
  console.log(`\u2022 Status do WAF:       ${statusColor}${ANSI.bold}${report.detected ? "ATIVO & DETECTADO" : "N\xC3O DETECTADO"}${ANSI.reset}`);
  console.log(`\u2022 Firewall / Shield:   ${ANSI.bold}${report.wafName}${ANSI.reset}`);
  console.log(`\u2022 Fabricante / Vendor: ${report.vendor}`);
  console.log(`\u2022 N\xEDvel de Confian\xE7a:  ${report.confidence}`);
  console.log(`\u2022 Fase de Detec\xE7\xE3o:    ${report.detectionPhase}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`\u2022 Recomenda\xE7\xE3o:        ${report.recommendation}`);
  console.log(`======================================================================
`);
  if (report.indicators.length > 0) {
    console.log(`\u{1F50D} EVID\xCANCIAS E ASSINATURAS IDENTIFICADAS:`);
    report.indicators.forEach((ind) => console.log(`  ${ANSI.cyan}\u2022${ANSI.reset} ${ind}`));
  }
  console.log(`
======================================================================
`);
}
async function runPorts() {
  const host = args[1];
  if (!host) {
    console.error(`${ANSI.red}\u274C Erro: Host / IP alvo n\xE3o especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec ports <host>${ANSI.reset}`);
    process.exit(1);
  }
  const config = loadObsidianConfig();
  const scope = validateTargetScope(host, config);
  if (!scope.allowed) {
    printBanner();
    console.error(`${ANSI.red}\u{1F6AB} [SCOPE GUARD]: Auditoria de portas bloqueada!${ANSI.reset}`);
    console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}
`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F6AA} [Nmap Engine] Auditando 12 portas cr\xEDticas e ca\xE7ando bancos de dados em ${ANSI.bold}${host}${ANSI.reset}...
`);
  const report = await scanHostCriticalPorts(host);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallVerdict === "CRITICAL" ? 1 : 0);
  }
  const verdictColor = report.overallVerdict === "SECURE" ? ANSI.green : report.overallVerdict === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} RELAT\xD3RIO DE AUDITORIA DE PORTAS CR\xCDTICAS & SERVI\xC7OS EXPOSTOS`);
  console.log(`======================================================================`);
  console.log(`\u2022 Host Auditado:       ${report.targetHost}`);
  console.log(`\u2022 Portas Analisadas:   ${report.totalScanned}`);
  console.log(`\u2022 Portas Abertas:      ${report.openCount > 0 ? ANSI.yellow + report.openCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`\u2022 Exposi\xE7\xE3o Cr\xEDtica:   ${report.criticalExposuresCount > 0 ? ANSI.red + report.criticalExposuresCount + " (RISCO GRAVE)" : ANSI.green + "0 (LIMPO)"}${ANSI.reset}`);
  console.log(`\u2022 Diagn\xF3stico:         ${verdictColor}${ANSI.bold}${report.overallVerdict}${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  console.log(`\u{1F4CB} RESULTADO POR PORTA AUDITADA:`);
  report.results.forEach((r) => {
    const statusBadge = r.status === "OPEN" ? ANSI.red + "[OPEN]" : r.status === "FILTERED" ? ANSI.green + "[FILTERED]" : ANSI.gray + "[CLOSED]";
    console.log(`  ${statusBadge}${ANSI.reset} ${ANSI.bold}Porta ${r.port}/TCP${ANSI.reset} - ${r.service} (${r.responseTimeMs}ms)`);
    if (r.status === "OPEN" && (r.riskLevel === "CRITICAL" || r.riskLevel === "HIGH")) {
      console.log(`      \u26A0\uFE0F  ${ANSI.red}${ANSI.bold}RISCO:${ANSI.reset} ${r.exposureRisk}`);
      console.log(`      \u{1F4A1} ${ANSI.cyan}Mitiga\xE7\xE3o:${ANSI.reset} ${r.mitigation}`);
    }
  });
  console.log(`
======================================================================
`);
  process.exit(report.overallVerdict === "CRITICAL" ? 1 : 0);
}
async function runSsl() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec ssl <url>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F512} Inspecionando certificado SSL/TLS e criptografia para ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await analyzeSslTls(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.valid ? 0 : 1);
  }
  const gradeColor = report.grade === "A+" || report.grade === "A" ? ANSI.green : report.grade === "B" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} RELAT\xD3RIO DE AUDITORIA SSL/TLS (SSL LABS ENGINE)`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo Auditado:       ${report.targetUrl}`);
  console.log(`\u2022 Emissor (CA):        ${report.issuer}`);
  console.log(`\u2022 Sujeito (CN):        ${report.subject}`);
  console.log(`\u2022 Protocolo:           ${report.protocol}`);
  console.log(`\u2022 Algoritmo de Ass.:   ${report.signatureAlgorithm}`);
  console.log(`\u2022 Nota TLS:            ${gradeColor}${ANSI.bold}GRADE ${report.grade}${ANSI.reset}`);
  console.log(`\u2022 Status:              ${report.valid ? ANSI.green + "V\xC1LIDO & CONFI\xC1VEL" : ANSI.red + "INV\xC1LIDO / RISCO"}${ANSI.reset}`);
  console.log(`\u2022 Expira\xE7\xE3o:           ${report.validTo} (${report.daysUntilExpiry} dias restantes)`);
  console.log(`\u2022 Auto-assinado:       ${report.isSelfSigned ? ANSI.red + "SIM (RISCO)" : ANSI.green + "N\xC3O"}${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  if (report.subjectAltNames.length > 0) {
    console.log(`\u{1F310} NOMES ALTERNATIVOS DO SUJEITO (SAN):`);
    report.subjectAltNames.slice(0, 10).forEach((san) => console.log(`  ${ANSI.cyan}\u2022${ANSI.reset} ${san}`));
    if (report.subjectAltNames.length > 10) console.log(`  ... e mais ${report.subjectAltNames.length - 10} dom\xEDnios.`);
    console.log("");
  }
  if (report.issues.length > 0) {
    console.log(`\u26A0\uFE0F  VULNERABILIDADES & ALERTAS DE CERTIFICADO:`);
    report.issues.forEach((iss) => {
      const color = iss.severity === "CRITICAL" ? ANSI.red : iss.severity === "HIGH" ? ANSI.yellow : ANSI.gray;
      console.log(`  ${color}[${iss.severity}] ${iss.message}${ANSI.reset}`);
    });
    console.log(`
======================================================================
`);
  }
  process.exit(report.valid ? 0 : 1);
}
async function runTech() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec tech <url>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F9EC} Identificando stack de tecnologias (Wappalyzer Engine) em ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await fingerprintTechStack(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} SUPERF\xCDCIE DE TECNOLOGIAS & FINGERPRINTING DE STACK`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo Auditado:       ${report.targetUrl}`);
  console.log(`\u2022 Servidor Web:        ${report.serverHeader}`);
  console.log(`\u2022 X-Powered-By:        ${report.poweredBy}`);
  console.log(`\u2022 Total Identificado:  ${ANSI.bold}${report.totalDetected} tecnologias${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  if (report.detections.length > 0) {
    console.log(`\u{1F6E0}\uFE0F  TECNOLOGIAS DETECTADAS:`);
    report.detections.forEach((t) => {
      console.log(`  ${ANSI.cyan}\u2022${ANSI.reset} ${ANSI.bold}${t.name}${ANSI.reset} [${t.category}] (Confian\xE7a: ${t.confidence})`);
      console.log(`      \u{1F50D} Evid\xEAncia: ${ANSI.gray}${t.evidence}${ANSI.reset}`);
    });
  } else {
    console.log(`  Nenhuma tecnologia identific\xE1vel explicitamente (Ofusca\xE7\xE3o ativa).`);
  }
  console.log(`
======================================================================
`);
}
async function runMethods() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec methods <url>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F4E1} Enumerando m\xE9todos HTTP e testando verbos perigosos em ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await analyzeHttpMethods(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
  }
  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} RELAT\xD3RIO DE ENUMERA\xC7\xC3O DE M\xC9TODOS HTTP`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo:                ${report.targetUrl}`);
  console.log(`\u2022 M\xE9todos Permitidos:  ${ANSI.bold}${report.allowedMethods.join(", ")}${ANSI.reset}`);
  console.log(`\u2022 M\xE9todos Perigosos:   ${report.riskyMethods.length > 0 ? ANSI.red + report.riskyMethods.join(", ") : ANSI.green + "NENHUM EXPOSTO"}${ANSI.reset}`);
  console.log(`\u2022 Diagn\xF3stico Geral:   ${statusColor}${ANSI.bold}${report.overallStatus}${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  console.log(`\u{1F4CB} RESULTADO POR M\xC9TODO:`);
  report.results.forEach((m) => {
    const badge = m.risky ? ANSI.red + "[PERIGO]" : m.allowed ? ANSI.green + "[PERMITIDO]" : ANSI.gray + "[BLOQUEADO]";
    console.log(`  ${badge}${ANSI.reset} ${ANSI.bold}${m.method}${ANSI.reset} (HTTP ${m.statusCode}) \u2014 ${m.description}`);
  });
  console.log(`
======================================================================
`);
  process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
}
async function runRedirects() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec redirects <url>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F500} Ca\xE7ando Open Redirects (OWASP CWE-601) em ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await detectOpenRedirects(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.vulnerableCount > 0 ? 1 : 0);
  }
  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} DETECTOR DE OPEN REDIRECT (OWASP CWE-601)`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo:                ${report.targetUrl}`);
  console.log(`\u2022 Par\xE2metros Testados: ${report.totalTested}`);
  console.log(`\u2022 Vulnerabilidades:    ${report.vulnerableCount > 0 ? ANSI.red + report.vulnerableCount + " VULNER\xC1VEL" : ANSI.green + "0 (SEGURO)"}${ANSI.reset}`);
  console.log(`\u2022 Diagn\xF3stico:         ${statusColor}${ANSI.bold}${report.overallStatus}${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  if (report.results.length > 0) {
    console.log(`\u{1F50D} REDIRECIONAMENTOS IDENTIFICADOS:`);
    report.results.forEach((r) => {
      const color = r.isOpenRedirect ? ANSI.red : ANSI.yellow;
      console.log(`  ${color}\u2022 Par\xE2metro: '${r.parameter}'${ANSI.reset} -> ${r.redirectedTo}`);
    });
  } else {
    console.log(`  Nenhum redirecionamento aberto detectado nos par\xE2metros comuns.`);
  }
  console.log(`
======================================================================
`);
  process.exit(report.vulnerableCount > 0 ? 1 : 0);
}
async function runOrigin() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: Dom\xEDnio ou URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec origin <url|dominio>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`\u{1F50D} Ca\xE7ando vazamentos de IP real e bypass de CDN/WAF em ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  const report = await analyzeOriginLeak(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallStatus === "CRITICAL_BYPASS" ? 1 : 0);
  }
  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`\u{1F4CA} DETECTOR DE ORIGIN BYPASS & VAZAMENTO DE IP REAL`);
  console.log(`======================================================================`);
  console.log(`\u2022 Dom\xEDnio Analisado:    ${report.targetDomain}`);
  console.log(`\u2022 Protegido por CDN:    ${report.isBehindProxyOrCdn ? ANSI.green + "SIM (" + report.proxyProvider + ")" : ANSI.yellow + "N\xC3O (ORIGEM DIRETA)"}${ANSI.reset}`);
  console.log(`\u2022 IPs P\xFAblicos (Borda): ${report.primaryIps.join(", ") || "Nenhum"}`);
  console.log(`\u2022 Risco de Bypass:      ${statusColor}${ANSI.bold}${report.riskScore}/100 [${report.overallStatus}]${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o da An\xE1lise:   ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  console.log(`\u{1F4CB} VETORES INSPECIONADOS:`);
  console.log(`  \u2022 Registros SPF/TXT:    ${report.testedVectors.spfIpsFound.length > 0 ? ANSI.yellow + report.testedVectors.spfIpsFound.join(", ") : ANSI.green + "Nenhum IP exposto"}${ANSI.reset}`);
  console.log(`  \u2022 Servidores de E-mail:  ${report.testedVectors.mxHostsFound.length > 0 ? report.testedVectors.mxHostsFound.join(", ") : "Nenhum MX detectado"}`);
  console.log(`  \u2022 Subdom\xEDnios Testados:  ${report.testedVectors.subdomainsProbed} sondados (${report.testedVectors.subdomainsExposed.length > 0 ? ANSI.red + report.testedVectors.subdomainsExposed.length + " expostos fora da CDN" : ANSI.green + "Todos protegidos"}${ANSI.reset})`);
  if (report.candidateOriginIps.length > 0) {
    console.log(`
\u{1F3AF} CANDIDATOS A IP REAL DE ORIGEM:`);
    report.candidateOriginIps.forEach((c) => {
      const matchBadge = c.virtualHostMatch ? ANSI.red + " [CONFIRMADO: VIRTUAL HOST MATCH]" : "";
      console.log(`  \u2022 IP: ${ANSI.bold}${c.ip}${ANSI.reset} | Vetor: ${c.sourceVector} ${c.discoveredHost ? "(" + c.discoveredHost + ")" : ""}${matchBadge}`);
    });
  }
  if (report.confirmedBypassIps.length > 0) {
    console.log(`
${ANSI.red}\u{1F6A8} ALERTA CR\xCDTICO: Vazamento de origem confirmado!${ANSI.reset}`);
    console.log(`O servidor f\xEDsico responde diretamente em ${report.confirmedBypassIps.join(", ")}, permitindo que atacantes ignorem 100% da Cloudflare/WAF.`);
  }
  console.log(`
\u{1F6E1}\uFE0F  PATCH RECOMENDADO DE FIREWALL (UFW / NGINX):`);
  console.log(`  Para fechar conex\xF5es diretas na porta 443 e aceitar tr\xE1fego apenas da Cloudflare:`);
  console.log(`${ANSI.cyan}  sudo ufw default deny incoming
  sudo ufw allow from 173.245.48.0/20 to any port 443 proto tcp
  sudo ufw deny 443/tcp
  sudo ufw reload${ANSI.reset}`);
  console.log(`
======================================================================
`);
  process.exit(report.overallStatus === "CRITICAL_BYPASS" ? 1 : 0);
}
async function runPhpAndVulns() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}\u274C Erro: URL alvo n\xE3o especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx chimeraguard php <url> [--json]${ANSI.reset} ou ${ANSI.bold}npx chimeraguard vulns <url>${ANSI.reset}`);
    process.exit(1);
  }
  const isJson = args.includes("--json");
  const config = loadObsidianConfig();
  const scope = validateTargetScope(targetUrl, config);
  if (!scope.allowed) {
    if (isJson) {
      console.log(JSON.stringify({ error: scope.reason, errorCode: scope.errorCode }, null, 2));
    } else {
      printBanner();
      console.error(`${ANSI.red}\u{1F6AB} [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
      console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}`);
    }
    process.exit(1);
  }
  if (!isJson) {
    printBanner();
    console.log(`\u{1F418} Auditando vulnerabilidades cr\xEDticas de PHP (CVE-2024-4577 / EOL), CVEs de Servidor e Exposi\xE7\xF5es em ${ANSI.bold}${targetUrl}${ANSI.reset}...
`);
  }
  const report = await analyzePhpAndWebVulnerabilities(targetUrl);
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
  }
  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;
  console.log(`======================================================================`);
  console.log(`${ANSI.bold}\u{1F4CA} AUDITORIA DE VULNERABILIDADES PHP, CVEs & EXPOSI\xC7\xC3O DE BORDA${ANSI.reset}`);
  console.log(`======================================================================`);
  console.log(`\u2022 Alvo Auditado:       ${report.targetUrl}`);
  console.log(`\u2022 Runtime PHP:         ${report.phpDetected ? ANSI.yellow + "DETECTADO" + (report.phpVersion ? ` (v${report.phpVersion})` : " (Vers\xE3o Oculta)") : ANSI.green + "N\xE3o Identificado / Oculto"}${ANSI.reset}`);
  if (report.phpVersion) {
    console.log(`\u2022 Ciclo de Vida PHP:   ${report.phpIsEol ? ANSI.red + "END-OF-LIFE (SEM SUPORTE DE SEGURAN\xC7A)" : ANSI.green + "SUPORTADO"}${ANSI.reset}`);
  }
  console.log(`\u2022 Servidor Web:        ${report.serverBanner}`);
  console.log(`\u2022 X-Powered-By:        ${report.poweredByBanner}`);
  console.log(`\u2022 Sistema Operacional: ${report.osHint}`);
  console.log(`\u2022 security.txt (9116): ${report.securityTxtPresent ? ANSI.green + "PRESENTE" : ANSI.yellow + "AUSENTE"}${ANSI.reset}`);
  console.log(`\u2022 Nota de Blindagem:   ${statusColor}${ANSI.bold}GRADE ${report.securityGrade} (Risco: ${report.riskScore}/100 - ${report.overallStatus})${ANSI.reset}`);
  console.log(`\u2022 Dura\xE7\xE3o:             ${report.durationMs}ms`);
  console.log(`======================================================================
`);
  if (report.cveFindings.length > 0) {
    console.log(`${ANSI.red}${ANSI.bold}\u{1F6A8} VULNERABILIDADES CVE IDENTIFICADAS (${report.cveFindings.length}):${ANSI.reset}`);
    for (const cve of report.cveFindings) {
      const sevColor = cve.severity === "CRITICAL" ? ANSI.red : ANSI.yellow;
      console.log(`  \u2022 ${sevColor}${ANSI.bold}[${cve.severity} // CVSS ${cve.cvssScore}] ${cve.cveId}${ANSI.reset} (${cve.component} ${cve.detectedVersion})`);
      console.log(`    T\xEDtulo:   ${cve.title}`);
      console.log(`    Detalhe:  ${cve.description}`);
      console.log(`    Corre\xE7\xE3o: ${ANSI.cyan}Atualizar para ${cve.patchedVersion}${ANSI.reset} \u2014 ${cve.remediation}
`);
    }
  } else {
    console.log(`${ANSI.green}\u2705 Nenhuma vers\xE3o vulner\xE1vel a CVEs cr\xEDticas (como CVE-2024-4577) foi exposta nos banners.${ANSI.reset}
`);
  }
  if (report.exposureFindings.length > 0) {
    console.log(`${ANSI.yellow}${ANSI.bold}\u{1F50D} EXPOSI\xC7\xD5ES & PONTOS DE HARDENING (${report.exposureFindings.length}):${ANSI.reset}`);
    for (const exp of report.exposureFindings) {
      const sevColor = exp.severity === "CRITICAL" || exp.severity === "HIGH" ? ANSI.red : exp.severity === "MEDIUM" ? ANSI.yellow : ANSI.cyan;
      console.log(`  \u2022 ${sevColor}[${exp.severity}] ${exp.title}${ANSI.reset} (${exp.pathOrHeader})`);
      console.log(`    Evid\xEAncia:  ${exp.evidence}`);
      console.log(`    Remedia\xE7\xE3o: ${exp.remediation}
`);
    }
  }
  console.log(`\u{1F6E1}\uFE0F  DIRETIVAS DE BLINDAGEM RECOMENDADAS (PHP.INI):`);
  console.log(`${ANSI.cyan}${report.remediationConfig.phpIni}${ANSI.reset}
`);
  console.log(`======================================================================
`);
  process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
}
function runInitConfig() {
  printBanner();
  try {
    const configPath = generateDefaultConfigFile();
    console.log(`${ANSI.green}\u2705 Arquivo de configura\xE7\xE3o gerado com sucesso!${ANSI.reset}`);
    console.log(`\u{1F4C1} Local: ${ANSI.bold}${configPath}${ANSI.reset}`);
    console.log(`
Voc\xEA pode configurar seu ${ANSI.cyan}scope.allowlist${ANSI.reset} e prefer\xEAncias de IA no arquivo.
`);
  } catch (err) {
    console.error(`${ANSI.red}\u274C Falha ao gerar arquivo de configura\xE7\xE3o:${ANSI.reset} ${err.message}`);
  }
}
function printHelp() {
  printBanner();
  console.log(`Arsenal de Comandos Dispon\xEDveis:

  ${ANSI.bold}chimeraguard audit <url>${ANSI.reset}           Audita cabe\xE7alhos de borda, cookies, CORS e MITRE attack chain
    Op\xE7\xF5es:
      --min-grade=<A|B|C>         Define a nota m\xEDnima para o Quality Gate de CI/CD (padr\xE3o: B)
      --json                      Retorna o relat\xF3rio completo em formato JSON

  ${ANSI.bold}chimeraguard origin <url>${ANSI.reset}          Ca\xE7a vazamentos de IP real e bypass de Cloudflare/WAF (SPF, MX, Subdom\xEDnios)

  ${ANSI.bold}chimeraguard php <url>${ANSI.reset}             Audita CVEs cr\xEDticas de PHP (CVE-2024-4577, 8926, EOL) e exposi\xE7\xF5es (phpinfo, .env, .git)

  ${ANSI.bold}chimeraguard vulns <url>${ANSI.reset}           Scanner de CVEs de Servidores (Apache, Nginx, OpenSSL, IIS) e Exposi\xE7\xF5es de Borda

  ${ANSI.bold}chimeraguard ssl <url>${ANSI.reset}             Auditoria de certificados SSL/TLS, validade, expira\xE7\xE3o e nota de seguran\xE7a
  
  ${ANSI.bold}chimeraguard tech <url>${ANSI.reset}            Identifica\xE7\xE3o de stack de tecnologias (Wappalyzer: React, Next, Nginx, CDNs)

  ${ANSI.bold}chimeraguard methods <url>${ANSI.reset}         Enumera m\xE9todos HTTP e ca\xE7a verbos perigosos (TRACE/XST, PUT, DELETE)

  ${ANSI.bold}chimeraguard redirects <url>${ANSI.reset}       Detecta falhas de Open Redirect nos par\xE2metros de URL (OWASP CWE-601)

  ${ANSI.bold}chimeraguard waf <url>${ANSI.reset}             Detector de WAF & Firewall de Borda (22+ assinaturas: Cloudflare, AWS, etc)

  ${ANSI.bold}chimeraguard ports <host>${ANSI.reset}          Auditoria de 37 portas TCP cr\xEDticas (Redis, Mongo, MySQL, Postgres, RDP, etc)

  ${ANSI.bold}chimeraguard scan-dir [pasta]${ANSI.reset}      Ca\xE7ador de segredos & SAST local (45+ patterns: AWS, Stripe, Slack, Discord)
  
  ${ANSI.bold}chimeraguard jwt <token>${ANSI.reset}           Auditor de tokens JWT (detecta alg: none, expira\xE7\xE3o e decodifica claims)

  ${ANSI.bold}chimeraguard subdomains <dominio>${ANSI.reset}  Descoberta passiva de subdom\xEDnios via Certificate Transparency

  ${ANSI.bold}chimeraguard dns <dominio>${ANSI.reset}         Inspeciona registros anti-phishing SPF, DMARC e DNSSEC

  ${ANSI.bold}chimeraguard entropy <senha>${ANSI.reset}       Calcula bits de Shannon e tempo de quebra em GPU cluster

  ${ANSI.bold}chimeraguard init-config${ANSI.reset}           Gera o template de configura\xE7\xE3o de escopo e IA

  ${ANSI.bold}chimeraguard help${ANSI.reset}                  Exibe este menu de ajuda
`);
}
switch (command) {
  case "audit":
    runAudit();
    break;
  case "origin":
  case "origin-leak":
  case "origin-bypass":
  case "bypass":
    runOrigin();
    break;
  case "php":
  case "vulns":
  case "cve":
  case "cves":
  case "exposure":
  case "misconfig":
    runPhpAndVulns();
    break;
  case "ssl":
  case "tls":
  case "cert":
    runSsl();
    break;
  case "tech":
  case "stack":
  case "wappalyzer":
    runTech();
    break;
  case "methods":
  case "http-methods":
  case "verbs":
    runMethods();
    break;
  case "redirects":
  case "open-redirect":
  case "redirect":
    runRedirects();
    break;
  case "waf":
  case "firewall":
    runWaf();
    break;
  case "ports":
  case "port-scan":
  case "nmap":
    runPorts();
    break;
  case "dns":
    runDns();
    break;
  case "scan-dir":
  case "scan":
  case "sast":
    runScanDir();
    break;
  case "jwt":
    runJwt();
    break;
  case "subdomains":
  case "subs":
    runSubdomains();
    break;
  case "entropy":
    runEntropy();
    break;
  case "init-config":
  case "init":
  case "config":
    runInitConfig();
    break;
  case "version":
  case "-v":
  case "--version":
    console.log("ChimeraGuard CLI v1.6.0 (formerly ObsidianSec)");
    break;
  default:
    printHelp();
    break;
}

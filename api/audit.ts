import type { VercelRequest, VercelResponse } from "../src/types/index.ts";

// ============================================================================
// BURP SUITE & BLOODHOUND EMBEDDED ANALYZERS (SELF-CONTAINED FOR VERCEL)
// ============================================================================
function analyzeSetCookieHeader(cookieStr: string) {
  const parts = cookieStr.split(";").map((p) => p.trim());
  const [nameValue, ...attributes] = parts;
  const name = nameValue.split("=")[0] || "";
  const attrLower = attributes.map((a) => a.toLowerCase());

  const isHttpOnly = attrLower.some((a) => a === "httponly");
  const isSecure = attrLower.some((a) => a === "secure");
  
  let sameSite: "Strict" | "Lax" | "None" | "Missing" = "Missing";
  const sameSiteAttr = attributes.find((a) => a.toLowerCase().startsWith("samesite="));
  if (sameSiteAttr) {
    const val = sameSiteAttr.split("=")[1]?.trim().toLowerCase();
    if (val === "strict") sameSite = "Strict";
    else if (val === "lax") sameSite = "Lax";
    else if (val === "none") sameSite = "None";
  }

  const issues: string[] = [];
  if (!isHttpOnly) issues.push("Missing 'HttpOnly' flag.");
  if (!isSecure) issues.push("Missing 'Secure' flag.");
  if (sameSite === "Missing" || sameSite === "None") issues.push("Permissive SameSite configuration.");

  let severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED" = "PASSED";
  if (!isHttpOnly && !isSecure) severity = "HIGH";
  else if (!isHttpOnly || !isSecure) severity = "MEDIUM";
  else if (sameSite === "Missing") severity = "LOW";

  return { name, isHttpOnly, isSecure, sameSite, issues, severity };
}

function analyzeCorsHeaders(headers: Headers) {
  const allowOrigin = headers.get("access-control-allow-origin") || undefined;
  const allowCredentials = headers.get("access-control-allow-credentials")?.toLowerCase() === "true";
  const vary = headers.get("vary") || "";

  const issues: string[] = [];
  let hasWildcardWithCredentials = false;

  if (allowOrigin === "*" && allowCredentials) {
    hasWildcardWithCredentials = true;
    issues.push("Critical CORS: 'Access-Control-Allow-Origin: *' combined with 'Credentials: true'.");
  }
  if (allowOrigin === "null") {
    issues.push("Insecure CORS: 'Access-Control-Allow-Origin: null' vulnerable to sandboxed iframes.");
  }
  if (allowOrigin && allowOrigin !== "*" && !vary.toLowerCase().includes("origin")) {
    issues.push("Cache Poisoning Risk: Missing 'Vary: Origin'.");
  }

  let severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED" = "PASSED";
  if (hasWildcardWithCredentials || allowOrigin === "null") severity = "HIGH";
  else if (issues.length > 0) severity = "MEDIUM";

  return { allowOrigin, allowCredentials, hasWildcardWithCredentials, issues, severity };
}

function runBurpHeaderAudit(headers: Headers, rawCookies: string[] = []) {
  const cookies = rawCookies.map(analyzeSetCookieHeader);
  const cors = analyzeCorsHeaders(headers);
  const findingsCount = cookies.filter((c) => c.severity !== "PASSED").length + (cors.severity !== "PASSED" ? 1 : 0);
  return { cookies, cors, findingsCount };
}

function buildAttackChainGraph(targetUrl: string, defenses: {
  hasCsp: boolean;
  hasXFrameOptions: boolean;
  hasHsts: boolean;
  hasNosniff: boolean;
  hasPermissionsPolicy: boolean;
  hasSecureCookies: boolean;
  hasStrictCors: boolean;
  serverVersionExposed: boolean;
}) {
  const nodes: Array<{ id: string; stage: string; title: string; description: string; mitreTechnique: string }> = [];
  const primaryPath: string[] = [];
  const priorities: string[] = [];

  if (defenses.serverVersionExposed) {
    nodes.push({
      id: "node-recon-server",
      stage: "RECON",
      title: "Web Server Version Fingerprinting",
      description: "The 'Server' header exposes exact software and version information.",
      mitreTechnique: "T1592.002",
    });
    primaryPath.push("Version Fingerprinting");
  }

  if (!defenses.hasCsp) {
    nodes.push({
      id: "node-xss-injection",
      stage: "INITIAL_ACCESS",
      title: "Malicious Script Injection (Cross-Site Scripting - XSS)",
      description: "Absence of Content-Security-Policy allows unrestricted script execution.",
      mitreTechnique: "T1189",
    });
    primaryPath.push("Script Injection (XSS)");
    priorities.push("Configure a strict Content-Security-Policy (CSP).");
  }

  if (!defenses.hasCsp && !defenses.hasSecureCookies) {
    nodes.push({
      id: "node-session-hijack",
      stage: "EXECUTION",
      title: "Cookie Exfiltration & Session Hijacking",
      description: "Cookies lacking HttpOnly can be exfiltrated by malicious client-side scripts.",
      mitreTechnique: "T1539",
    });
    primaryPath.push("Session Hijacking");
    priorities.push("Enable the HttpOnly flag on all session cookies.");
  }

  if (!defenses.hasXFrameOptions) {
    nodes.push({
      id: "node-clickjacking",
      stage: "INITIAL_ACCESS",
      title: "UI Redressing & Invisible Action Hijacking (Clickjacking)",
      description: "Authenticated pages can be embedded within transparent external iframes.",
      mitreTechnique: "T1204.001",
    });
    priorities.push("Add 'X-Frame-Options: DENY'.");
  }

  let maxImpactLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "LOW";
  if (nodes.some((n) => n.id === "node-session-hijack")) {
    nodes.push({
      id: "node-account-takeover",
      stage: "IMPACT",
      title: "Full Account Takeover",
      description: "Attacker leverages stolen session credentials to assume victim identity.",
      mitreTechnique: "T1078",
    });
    primaryPath.push("Account Takeover");
    maxImpactLevel = "CRITICAL";
  } else if (nodes.some((n) => n.id === "node-xss-injection") || nodes.some((n) => n.id === "node-clickjacking")) {
    maxImpactLevel = "HIGH";
  } else if (nodes.length > 0) {
    maxImpactLevel = "MEDIUM";
  }

  const riskSummary =
    primaryPath.length > 1
      ? `Attack Chain Detected: ${primaryPath.join(" ➔ ")}`
      : nodes.length > 0
        ? `Risk Surface Identified with ${nodes.length} potential attack vectors.`
        : "Isolated and hardened perimeter: No exploitable attack paths found.";

  return {
    target: targetUrl,
    riskSummary,
    primaryAttackPath: primaryPath,
    nodes,
    maxImpactLevel,
    tacticalDefensePriority: priorities,
  };
}

// ============================================================================
// VALIDAÇÃO DE SEGURANÇA & SSRF SHIELD
// ============================================================================
function validateTargetUrlSafety(targetUrl: string): { safe: boolean; reason?: string } {
  try {
    const parsed = new URL(targetUrl);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { safe: false, reason: "Protocolo não suportado. Utilize HTTP ou HTTPS." };
    }

    const hostname = parsed.hostname.toLowerCase();

    // 1. Bloqueio de IP de Metadados de Nuvem (AWS/GCP/Azure/Oracle/Vercel)
    if (
      hostname === "169.254.169.254" ||
      hostname === "metadata.google.internal" ||
      hostname === "instance-data"
    ) {
      return {
        safe: false,
        reason: "SSRF Shield: Tentativa de acesso a serviços de metadados de nuvem bloqueada.",
      };
    }

    // 2. Bloqueio de Redes Locais e Loopback (RFC 1918 & RFC 6890)
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "::1" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)
    ) {
      return {
        safe: false,
        reason: "SSRF Shield: Access to internal networks and loopback interfaces is blocked for security.",
      };
    }

    return { safe: true };
  } catch (err: any) {
    return { safe: false, reason: `Malformed URL: ${err.message}` };
  }
}

// ============================================================================
// AUDITORIA UNIVERSAL DE CABEÇALHOS E BORDAS
// ============================================================================
async function auditUniversalEndpoint(targetUrl: string) {
  const safety = validateTargetUrlSafety(targetUrl);
  if (!safety.safe) {
    throw new Error(safety.reason);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);

  try {
    const res = await fetch(targetUrl, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "ChimeraGuard-DevSecOps-Auditor/1.0 (+https://chimera-guard.vercel.app)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    clearTimeout(timeoutId);

    const headers = res.headers;
    const serverHeader = headers.get("server") || "";
    const xPoweredBy = headers.get("x-powered-by") || "";

    const cspVal = headers.get("content-security-policy");
    const cspReportOnly = headers.get("content-security-policy-report-only");
    const xfoVal = headers.get("x-frame-options");
    const xctoVal = headers.get("x-content-type-options");
    const permVal = headers.get("permissions-policy");
    const hstsVal = headers.get("strict-transport-security");
    const refVal = headers.get("referrer-policy");
    const coopVal = headers.get("cross-origin-opener-policy");

    // Detectar Servidor / CDN
    let serverDetected = "Unknown / Hidden Proxy";
    const sLower = serverHeader.toLowerCase();
    if (sLower.includes("cloudflare")) serverDetected = "Cloudflare Edge";
    else if (sLower.includes("nginx")) serverDetected = "Nginx Web Server";
    else if (sLower.includes("apache")) serverDetected = "Apache HTTP Server";
    else if (sLower.includes("caddy")) serverDetected = "Caddy Web Server";
    else if (sLower.includes("vercel")) serverDetected = "Vercel Edge Network";
    else if (sLower.includes("netlify")) serverDetected = "Netlify Edge";
    else if (sLower.includes("iis") || sLower.includes("microsoft")) serverDetected = "Microsoft IIS";
    else if (serverHeader) serverDetected = serverHeader;

    // Detectar Framework
    let frameworkDetected: string | undefined;
    const pLower = xPoweredBy.toLowerCase();
    if (pLower.includes("express")) frameworkDetected = "Node.js / Express";
    else if (pLower.includes("next")) frameworkDetected = "Next.js";
    else if (pLower.includes("php")) frameworkDetected = `PHP Runtime (${xPoweredBy})`;
    else if (xPoweredBy) frameworkDetected = xPoweredBy;

    // Snippets de Remediação
    const remediationSnippets = [
      {
        serverType: "Nginx (nginx.conf)",
        snippet: `# =========================================================
# CHIMERAGUARD DEFENSE PATCH // NGINX HARDENING
# =========================================================
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
server_tokens off;`,
      },
      {
        serverType: "Apache (.htaccess)",
        snippet: `# =========================================================
# CHIMERAGUARD DEFENSE PATCH // APACHE HTTP HARDENING
# =========================================================
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header unset X-Powered-By
</IfModule>
ServerSignature Off`,
      },
      {
        serverType: "Node.js (Helmet / Express)",
        snippet: `// =========================================================
// CHIMERAGUARD DEFENSE PATCH // NODE.JS & EXPRESS HELMET
// =========================================================
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));`,
      },
      {
        serverType: "Cloudflare (Transform Rules)",
        snippet: `# =========================================================
# CHIMERAGUARD DEFENSE PATCH // CLOUDFLARE EDGE HEADERS
# HTTP Response Header Modification Rules
# =========================================================
Set Dynamic Header:
- Content-Security-Policy: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
- X-Frame-Options: "DENY"
- X-Content-Type-Options: "nosniff"
- Referrer-Policy: "strict-origin-when-cross-origin"
- Permissions-Policy: "camera=(), microphone=(), geolocation=()"
- Cross-Origin-Opener-Policy: "same-origin"`,
      },
      {
        serverType: "Vercel (vercel.json)",
        snippet: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        { "key": "Cross-Origin-Opener-Policy", "value": "same-origin" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" }
      ]
    }
  ]
}`,
      },
      {
        serverType: "PHP (php.ini // CVE-2026-115560 & Hardening)",
        snippet: `; =========================================================
; CHIMERAGUARD DEFENSE PATCH // PHP HARDENING & CVE-2026-115560
; =========================================================
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
allow_url_include = Off
allow_url_fopen = Off
cgi.force_redirect = 1

; --- MITIGAÇÃO CRÍTICA CVE-2026-115560 & PHP2SHELL ---
session.upload_progress.enabled = Off
session.upload_progress.cleanup = On

session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
session.use_strict_mode = 1
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,show_source,phpinfo`,
      },
    ];

    const rawSetCookies: string[] = [];
    if (typeof (headers as any).getSetCookie === "function") {
      rawSetCookies.push(...(headers as any).getSetCookie());
    } else {
      const sc = headers.get("set-cookie");
      if (sc) rawSetCookies.push(sc);
    }

    const burpInspection = runBurpHeaderAudit(headers, rawSetCookies);

    // ====================================================================
    // ADAPTIVE MULTI-VECTOR TECH FINGERPRINTING & VULNERABILITY BATTERY
    // ====================================================================
    let htmlBody = "";
    try {
      htmlBody = (await res.text()).slice(0, 150000);
    } catch {
      htmlBody = "";
    }

    const combinedBanner = `${serverHeader} ${xPoweredBy}`;
    const cveFindings: Array<{ cveId: string; component: string; version: string; severity: string; title: string; remediation: string }> = [];
    const exposureFindings: Array<{ title: string; severity: string; detail: string }> = [];
    const detectedStack: Array<{ name: string; category: string; version?: string; evidence: string }> = [];
    const adaptiveTestsExecuted: string[] = [
      "HTTP Edge Security Headers & Browser Isolation Matrix",
      "Passive Session Cookie & CORS Policy Inspector (Burp Engine)",
      "MITRE ATT&CK Kill Chain Correlation (BloodHound Engine)",
      "Server & Runtime Banner CVE Matcher (2024–2026 NVD Database)",
    ];

    const compareVer = (v1: string, v2: string) => {
      const a = v1.replace(/[^0-9.]/g, "").split(".").map((n) => parseInt(n, 10) || 0);
      const b = v2.replace(/[^0-9.]/g, "").split(".").map((n) => parseInt(n, 10) || 0);
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        if ((a[i] ?? 0) < (b[i] ?? 0)) return -1;
        if ((a[i] ?? 0) > (b[i] ?? 0)) return 1;
      }
      return 0;
    };

    let phpDetected = false;
    let phpVersion: string | null = null;
    let phpIsEol = false;
    let wordpressDetected = false;
    let wordpressVersion: string | null = null;

    // 1. Detect WordPress (via DOM / Headers / Links)
    const wpGenMatch = htmlBody.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([\d.]+)?["']/i);
    const hasWpPaths = /\/wp-(?:content|includes|json)\//i.test(htmlBody) || (headers.get("link") || "").includes("wp-json");
    if (wpGenMatch || hasWpPaths) {
      wordpressDetected = true;
      phpDetected = true; // WordPress runs on PHP
      wordpressVersion = wpGenMatch?.[1] || null;
      detectedStack.push({
        name: "WordPress CMS",
        category: "CMS",
        version: wordpressVersion || undefined,
        evidence: wpGenMatch ? `Meta generator (WordPress ${wordpressVersion || ""})` : "/wp-content/ & /wp-includes/ assets",
      });
      if (wordpressVersion) {
        exposureFindings.push({
          title: `WordPress Version Disclosed in Meta Generator (${wordpressVersion})`,
          severity: "LOW",
          detail: "Remove the WordPress generator meta tag via 'remove_action(\"wp_head\", \"wp_generator\");' in functions.php.",
        });
      }

      // Extract WordPress Active Plugins and Versions
      const pluginRegex = /\/wp-content\/plugins\/([a-zA-Z0-9_-]+)(?:[^"'\s>]*\?(?:ver=([0-9.]+)))?/gi;
      const foundPlugins = new Map<string, string | undefined>();
      for (const match of htmlBody.matchAll(pluginRegex)) {
        const slug = match[1];
        const ver = match[2];
        if (slug && !foundPlugins.has(slug)) {
          foundPlugins.set(slug, ver);
        }
      }

      for (const [slug, ver] of foundPlugins) {
        detectedStack.push({
          name: `Plugin: ${slug}`,
          category: "WP_PLUGIN",
          version: ver || undefined,
          evidence: ver ? `Asset query ver=${ver}` : "Asset path in /wp-content/plugins/",
        });
      }

      // Extract WordPress Active Theme
      const themeMatch = htmlBody.match(/\/wp-content\/themes\/([a-zA-Z0-9_-]+)\//i);
      if (themeMatch && themeMatch[1]) {
        detectedStack.push({
          name: `Theme: ${themeMatch[1]}`,
          category: "CMS",
          evidence: "Asset path in /wp-content/themes/",
        });
      }

      if (foundPlugins.size > 0) {
        adaptiveTestsExecuted.push(`WordPress Plugin Enumeration (${foundPlugins.size} Active Plugins Fingerprinted)`);
      }

      remediationSnippets.push({
        serverType: "WordPress (functions.php / .htaccess)",
        snippet: `# =========================================================
# CHIMERAGUARD DEFENSE PATCH // WORDPRESS CMS HARDENING
# =========================================================
# 1. Block XML-RPC Brute Force & Pingback Amplification (.htaccess)
<Files xmlrpc.php>
  Require all denied
</Files>

# 2. Disable REST API User Enumeration & Hide WP Version (functions.php)
remove_action('wp_head', 'wp_generator');
add_filter('rest_endpoints', function($endpoints) {
  if (isset($endpoints['/wp/v2/users'])) unset($endpoints['/wp/v2/users']);
  if (isset($endpoints['/wp/v2/users/(?P<id>[\\d]+)'])) unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);
  return $endpoints;
});`,
      });
    }

    // 2. Detect Other Frameworks & Libraries from HTML/Headers
    if (/laravel_session|XSRF-TOKEN/i.test(rawSetCookies.join(" "))) {
      phpDetected = true;
      detectedStack.push({ name: "Laravel Framework", category: "FRAMEWORK", evidence: "Session cookie signature" });
    }
    if (/Drupal\.settings|\/sites\/default\/files/i.test(htmlBody) || headers.get("x-drupal-cache")) {
      phpDetected = true;
      detectedStack.push({ name: "Drupal CMS", category: "CMS", evidence: "Drupal DOM/Header signature" });
    }
    if (/__NEXT_DATA__|\/_next\/static/i.test(htmlBody) || /Next\.js/i.test(xPoweredBy)) {
      detectedStack.push({ name: "Next.js", category: "FRAMEWORK", evidence: "_next/static or X-Powered-By" });
    }
    if (/data-reactroot|react-root|__NEXT_DATA__/i.test(htmlBody)) {
      detectedStack.push({ name: "React", category: "FRONTEND", evidence: "React DOM markers" });
    }
    if (/__VUE__|data-v-[a-f0-9]{6}/i.test(htmlBody)) {
      detectedStack.push({ name: "Vue.js", category: "FRONTEND", evidence: "Vue DOM markers" });
    }
    if (/ng-version=|ng-app/i.test(htmlBody)) {
      detectedStack.push({ name: "Angular", category: "FRONTEND", evidence: "Angular DOM attributes" });
    }
    if (headers.get("cf-ray") || sLower.includes("cloudflare")) {
      detectedStack.push({ name: "Cloudflare WAF/CDN", category: "WAF / CDN", evidence: "cf-ray / server header" });
    }
    if (headers.get("x-azure-ref")) {
      detectedStack.push({ name: "Azure Front Door WAF", category: "WAF / CDN", evidence: "x-azure-ref header" });
    }
    if (headers.get("x-vercel-id") || sLower.includes("vercel")) {
      detectedStack.push({ name: "Vercel Edge Network", category: "CDN", evidence: "x-vercel-id header" });
    }

    // 3. Detect PHP Version & CVEs
    const phpMatch = combinedBanner.match(/PHP\/(\d+\.\d+\.\d+)/i);
    if (phpMatch) {
      phpDetected = true;
      phpVersion = phpMatch[1];
      const parts = phpVersion.split(".").map((n) => parseInt(n, 10) || 0);
      const maj = parts[0] ?? 0;
      const min = parts[1] ?? 0;
      const branch = `${maj}.${min}`;
      phpIsEol = maj < 8 || (maj === 8 && min <= 1);

      detectedStack.push({
        name: "PHP Runtime",
        category: "LANGUAGE",
        version: phpVersion,
        evidence: `X-Powered-By / Server: PHP/${phpVersion}`,
      });

      exposureFindings.push({
        title: `PHP Version Disclosed (PHP/${phpVersion})`,
        severity: "MEDIUM",
        detail: "Set 'expose_php = Off' in php.ini to hide X-Powered-By version banners.",
      });

      if (phpIsEol) {
        exposureFindings.push({
          title: `End-of-Life PHP Runtime (${phpVersion})`,
          severity: "HIGH",
          detail: "This PHP branch no longer receives official security updates. Upgrade to PHP 8.3+ or 8.4+.",
        });
      }

      if (
        maj < 8 ||
        (maj === 8 && min === 0) ||
        (branch === "8.1" && compareVer(phpVersion, "8.1.29") < 0) ||
        (branch === "8.2" && compareVer(phpVersion, "8.2.20") < 0) ||
        (branch === "8.3" && compareVer(phpVersion, "8.3.8") < 0)
      ) {
        cveFindings.push({
          cveId: "CVE-2024-4577",
          component: "PHP-CGI",
          version: phpVersion,
          severity: "CRITICAL (CVSS 9.8)",
          title: "PHP-CGI Argument Injection (Best-Fit Encoding Bypass)",
          remediation: "Upgrade to PHP >= 8.3.14 / >= 8.2.26 and migrate from PHP-CGI to PHP-FPM.",
        });
      }

      if (
        maj < 8 ||
        (maj === 8 && min === 0) ||
        (branch === "8.1" && compareVer(phpVersion, "8.1.30") < 0) ||
        (branch === "8.2" && compareVer(phpVersion, "8.2.24") < 0) ||
        (branch === "8.3" && compareVer(phpVersion, "8.3.12") < 0)
      ) {
        cveFindings.push({
          cveId: "CVE-2024-8926 / CVE-2024-8927",
          component: "PHP-CGI / FastCGI",
          version: phpVersion,
          severity: "CRITICAL (CVSS 9.8)",
          title: "PHP-CGI Protection Bypass & cgi.force_redirect Collision",
          remediation: "Upgrade PHP to >= 8.3.12 / >= 8.2.24 and disable php-cgi in public directories.",
        });
      }
    } else if (phpDetected || rawSetCookies.some((c) => /PHPSESSID/i.test(c)) || /\.php(?:\?|$)/i.test(targetUrl)) {
      phpDetected = true;
      detectedStack.push({
        name: "PHP Runtime",
        category: "LANGUAGE",
        evidence: wordpressDetected ? "Inferred via WordPress CMS" : "Session cookie / route signature (Version Hidden)",
      });
    }

    // 4. Web Server & OS Fingerprinting + CVEs
    const apacheMatch = combinedBanner.match(/Apache\/(\d+\.\d+\.\d+)/i);
    if (apacheMatch) {
      detectedStack.push({ name: "Apache HTTP Server", category: "WEB SERVER", version: apacheMatch[1], evidence: serverHeader });
      if (compareVer(apacheMatch[1], "2.4.62") < 0) {
        cveFindings.push({
          cveId: "CVE-2024-38476 / CVE-2024-40725",
          component: "Apache HTTP Server",
          version: apacheMatch[1],
          severity: "CRITICAL (CVSS 9.1)",
          title: "Apache mod_rewrite SSRF & Source Code Disclosure",
          remediation: "Upgrade Apache to >= 2.4.62 and set 'ServerTokens Prod' in httpd.conf.",
        });
      }
    }

    const nginxMatch = combinedBanner.match(/nginx\/(\d+\.\d+\.\d+)/i);
    if (nginxMatch) {
      detectedStack.push({ name: "Nginx Web Server", category: "WEB SERVER", version: nginxMatch[1], evidence: serverHeader });
      if (compareVer(nginxMatch[1], "1.26.2") < 0) {
        cveFindings.push({
          cveId: "CVE-2024-7347 / CVE-2024-32760",
          component: "Nginx Web Server",
          version: nginxMatch[1],
          severity: "MEDIUM (CVSS 6.5)",
          title: "Nginx HTTP/3 QUIC & MP4 Module Memory Safety",
          remediation: "Upgrade Nginx to >= 1.26.2 and set 'server_tokens off;' in nginx.conf.",
        });
      }
    }

    if (/Ubuntu/i.test(combinedBanner)) {
      detectedStack.push({ name: "Ubuntu Linux", category: "OS", evidence: "Server header OS token" });
    } else if (/Debian/i.test(combinedBanner)) {
      detectedStack.push({ name: "Debian Linux", category: "OS", evidence: "Server header OS token" });
    } else if (/Win64|Win32|Microsoft-IIS/i.test(combinedBanner)) {
      detectedStack.push({ name: "Windows Server", category: "OS", evidence: "Server header OS token" });
    }

    const debugToken = headers.get("x-debug-token") || headers.get("x-debug-token-link");
    if (debugToken) {
      exposureFindings.push({
        title: "Symfony / Laravel Debug Profiler Exposed",
        severity: "HIGH",
        detail: "X-Debug-Token header detected in production response. Set APP_DEBUG=false.",
      });
    }

    // 5. Execute Adaptive Probes Based on Detected Stack (Parallel & Fast)
    const parsedOrigin = new URL(targetUrl).origin;
    const adaptiveProbeTasks: Promise<void>[] = [];

    // Universal Exposure Probes (.env & .git/HEAD)
    adaptiveTestsExecuted.push("Universal Sensitive File Probe (/.env, /.git/HEAD)");
    adaptiveProbeTasks.push(
      (async () => {
        try {
          const gitRes = await fetch(`${parsedOrigin}/.git/HEAD`, {
            method: "GET",
            redirect: "manual",
            signal: AbortSignal.timeout(2200),
          });
          if (gitRes.status === 200) {
            const txt = (await gitRes.text()).slice(0, 200);
            if (/^ref:\s+refs\/heads\//m.test(txt.trim())) {
              exposureFindings.push({
                title: "Exposed Git Repository (/.git/HEAD)",
                severity: "CRITICAL",
                detail: "Public /.git/HEAD allows attackers to reconstruct source code. Deny access to /.git in web server config.",
              });
            }
          }
        } catch {}
      })(),
      (async () => {
        try {
          const envRes = await fetch(`${parsedOrigin}/.env`, {
            method: "GET",
            redirect: "manual",
            signal: AbortSignal.timeout(2200),
          });
          if (envRes.status === 200) {
            const ct = (envRes.headers.get("content-type") || "").toLowerCase();
            const txt = (await envRes.text()).slice(0, 2048);
            if (!ct.includes("text/html") && !txt.trim().startsWith("<") && /(?:APP_KEY|DB_PASSWORD|DATABASE_URL|AWS_ACCESS_KEY_ID)\s*=/i.test(txt)) {
              exposureFindings.push({
                title: "Exposed Environment File (/.env)",
                severity: "CRITICAL",
                detail: "Public /.env file leaks production secrets and database credentials.",
              });
            }
          }
        } catch {}
      })()
    );

    // WordPress-Specific Adaptive Probes
    if (wordpressDetected) {
      adaptiveTestsExecuted.push("WordPress Adaptive Battery: REST API User Enumeration (/wp-json/wp/v2/users) & XML-RPC (/xmlrpc.php)");
      adaptiveProbeTasks.push(
        (async () => {
          try {
            const wpUsersRes = await fetch(`${parsedOrigin}/wp-json/wp/v2/users`, {
              method: "GET",
              redirect: "manual",
              signal: AbortSignal.timeout(2500),
            });
            if (wpUsersRes.status === 200) {
              const txt = (await wpUsersRes.text()).slice(0, 4096);
              if (txt.trim().startsWith("[") && /"slug"\s*:\s*"[^"]+"/.test(txt)) {
                exposureFindings.push({
                  title: "WordPress REST API User Enumeration Exposed (/wp-json/wp/v2/users)",
                  severity: "HIGH",
                  detail: "Unauthenticated visitors can list valid WordPress administrator/author usernames via /wp-json/wp/v2/users.",
                });
              }
            }
          } catch {}
        })(),
        (async () => {
          try {
            const xmlrpcRes = await fetch(`${parsedOrigin}/xmlrpc.php`, {
              method: "GET",
              redirect: "manual",
              signal: AbortSignal.timeout(2500),
            });
            if (xmlrpcRes.status === 405 || xmlrpcRes.status === 200) {
              const txt = (await xmlrpcRes.text()).slice(0, 500);
              if (/XML-RPC server accepts POST requests only/i.test(txt)) {
                exposureFindings.push({
                  title: "WordPress XML-RPC Interface Active (/xmlrpc.php)",
                  severity: "MEDIUM",
                  detail: "xmlrpc.php is enabled and can be abused for brute-force credential stuffing (system.multicall) and pingback SSRF.",
                });
              }
            }
          } catch {}
        })()
      );
    }

    // PHP-Specific Adaptive Probes
    if (phpDetected) {
      adaptiveTestsExecuted.push("PHP Adaptive Battery: Diagnostic Exposure (/phpinfo.php) & Error Leak Check");
      exposureFindings.push({
        title: "PHP Session Zero-Day Advisory (CVE-2026-115560 / PHP2Shell)",
        severity: "HIGH",
        detail:
          "Zero-day session advisory: verify that 'session.upload_progress.enabled = Off' is set in php.ini to prevent unauthenticated session initialization and RCE (CVE-2026-115560).",
      });
      adaptiveProbeTasks.push(
        (async () => {
          try {
            const infoRes = await fetch(`${parsedOrigin}/phpinfo.php`, {
              method: "GET",
              redirect: "manual",
              signal: AbortSignal.timeout(2200),
            });
            if (infoRes.status === 200) {
              const txt = (await infoRes.text()).slice(0, 4096);
              if (txt.includes("<title>phpinfo()</title>") || (txt.includes("PHP Version") && txt.includes("Zend Extension"))) {
                exposureFindings.push({
                  title: "Public phpinfo() Diagnostic Page Exposed (/phpinfo.php)",
                  severity: "CRITICAL",
                  detail: "Remove /phpinfo.php immediately; it exposes environment variables and server paths.",
                });
              }
            }
          } catch {}
        })()
      );
    }

    await Promise.allSettled(adaptiveProbeTasks);

    const vulnInspection = {
      phpDetected,
      phpVersion,
      phpIsEol,
      wordpressDetected,
      wordpressVersion,
      serverBanner: serverHeader || "Hidden (Hardened)",
      poweredByBanner: xPoweredBy || "Hidden (Hardened)",
      detectedStack,
      adaptiveTestsExecuted,
      cves: cveFindings,
      exposures: exposureFindings,
    };

    const attackChain = buildAttackChainGraph(targetUrl, {
      hasCsp: !!cspVal,
      hasXFrameOptions: !!xfoVal,
      hasHsts: !!hstsVal,
      hasNosniff: !!xctoVal,
      hasPermissionsPolicy: !!permVal,
      hasSecureCookies: burpInspection.cookies.length === 0 || burpInspection.cookies.every((c) => c.isHttpOnly && c.isSecure),
      hasStrictCors: burpInspection.cors.severity === "PASSED",
      serverVersionExposed: /\d+\.\d+/.test(serverHeader),
    });

    return {
      targetUrl,
      httpStatus: res.status,
      serverDetected,
      frameworkDetected,
      securityHeaders: {
        csp: {
          present: !!cspVal || !!cspReportOnly,
          value: cspVal || cspReportOnly || undefined,
          isReportOnly: !cspVal && !!cspReportOnly,
        },
        xFrameOptions: { present: !!xfoVal, value: xfoVal || undefined },
        xContentTypeOptions: { present: !!xctoVal, value: xctoVal || undefined },
        permissionsPolicy: { present: !!permVal, value: permVal || undefined },
        hsts: { present: !!hstsVal, value: hstsVal || undefined },
        referrerPolicy: { present: !!refVal, value: refVal || undefined },
        coop: { present: !!coopVal, value: coopVal || undefined },
      },
      burpInspection,
      vulnInspection,
      attackChain,
      remediationSnippets,
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const msg = (err?.message || "").toLowerCase();
    const causeMsg = String(err?.cause?.message || err?.cause?.code || "").toLowerCase();

    if (msg.includes("abort") || msg.includes("timeout")) {
      throw new Error("Connection timeout. The target server took too long to respond.");
    }
    if (msg.includes("fetch failed") || causeMsg.includes("enotfound") || causeMsg.includes("eai_again")) {
      throw new Error("Target address could not be resolved (DNS/Domain not found). Verify that the domain was entered correctly.");
    }
    if (causeMsg.includes("econnrefused")) {
      throw new Error("Connection refused by target server.");
    }
    throw new Error(err?.message || "Failed to connect to target server.");
  }
}

// ============================================================================
// GEMINI 3.7 FLASH & FALLBACK COGNITIVO
// ============================================================================
async function generateAiDiagnosis(auditReport: any, score: number, grade: string, apiKey?: string) {
  const finalApiKey = apiKey || process.env.GEMINI_API_KEY || "";
  const models = ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3-flash-preview", "gemini-3.6-flash"];

  const prompt = `You are CyberBrain from the ChimeraGuard DevSecOps platform. Analyze this target security audit report: ${auditReport.targetUrl}
- Score: ${score}/100 (Grade ${grade})
- Server / Edge: ${auditReport.serverDetected}
- CSP: ${auditReport.securityHeaders.csp.present ? "Present" : "MISSING"}
- X-Frame-Options: ${auditReport.securityHeaders.xFrameOptions.present ? "Present" : "MISSING"}
- X-Content-Type-Options: ${auditReport.securityHeaders.xContentTypeOptions.present ? "Present" : "MISSING"}
- Permissions-Policy: ${auditReport.securityHeaders.permissionsPolicy.present ? "Present" : "MISSING"}
- HSTS: ${auditReport.securityHeaders.hsts.present ? "Present" : "MISSING"}
- COOP: ${auditReport.securityHeaders.coop.present ? "Present" : "MISSING"}

Generate a pedagogical, tactical, and defensive security analysis (3 to 4 paragraphs) in English, highlighting real-world attack vectors and how to apply edge hardening remediation.`;

  if (finalApiKey) {
    const maestroSystemPrompt = `You are the CHIMERAGUARD MASTER ORCHESTRATOR (CyberBrain Maestro), the supreme AI core of the ChimeraGuard DevSecOps squad.
Your mission: provide authoritative, pedagogical, investigative, and tactical technical diagnoses on edge security, HTTP response headers, Zero Trust Architecture (NIST SP 800-207), OWASP Top 10, and data privacy frameworks.
Tone of voice: Tactical, analytical, authoritative, precise, and actionable.`;

    for (const model of models) {
      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${finalApiKey}`;
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: maestroSystemPrompt }] },
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 1000, temperature: 0.2 },
          }),
          signal: AbortSignal.timeout(3000),
        });

        if (resp.ok) {
          const data = await resp.json();
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) return { provider: "Google Gemini AI Core", analysis: text };
        }

        if (resp.status === 503 || resp.status === 429) {
          break; // Fallback instantâneo
        }
      } catch {
        break; // Timeout ou erro de rede: ativa fallback cognitivo
      }
    }
  }

  // Motor Cognitivo Embutido (Offline Fallback Instantâneo em Inglês)
  let fallbackText = `### 🧠 COGNITIVE VERDICT // CHIMERAGUARD DEFENSE CORE\n\n`;
  fallbackText += `Target **${auditReport.targetUrl}** scored **${score}/100 (Grade ${grade})** with infrastructure identified as **${auditReport.serverDetected}**.\n\n`;

  if (score >= 90) {
    fallbackText += `**Verdict:** The environment demonstrates an **Excellent Security Posture**, implementing rigorous isolation headers against Cross-Site Scripting (XSS), Clickjacking, and MIME Sniffing attacks.\n\n`;
  } else if (score >= 60) {
    fallbackText += `**Verdict:** The environment maintains a **Moderate Security Posture**, but leaves key attack surfaces exposed that could facilitate Clickjacking or malicious script execution.\n\n`;
  } else {
    fallbackText += `**Verdict:** The environment is in a **Critical Vulnerability State**, lacking essential perimeter isolation policies and allowing unauthorized framing and browser policy bypasses.\n\n`;
  }

  fallbackText += `**Immediate Recommendation:** Apply the response header remediation patches provided below to your proxy/CDN layer to elevate your rating to **A+ (100/100)** immediately.`;

  return { provider: "ChimeraGuard Cognitive Core", analysis: fallbackText };
}

// ============================================================================
// CONFIGURAÇÃO DA SERVERLESS FUNCTION (VERCEL EDGE / NODE RUNTIME)
// ============================================================================
export const config = {
  maxDuration: 15,
};

// ============================================================================
// HANDLER PRINCIPAL DA SERVERLESS FUNCTION
// ============================================================================
export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed. Use POST." });
    return;
  }

  try {
    const rawBody = req.body;
    const body = typeof rawBody === "string" ? JSON.parse(rawBody || "{}") : rawBody || {};
    const { url, acceptedTerms, apiKey } = body;

    if (!acceptedTerms) {
      res.status(403).json({
        error: "Acceptance of Terms of Use and Disclaimer is required to proceed.",
      });
      return;
    }
    let targetUrl = typeof url === "string" ? url.trim() : "";
    if (!targetUrl) {
      res.status(400).json({
        error: "Invalid URL. Please provide a domain or web address for probing.",
      });
      return;
    }

    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = `https://${targetUrl}`;
    }

    // 1. Auditoria de Rede e Cabeçalhos
    const auditReport = await auditUniversalEndpoint(targetUrl);

    // 2. Cálculo Pedagógico da Pontuação
    const earnedItems: Array<{ control: string; points: number; explanation: string; lesson: string }> = [];
    const missedItems: Array<{ control: string; lostPoints: number; risk: string; lesson: string }> = [];

    const h = auditReport.securityHeaders;

    if (h.csp.present) {
      earnedItems.push({
        control: "Content-Security-Policy (CSP)",
        points: 30,
        explanation: "Active directive restricting authorized script and resource execution origins.",
        lesson: "Mitigates devastating Cross-Site Scripting (XSS) and malicious data injection attacks.",
      });
    } else {
      missedItems.push({
        control: "Content-Security-Policy (CSP)",
        lostPoints: 30,
        risk: "Open attack surface for script injection (XSS) and unauthorized iframe embedding.",
        lesson: "Define 'Content-Security-Policy: default-src 'self'' to block unvetted external scripts.",
      });
    }

    if (h.xFrameOptions.present) {
      earnedItems.push({
        control: "X-Frame-Options",
        points: 20,
        explanation: `Active protection configured with value '${h.xFrameOptions.value}'.`,
        lesson: "Prevents phishing pages from embedding your application inside invisible iframes.",
      });
    } else {
      missedItems.push({
        control: "X-Frame-Options",
        lostPoints: 20,
        risk: "Severe risk of Clickjacking / UI Redressing attacks.",
        lesson: "Configure 'X-Frame-Options: DENY' or use CSP 'frame-ancestors 'none''.",
      });
    }

    if (h.xContentTypeOptions.present) {
      earnedItems.push({
        control: "X-Content-Type-Options",
        points: 15,
        explanation: "Active 'nosniff' protection against MIME-type confusion attacks.",
        lesson: "Prevents browsers from executing user-uploaded images or text files as JavaScript.",
      });
    } else {
      missedItems.push({
        control: "X-Content-Type-Options",
        lostPoints: 15,
        risk: "Vulnerable to MIME-Sniffing and disguised polyglot file uploads.",
        lesson: "Add 'X-Content-Type-Options: nosniff' to HTTP response headers.",
      });
    }

    if (h.hsts.present) {
      earnedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        points: 15,
        explanation: "Cryptographic HTTPS enforcement enabled across all connections.",
        lesson: "Prevents SSL-strip downgrade attacks and interception on public Wi-Fi networks.",
      });
    } else {
      missedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        lostPoints: 15,
        risk: "Vulnerable to Man-in-the-Middle (MitM) attacks via plaintext HTTP downgrade.",
        lesson: "Enable 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'.",
      });
    }

    if (h.permissionsPolicy.present) {
      earnedItems.push({
        control: "Permissions-Policy",
        points: 10,
        explanation: "Hardware API restriction and device isolation active.",
        lesson: "Blocks third-party scripts from accessing microphone, camera, and geolocation.",
      });
    } else {
      missedItems.push({
        control: "Permissions-Policy",
        lostPoints: 10,
        risk: "Malicious scripts can attempt to invoke device sensors, camera, or payment APIs.",
        lesson: "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
      });
    }

    if (h.coop.present) {
      earnedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        points: 5,
        explanation: "Active window context isolation ('same-origin').",
        lesson: "Protects browser process memory against side-channel attacks like Spectre.",
      });
    } else {
      missedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        lostPoints: 5,
        risk: "Opened windows may retain context references accessible to malicious origins.",
        lesson: "Add 'Cross-Origin-Opener-Policy: same-origin'.",
      });
    }

    if (h.referrerPolicy.present) {
      earnedItems.push({
        control: "Referrer-Policy",
        points: 5,
        explanation: "Active metadata isolation on cross-origin navigation.",
        lesson: "Prevents sensitive internal URL paths from leaking to third-party domains.",
      });
    } else {
      missedItems.push({
        control: "Referrer-Policy",
        lostPoints: 5,
        risk: "Sensitive query parameters in URLs can leak via the Referer header on external links.",
        lesson: "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
      });
    }

    const totalScore = earnedItems.reduce((acc, curr) => acc + curr.points, 0);

    let grade = "F";
    let gradeVerdict = "Critical Security Posture: Multiple essential perimeter defenses are missing.";
    if (totalScore >= 95) {
      grade = "A+";
      gradeVerdict = "Excellent! Edge Fortress: Maximum level of isolation and edge security controls.";
    } else if (totalScore >= 80) {
      grade = "A";
      gradeVerdict = "Strong Perimeter: Most defensive controls are active and safeguarding users.";
    } else if (totalScore >= 60) {
      grade = "B";
      gradeVerdict = "Moderate Posture: Partial controls active. Applying recommended patches is advised.";
    } else if (totalScore >= 40) {
      grade = "C";
      gradeVerdict = "Weak Posture: Significant header deficiencies expose users to exploitation.";
    }

    // 3. Síntese com Inteligência Artificial
    const aiDiagnosis = await generateAiDiagnosis(auditReport, totalScore, grade, apiKey);

    // Retornar JSON completo
    res.status(200).json({
      url: auditReport.targetUrl,
      httpStatus: auditReport.httpStatus,
      serverDetected: auditReport.serverDetected,
      frameworkDetected: auditReport.frameworkDetected,
      score: totalScore,
      grade,
      gradeVerdict,
      scoreBreakdown: {
        earned: earnedItems,
        missed: missedItems,
        earnedItems,
        missedItems,
        totalEarned: totalScore,
      },
      securityHeaders: auditReport.securityHeaders,
      burpInspection: auditReport.burpInspection,
      vulnInspection: auditReport.vulnInspection,
      attackChain: auditReport.attackChain,
      aiDiagnosis,
      aiAnalysis: {
        providerUsed: aiDiagnosis.provider,
        customAnalysis: aiDiagnosis.analysis,
      },
      remediationSnippets: auditReport.remediationSnippets,
    });
  } catch (err: any) {
    res.status(500).json({
      error: `Error processing security audit: ${err.message || "Unknown error."}`,
    });
  }
}

export interface CveFinding {
  cveId: string;
  component: string;
  detectedVersion: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvssScore: number;
  title: string;
  description: string;
  patchedVersion: string;
  remediation: string;
}

export interface ExposureFinding {
  id: string;
  category:
    | "PHP_HARDENING"
    | "SENSITIVE_FILE"
    | "DEBUG_INTERFACE"
    | "VERSION_DISCLOSURE"
    | "RFC_COMPLIANCE"
    | "DIRECTORY_LISTING";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  pathOrHeader: string;
  title: string;
  evidence: string;
  remediation: string;
}

export interface PhpAndVulnAuditReport {
  targetUrl: string;
  phpDetected: boolean;
  phpVersion: string | null;
  phpIsEol: boolean;
  osHint: "WINDOWS" | "LINUX_UNIX" | "UNKNOWN";
  serverBanner: string;
  poweredByBanner: string;
  cveFindings: CveFinding[];
  exposureFindings: ExposureFinding[];
  securityTxtPresent: boolean;
  riskScore: number; // 0 to 100 (higher = more risk)
  securityGrade: "A+" | "A" | "B" | "C" | "D" | "F";
  overallStatus: "SECURE" | "WARNING" | "VULNERABLE" | "CRITICAL";
  remediationConfig: {
    phpIni: string;
    nginxConf: string;
    apacheConf: string;
  };
  durationMs: number;
}

/**
 * Compara duas versões semânticas simples (ex: "8.3.7" < "8.3.8")
 * Retorna -1 se v1 < v2, 0 se v1 == v2, 1 se v1 > v2
 */
export function compareSemver(v1: string, v2: string): number {
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

/**
 * Avalia uma versão do PHP contra a base de CVEs críticas (2024-2026) e status EOL
 */
export function evaluatePhpVersionVulnerabilities(version: string): {
  isEol: boolean;
  cves: CveFinding[];
} {
  const cves: CveFinding[] = [];
  const parts = version.replace(/[^0-9.]/g, "").split(".").map((n) => parseInt(n, 10) || 0);
  const major = parts[0] ?? 0;
  const minor = parts[1] ?? 0;
  const branch = `${major}.${minor}`;

  // PHP <= 8.1 é EOL em 2026 (PHP 8.0 EOL em Nov 2023, PHP 8.1 EOL em Dez 2025)
  const isEol = major < 8 || (major === 8 && minor <= 1);

  const checkRange = (minBranch: string, patchedVersion: string): boolean => {
    if (major < 8 || (major === 8 && minor === 0)) return true;
    if (branch === minBranch) {
      return compareSemver(version, patchedVersion) < 0;
    }
    return false;
  };

  // 1. CVE-2024-4577 (PHP-CGI Argument Injection no Windows - CVSS 9.8)
  if (
    major < 8 ||
    (major === 8 && minor === 0) ||
    checkRange("8.1", "8.1.29") ||
    checkRange("8.2", "8.2.20") ||
    checkRange("8.3", "8.3.8")
  ) {
    cves.push({
      cveId: "CVE-2024-4577",
      component: "PHP (PHP-CGI)",
      detectedVersion: version,
      severity: "CRITICAL",
      cvssScore: 9.8,
      title: "PHP-CGI Argument Injection (Best-Fit Character Encoding Bypass)",
      description:
        "Falha crítica onde a conversão de codificação Best-Fit do Windows transforma caracteres especiais (ex: soft-hyphen 0xAD) em hífens reais, permitindo injeção de argumentos no interpretador php-cgi.exe.",
      patchedVersion: "8.1.29 / 8.2.20 / 8.3.8+",
      remediation:
        "Atualizar o PHP imediatamente para >= 8.3.14 ou >= 8.2.26, migrar de PHP-CGI para PHP-FPM e bloquear sequências %AD na borda/WAF.",
    });
  }

  // 2. CVE-2024-8926 & CVE-2024-8927 (PHP-CGI Bypass & cgi.force_redirect Bypass - CVSS 9.8)
  if (
    major < 8 ||
    (major === 8 && minor === 0) ||
    checkRange("8.1", "8.1.30") ||
    checkRange("8.2", "8.2.24") ||
    checkRange("8.3", "8.3.12")
  ) {
    cves.push({
      cveId: "CVE-2024-8926 / CVE-2024-8927",
      component: "PHP (CGI / FastCGI)",
      detectedVersion: version,
      severity: "CRITICAL",
      cvssScore: 9.8,
      title: "PHP-CGI Protection Bypass & cgi.force_redirect Environment Collision",
      description:
        "Bypass da mitigação original da CVE-2024-4577 e colisão de variáveis de ambiente HTTP que permite contornar a diretiva cgi.force_redirect.",
      patchedVersion: "8.1.30 / 8.2.24 / 8.3.12+",
      remediation:
        "Atualizar o PHP para >= 8.3.12 ou >= 8.2.24 e desativar completamente o binário php-cgi em diretórios públicos.",
    });

    cves.push({
      cveId: "CVE-2024-8925",
      component: "PHP Core (Multipart Parser)",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 7.5,
      title: "Erroneous Multipart Form-Data Boundary Parsing",
      description:
        "Erro de parsing em limites de requisições multipart/form-data que pode causar corrupção ou exposição indevida de dados de buffer em uploads.",
      patchedVersion: "8.1.30 / 8.2.24 / 8.3.12+",
      remediation: "Atualizar o runtime PHP para >= 8.3.12 ou >= 8.2.24.",
    });
  }

  // 3. CVE-2024-2756 (__Host- / __Secure- Cookie Prefix Bypass)
  if (
    major < 8 ||
    (major === 8 && minor === 0) ||
    checkRange("8.1", "8.1.28") ||
    checkRange("8.2", "8.2.18") ||
    checkRange("8.3", "8.3.5")
  ) {
    cves.push({
      cveId: "CVE-2024-2756",
      component: "PHP Session / Cookie Parser",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 7.5,
      title: "__Host- and __Secure- Cookie Prefix Integrity Bypass",
      description:
        "A conversão automática de caracteres '[' e '.' para '_' em variáveis superglobais $_COOKIE permite sobrescrever cookies protegidos pelos prefixos __Host- e __Secure-.",
      patchedVersion: "8.1.28 / 8.2.18 / 8.3.5+",
      remediation: "Atualizar o PHP e validar nomes de cookies brutos no cabeçalho HTTP Cookie.",
    });
  }

  // 4. CVE-2024-5458 (FILTER_VALIDATE_URL Bypass)
  if (
    major < 8 ||
    (major === 8 && minor === 0) ||
    checkRange("8.1", "8.1.29") ||
    checkRange("8.2", "8.2.20") ||
    checkRange("8.3", "8.3.8")
  ) {
    cves.push({
      cveId: "CVE-2024-5458",
      component: "PHP Standard Library (filter_var)",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 7.3,
      title: "filter_var(FILTER_VALIDATE_URL) Validation Bypass (SSRF Vector)",
      description:
        "Falha na validação de URLs com sintaxe IPv6/userinfo na função nativa filter_var(), permitindo bypass de filtros anti-SSRF e Open Redirect.",
      patchedVersion: "8.1.29 / 8.2.20 / 8.3.8+",
      remediation: "Atualizar o PHP e utilizar parser estrito de hostnames com allowlist.",
    });
  }

  // 5. CVE-2024-11234 / CVE-2024-11236 (Stream Proxy & LDAP/PDO Overflow)
  if (
    major < 8 ||
    (major === 8 && minor === 0) ||
    checkRange("8.1", "8.1.31") ||
    checkRange("8.2", "8.2.26") ||
    checkRange("8.3", "8.3.14")
  ) {
    cves.push({
      cveId: "CVE-2024-11234 / CVE-2024-11236",
      component: "PHP Streams / LDAP / PDO",
      detectedVersion: version,
      severity: "HIGH",
      cvssScore: 8.1,
      title: "HTTP Stream Proxy Header Injection & Integer Overflow in ldap_escape",
      description:
        "Possibilidade de CRLF injection em conexões de stream via proxy e estouro de inteiro em funções de escape LDAP/PDO.",
      patchedVersion: "8.1.31 / 8.2.26 / 8.3.14+",
      remediation: "Atualizar o PHP para >= 8.3.14, >= 8.2.26 ou migrar para a branch 8.4.x.",
    });
  }

  return { isEol, cves };
}

/**
 * Avalia banners de servidores web (Apache, Nginx, OpenSSL, IIS) contra CVEs conhecidas
 */
export function evaluateServerBannerVulnerabilities(
  serverHeader: string,
  poweredByHeader: string
): CveFinding[] {
  const findings: CveFinding[] = [];
  const combined = `${serverHeader} ${poweredByHeader}`;

  // Apache HTTP Server: ex "Apache/2.4.58 (Win64)"
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
        description:
          "Versões do Apache anteriores à 2.4.62 possuem falhas críticas de revelação de código-fonte de scripts (CVE-2024-40725) e manipulação insegura de respostas de backend/mod_rewrite.",
        patchedVersion: "2.4.62+",
        remediation:
          "Atualizar o Apache HTTP Server para >= 2.4.62 e configurar 'ServerTokens Prod' e 'ServerSignature Off' no httpd.conf.",
      });
    }
  }

  // Nginx: ex "nginx/1.24.0"
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
        description:
          "Versões anteriores ao Nginx 1.26.2 / 1.27.1 possuem vulnerabilidades de leitura/escrita de memória no módulo ngx_http_mp4_module e no processamento HTTP/3 QUIC.",
        patchedVersion: "1.26.2+ / 1.27.1+",
        remediation: "Atualizar o Nginx para >= 1.26.2 e adicionar 'server_tokens off;' no bloco http do nginx.conf.",
      });
    }
  }

  // OpenSSL no banner: ex "OpenSSL/1.1.1t" ou "OpenSSL/3.0.10"
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
        title: "OpenSSL 1.1.1 End-of-Life (Sem Suporte de Segurança)",
        description:
          "A série OpenSSL 1.1.1 atingiu o fim de vida útil (EOL) em setembro de 2023 e não recebe correções públicas para novas vulnerabilidades criptográficas.",
        patchedVersion: "3.0.15+ / 3.2.3+ / 3.3.2+",
        remediation: "Migrar a biblioteca TLS do servidor para OpenSSL 3.x atualizado.",
      });
    } else if (ver.startsWith("3.0.") && compareSemver(ver, "3.0.15") < 0) {
      findings.push({
        cveId: "CVE-2024-6119 / CVE-2024-5535",
        component: "OpenSSL 3.0",
        detectedVersion: ver,
        severity: "HIGH",
        cvssScore: 7.5,
        title: "OpenSSL 3.0 Certificate Name Check & SSL_select_next_proto Buffer Overread",
        description:
          "Vulnerabilidade na validação de certificados X.509 e leitura fora dos limites em negociações ALPN/NPN em versões OpenSSL < 3.0.15.",
        patchedVersion: "3.0.15+",
        remediation: "Atualizar os pacotes libssl/openssl do sistema operacional para >= 3.0.15.",
      });
    }
  }

  // Microsoft IIS legado (< 10.0)
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
        description:
          `O servidor expõe Microsoft-IIS/${ver}, associado ao Windows Server 2008 R2 / 2012, cujo ciclo de suporte estendido foi encerrado.`,
        patchedVersion: "IIS 10.0+ (Windows Server 2019/2022/2025)",
        remediation: "Migrar para Windows Server suportado e remover cabeçalhos Server e X-Powered-By no web.config.",
      });
    }
  }

  return findings;
}

interface ProbeRouteSpec {
  path: string;
  id: string;
  category: ExposureFinding["category"];
  severity: ExposureFinding["severity"];
  title: string;
  remediation: string;
  validateMatch: (status: number, contentType: string, body: string) => string | null;
}

const SAFE_EXPOSURE_PROBES: ProbeRouteSpec[] = [
  {
    path: "/phpinfo.php",
    id: "PHPINFO_EXPOSED",
    category: "PHP_HARDENING",
    severity: "CRITICAL",
    title: "Página de Diagnóstico phpinfo() Exposta Publicamente",
    remediation: "Remover imediatamente o arquivo /phpinfo.php do servidor de produção.",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && (body.includes("<title>phpinfo()</title>") || (body.includes("PHP Version") && body.includes("Zend Extension")))) {
        return "Página phpinfo() ativa revelando variáveis de ambiente, extensões e caminhos internos.";
      }
      return null;
    },
  },
  {
    path: "/info.php",
    id: "INFO_PHP_EXPOSED",
    category: "PHP_HARDENING",
    severity: "CRITICAL",
    title: "Script /info.php Exposto com Diagnóstico do Servidor",
    remediation: "Excluir /info.php do diretório público (document_root).",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && (body.includes("<title>phpinfo()</title>") || (body.includes("PHP Version") && body.includes("Configuration File (php.ini) Path")))) {
        return "Script /info.php público contendo informações completas do ambiente PHP.";
      }
      return null;
    },
  },
  {
    path: "/.user.ini",
    id: "PHP_USER_INI_EXPOSED",
    category: "PHP_HARDENING",
    severity: "HIGH",
    title: "Arquivo de Configuração PHP (/.user.ini) Acessível",
    remediation: "Bloquear acesso a arquivos .user.ini e .ini no Nginx/Apache.",
    validateMatch: (status, ct, body) => {
      if (
        status === 200 &&
        !ct.includes("text/html") &&
        !body.trim().startsWith("<!DOCTYPE") &&
        !body.trim().startsWith("<html") &&
        /(?:display_errors|memory_limit|upload_max_filesize|open_basedir|auto_prepend_file)\s*=/i.test(body)
      ) {
        return "Arquivo /.user.ini público expondo diretivas internas do interpretador PHP.";
      }
      return null;
    },
  },
  {
    path: "/.git/HEAD",
    id: "GIT_REPOSITORY_EXPOSED",
    category: "SENSITIVE_FILE",
    severity: "CRITICAL",
    title: "Repositório Git (/.git/HEAD) Exposto em Produção",
    remediation: "Bloquear acesso ao diretório /.git no servidor web (location ~ /\\.git { deny all; }).",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && /^ref:\s+refs\/heads\//m.test(body.trim())) {
        return `Metadados do Git acessíveis publicamente (${body.trim().slice(0, 50)}). Permite reconstrução do código-fonte.`;
      }
      return null;
    },
  },
  {
    path: "/.env",
    id: "DOTENV_FILE_EXPOSED",
    category: "SENSITIVE_FILE",
    severity: "CRITICAL",
    title: "Arquivo de Variáveis de Ambiente (/.env) Exposto",
    remediation: "Mover o arquivo .env para fora da pasta pública e bloquear arquivos ocultos (dot-files).",
    validateMatch: (status, ct, body) => {
      if (
        status === 200 &&
        !ct.includes("text/html") &&
        !body.trim().startsWith("<") &&
        /(?:APP_ENV|APP_KEY|DB_HOST|DB_PASSWORD|DATABASE_URL|AWS_ACCESS_KEY_ID|JWT_SECRET|STRIPE_SECRET)\s*=/i.test(body)
      ) {
        return "Arquivo /.env público contendo chaves de configuração e credenciais de banco/API.";
      }
      return null;
    },
  },
  {
    path: "/actuator/health",
    id: "SPRING_ACTUATOR_EXPOSED",
    category: "DEBUG_INTERFACE",
    severity: "MEDIUM",
    title: "Endpoint Spring Boot Actuator (/actuator/health) Exposto",
    remediation: "Restringir management.endpoints.web.exposure.include no application.properties e exigir autenticação.",
    validateMatch: (status, ct, body) => {
      if (
        status === 200 &&
        (ct.includes("application/json") || ct.includes("spring-boot.actuator")) &&
        /"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"/i.test(body)
      ) {
        return "Spring Boot Actuator respondendo publicamente sem autenticação.";
      }
      return null;
    },
  },
  {
    path: "/openapi.json",
    id: "OPENAPI_SCHEMA_EXPOSED",
    category: "DEBUG_INTERFACE",
    severity: "LOW",
    title: "Especificação de API (/openapi.json) Pública em Produção",
    remediation: "Restringir a documentação Swagger/OpenAPI a redes internas ou exigir autenticação em produção.",
    validateMatch: (status, ct, body) => {
      if (status === 200 && ct.includes("json") && /"(?:openapi|swagger)"\s*:\s*"[23]\./.test(body)) {
        return "Esquema completo de rotas OpenAPI/Swagger exposto publicamente.";
      }
      return null;
    },
  },
  {
    path: "/server-status",
    id: "APACHE_SERVER_STATUS_EXPOSED",
    category: "DEBUG_INTERFACE",
    severity: "HIGH",
    title: "Módulo Apache mod_status (/server-status) Público",
    remediation: "Restringir o Location /server-status no Apache apenas para localhost (Require local).",
    validateMatch: (status, _ct, body) => {
      if (status === 200 && body.includes("Apache Server Status for") && body.includes("Server uptime:")) {
        return "Painel Apache mod_status público revelando IPs de clientes e URLs internas em processamento.";
      }
      return null;
    },
  },
  {
    path: "/wp-json/wp/v2/users",
    id: "WORDPRESS_REST_USERS_EXPOSED",
    category: "PHP_HARDENING",
    severity: "MEDIUM",
    title: "WordPress REST API (/wp-json/wp/v2/users) Expondo Lista de Usuários",
    remediation: "Restringir o endpoint /wp-json/wp/v2/users via filtro rest_endpoints no functions.php ou regra de WAF.",
    validateMatch: (status, ct, body) => {
      if (status === 200 && ct.includes("json") && body.includes('"slug":') && body.includes('"id":')) {
        return "Endpoint REST API /wp-json/wp/v2/users público permitindo enumeração de logins de administradores/autores.";
      }
      return null;
    },
  },
];

/**
 * Executa a auditoria defensiva de vulnerabilidades PHP, CVEs de Servidores/Frameworks
 * e Exposições Críticas de Configuração.
 */
export async function analyzePhpAndWebVulnerabilities(
  targetUrl: string
): Promise<PhpAndVulnAuditReport> {
  const start = Date.now();
  const normalizedUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
  const parsedUrl = new URL(normalizedUrl);
  const baseOrigin = parsedUrl.origin;

  let phpDetected = false;
  let phpVersion: string | null = null;
  let phpIsEol = false;
  let osHint: PhpAndVulnAuditReport["osHint"] = "UNKNOWN";
  let serverBanner = "Hidden / Not Disclosed";
  let poweredByBanner = "Hidden / Not Disclosed";
  let securityTxtPresent = false;

  const cveFindings: CveFinding[] = [];
  const exposureFindings: ExposureFinding[] = [];

  try {
    const mainRes = await fetch(normalizedUrl, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "ChimeraGuard-SecurityAuditor/1.5 (+https://chimera-guard.vercel.app)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: AbortSignal.timeout(5000),
    });

    const serverHdr = mainRes.headers.get("server") || "";
    const poweredByHdr = mainRes.headers.get("x-powered-by") || "";
    const setCookieHdr = mainRes.headers.get("set-cookie") || "";
    const debugTokenHdr = mainRes.headers.get("x-debug-token") || mainRes.headers.get("x-debug-token-link") || "";
    const aspnetVerHdr = mainRes.headers.get("x-aspnet-version") || "";

    if (serverHdr) serverBanner = serverHdr;
    if (poweredByHdr) poweredByBanner = poweredByHdr;

    const combinedHeaders = `${serverHdr} ${poweredByHdr}`;

    // Detect OS Hint
    if (/(?:Win32|Win64|Windows|Microsoft-IIS)/i.test(combinedHeaders)) {
      osHint = "WINDOWS";
    } else if (/(?:Ubuntu|Debian|CentOS|Red Hat|Fedora|Unix|Alpine|FreeBSD)/i.test(combinedHeaders)) {
      osHint = "LINUX_UNIX";
    }

    // Detect PHP presence and version
    const phpVerMatch = combinedHeaders.match(/PHP\/(\d+\.\d+\.\d+)/i);
    if (phpVerMatch) {
      phpDetected = true;
      phpVersion = phpVerMatch[1];
      exposureFindings.push({
        id: "PHP_VERSION_EXPOSED",
        category: "PHP_HARDENING",
        severity: "MEDIUM",
        pathOrHeader: `X-Powered-By / Server: PHP/${phpVersion}`,
        title: "Exposição Explícita de Versão do Runtime PHP",
        evidence: `O servidor anuncia 'PHP/${phpVersion}' nos cabeçalhos HTTP, facilitando o mapeamento automatizado de CVEs.`,
        remediation: "Definir 'expose_php = Off' no arquivo php.ini para ocultar o cabeçalho X-Powered-By.",
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
          title: `Versão do PHP em Fim de Vida Útil (End-of-Life: ${phpVersion})`,
          evidence: `A versão PHP ${phpVersion} não recebe mais atualizações oficiais de segurança da PHP Foundation.`,
          remediation: "Planejar atualização imediata do runtime para PHP 8.3.x ou PHP 8.4.x.",
        });
      }
    } else if (/PHPSESSID/i.test(setCookieHdr) || /\.php(?:\?|$)/i.test(normalizedUrl) || /\bPHP\b/i.test(combinedHeaders)) {
      phpDetected = true;
    }

    // Check PHPSESSID cookie security flags if present
    if (/PHPSESSID=/i.test(setCookieHdr)) {
      const hasHttpOnly = /HttpOnly/i.test(setCookieHdr);
      const hasSecure = /Secure/i.test(setCookieHdr);
      if (!hasHttpOnly || !hasSecure) {
        exposureFindings.push({
          id: "PHP_SESSION_COOKIE_INSECURE",
          category: "PHP_HARDENING",
          severity: "HIGH",
          pathOrHeader: "Set-Cookie: PHPSESSID",
          title: "Cookie de Sessão PHPSESSID sem Flags de Blindagem",
          evidence: `O cookie PHPSESSID foi emitido sem ${!hasHttpOnly ? "session.cookie_httponly" : ""} ${!hasSecure ? "session.cookie_secure" : ""}.`.trim(),
          remediation:
            "Configurar 'session.cookie_httponly = 1', 'session.cookie_secure = 1' e 'session.cookie_samesite = Lax' no php.ini.",
        });
      }
    }

    // Evaluate Web Server & OpenSSL Banner CVEs
    const serverCves = evaluateServerBannerVulnerabilities(serverHdr, poweredByHdr);
    cveFindings.push(...serverCves);

    // Check Debug / Framework Headers Disclosure
    if (debugTokenHdr) {
      exposureFindings.push({
        id: "SYMFONY_LARAVEL_PROFILER_EXPOSED",
        category: "DEBUG_INTERFACE",
        severity: "HIGH",
        pathOrHeader: `X-Debug-Token: ${debugTokenHdr}`,
        title: "Profiler de Depuração (Symfony/Laravel) Ativo em Produção",
        evidence: `Cabeçalho X-Debug-Token detectado (${debugTokenHdr}), indicando modo APP_DEBUG ativo.`,
        remediation: "Desativar o modo debug em produção (APP_ENV=prod / APP_DEBUG=false).",
      });
    }

    if (aspnetVerHdr) {
      exposureFindings.push({
        id: "ASPNET_VERSION_EXPOSED",
        category: "VERSION_DISCLOSURE",
        severity: "LOW",
        pathOrHeader: `X-AspNet-Version: ${aspnetVerHdr}`,
        title: "Vazamento de Versão do .NET Framework",
        evidence: `O cabeçalho X-AspNet-Version revela a versão exata da stack (${aspnetVerHdr}).`,
        remediation: "Adicionar <httpRuntime enableVersionHeader=\"false\" /> no arquivo web.config.",
      });
    }

    if (/Next\.js/i.test(poweredByHdr)) {
      exposureFindings.push({
        id: "NEXTJS_POWERED_BY_EXPOSED",
        category: "VERSION_DISCLOSURE",
        severity: "LOW",
        pathOrHeader: `X-Powered-By: ${poweredByHdr}`,
        title: "Cabeçalho X-Powered-By: Next.js Exposto",
        evidence:
          "A aplicação anuncia explicitamente o uso de Next.js. Certifique-se de estar em versão >= 14.2.25 ou >= 15.2.3 (mitigação contra CVE-2025-29927) e remover o cabeçalho.",
        remediation: "Configurar 'poweredByHeader: false' no arquivo next.config.js e bloquear o cabeçalho x-middleware-subrequest no proxy reverso.",
      });
    }

    // Inspect Main Body for WordPress / CMS / PHP Error Leaks or Directory Listing
    const mainBody = await mainRes.text();
    if (/\/wp-content\/|\/wp-includes\/|wp-json|<meta[^>]+name=["']generator["'][^>]+content=["']WordPress/i.test(mainBody)) {
      phpDetected = true;
    }
    if (/(?:<b>Fatal error<\/b>:|<b>Warning<\/b>:|<b>Parse error<\/b>:).*? in <b>.*?(?:\.php)<\/b> on line <b>\d+<\/b>/i.test(mainBody)) {
      phpDetected = true;
      exposureFindings.push({
        id: "PHP_DISPLAY_ERRORS_ENABLED",
        category: "PHP_HARDENING",
        severity: "HIGH",
        pathOrHeader: normalizedUrl,
        title: "Diretiva display_errors Ativa (Vazamento de Caminhos e Stack Trace PHP)",
        evidence: "A resposta HTML contém mensagens nativas de erro do PHP revelando caminhos internos do sistema de arquivos.",
        remediation: "Definir 'display_errors = Off' e 'log_errors = On' no arquivo php.ini de produção.",
      });
    }

    if (/<title>Index of \//i.test(mainBody)) {
      exposureFindings.push({
        id: "DIRECTORY_LISTING_ENABLED",
        category: "DIRECTORY_LISTING",
        severity: "HIGH",
        pathOrHeader: normalizedUrl,
        title: "Listagem Automática de Diretórios (Directory Indexing) Ativa",
        evidence: "O servidor retorna '<title>Index of /', permitindo navegar pelos arquivos internos.",
        remediation: "Desativar autoindex ('Options -Indexes' no Apache ou 'autoindex off;' no Nginx).",
      });
    }
  } catch {
    // Caso a requisição principal falhe por timeout/rede, prossegue com relatório parcial
  }

  // Run Safe Non-Destructive Probes in Parallel
  const probePromises = SAFE_EXPOSURE_PROBES.map(async (probe) => {
    try {
      const probeUrl = `${baseOrigin}${probe.path}`;
      const res = await fetch(probeUrl, {
        method: "GET",
        redirect: "manual", // Evita seguir redirects para páginas de login ou home (anti-falso-positivo)
        headers: {
          "User-Agent": "ChimeraGuard-SecurityAuditor/1.5 (+https://chimera-guard.vercel.app)",
        },
        signal: AbortSignal.timeout(3500),
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
            remediation: probe.remediation,
          });
        }
      }
    } catch {
      // Ignora timeouts individuais de rota
    }
  });

  // Check RFC 9116 /.well-known/security.txt
  const securityTxtPromise = (async () => {
    try {
      const res = await fetch(`${baseOrigin}/.well-known/security.txt`, {
        method: "GET",
        redirect: "manual",
        headers: {
          "User-Agent": "ChimeraGuard-SecurityAuditor/1.5 (+https://chimera-guard.vercel.app)",
        },
        signal: AbortSignal.timeout(3500),
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
              title: "Arquivo security.txt sem Diretiva Obrigatória Expires (RFC 9116)",
              evidence: "O arquivo /.well-known/security.txt existe, mas não contém o campo Expires exigido pela RFC 9116.",
              remediation: "Adicionar a diretiva 'Expires: 2027-12-31T23:59:59.000Z' no arquivo security.txt.",
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
        title: "Política de Divulgação de Vulnerabilidades (security.txt - RFC 9116) Ausente",
        evidence: "O domínio não publica o arquivo padronizado /.well-known/security.txt para contato de segurança.",
        remediation:
          "Criar o arquivo /.well-known/security.txt com as diretivas Contact: e Expires: conforme a RFC 9116.",
      });
    } catch {
      // Ignora erro de rede
    }
  })();

  await Promise.all([...probePromises, securityTxtPromise]);

  // Calculate Risk Score & Security Grade
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

  let securityGrade: PhpAndVulnAuditReport["securityGrade"] = "A+";
  if (riskScore === 0) securityGrade = "A+";
  else if (riskScore <= 10) securityGrade = "A";
  else if (riskScore <= 25) securityGrade = "B";
  else if (riskScore <= 50) securityGrade = "C";
  else if (riskScore <= 75) securityGrade = "D";
  else securityGrade = "F";

  let overallStatus: PhpAndVulnAuditReport["overallStatus"] = "SECURE";
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
      nginxConf: `# Blindagem Nginx contra PHP-CGI Argument Injection (CVE-2024-4577) e Arquivos Sensíveis
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
</FilesMatch>`,
    },
    durationMs: Date.now() - start,
  };
}

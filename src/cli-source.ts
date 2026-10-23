#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { auditUniversalEndpoint } from "./scanner/universal-web-scanner.ts";
import {
  auditDomainDnsSecurity,
  scanDirectoryForSecrets,
  auditJwtToken,
  discoverSubdomains,
  calculatePasswordEntropy,
  detectWaf,
  scanHostCriticalPorts,
  validateTargetScope,
  loadObsidianConfig,
  generateDefaultConfigFile,
  analyzeSslTls,
  fingerprintTechStack,
  analyzeHttpMethods,
  detectOpenRedirects,
  convertSecretReportToSarif,
  generateHtmlSecurityReport,
  checkCachedUpdateSync,
  triggerBackgroundUpdateCheck,
  analyzeOriginLeak,
  analyzePhpAndWebVulnerabilities,
} from "./lib/security/index.ts";

const CLI_VERSION = "1.6.0";
const args = process.argv.slice(2);
const command = args[0] || "help";

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  magenta: "\x1b[35m",
};

function printBanner() {
  const isLegacyInvoked = (process.argv[1] || "").toLowerCase().includes("obsidiansec");
  if (isLegacyInvoked && !args.includes("--json") && !args.includes("--sarif") && !args.some((a) => a.startsWith("--format="))) {
    console.log(`${ANSI.yellow}⚡ NOTICE: ObsidianSec has officially evolved into ChimeraGuard!${ANSI.reset}`);
    console.log(`${ANSI.yellow}   Both commands work, but 'npx chimeraguard' is now the official CLI.${ANSI.reset}\n`);
  }

  console.log(`
${ANSI.bold}${ANSI.cyan}╔══════════════════════════════════════════════════════════════════════╗
║    🛡️  CHIMERAGUARD CLI // DEVSECOPS & DEFENSE ARSENAL 2026           ║
║    (Formerly ObsidianSec · Multi-Vector Security Guardian)           ║
╚══════════════════════════════════════════════════════════════════════╝${ANSI.reset}
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
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec audit <url> [--min-grade=A] [--json]${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  const config = loadObsidianConfig();

  // Validação de Perímetro e Escopo Autorizado
  const scope = validateTargetScope(targetUrl, config);
  if (!scope.allowed) {
    if (isJson) {
      console.log(JSON.stringify({ error: scope.reason, errorCode: scope.errorCode }, null, 2));
    } else {
      printBanner();
      console.error(`${ANSI.red}🚫 [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
      console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}`);
      console.log(`Para autorizar este alvo, adicione-o ao 'scope.allowlist' em ${ANSI.bold}obsidiansec.config.json${ANSI.reset}.\n`);
    }
    process.exit(1);
  }

  const minGradeArg = args.find((a) => a.startsWith("--min-grade="));
  const minGrade = minGradeArg ? minGradeArg.split("=")[1].toUpperCase() : "B";

  if (!isJson) printBanner();
  if (!isJson) console.log(`🔍 [1/2] Disparando sondagem tática de borda em ${ANSI.bold}${targetUrl}${ANSI.reset}...`);

  try {
    const report = await auditUniversalEndpoint(targetUrl);
    
    // Cálculo de Score
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
      fs.writeFileSync(path.resolve(process.cwd(), htmlPath), htmlContent, "utf-8");
      console.log(`\n${ANSI.green}📄 Relatório Executivo HTML gerado com sucesso em:${ANSI.reset} ${htmlPath}`);
    }

    if (isJson) {
      console.log(JSON.stringify({ ...report, score, grade }, null, 2));
      process.exit(0);
    }

    const gradeColor = (grade === "A+" || grade === "A") ? ANSI.green : grade === "B" ? ANSI.yellow : ANSI.red;

    console.log(`\n======================================================================`);
    console.log(`📊 RESULTADO DA AUDITORIA DE SEGURANÇA`);
    console.log(`======================================================================`);
    console.log(`• Alvo Auditado:           ${report.targetUrl}`);
    console.log(`• Servidor / Borda:        ${report.serverDetected}`);
    console.log(`• Score de Blindagem:      ${score} / 100`);
    console.log(`• Nota Final:              ${gradeColor}${ANSI.bold}GRADE ${grade}${ANSI.reset}`);
    console.log(`• Status:                  ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "AÇÃO REQUERIDA"}${ANSI.reset}`);
    console.log(`• Cadeia de Ataque:        ${report.attackChain.riskSummary}`);
    console.log(`======================================================================\n`);

    console.log(`🛡️  CONTROLES DE BORDA:`);
    console.log(`  [${h.csp.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] Content-Security-Policy (CSP)`);
    console.log(`  [${h.xFrameOptions.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] X-Frame-Options (Anti-Clickjacking)`);
    console.log(`  [${h.hsts.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] Strict-Transport-Security (HSTS)`);
    console.log(`  [${h.xContentTypeOptions.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] X-Content-Type-Options (nosniff)`);
    console.log(`  [${h.permissionsPolicy.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] Permissions-Policy`);
    console.log(`\n======================================================================\n`);

    // Quality Gate Check para CI/CD
    const gradeRanks = { "A+": 5, "A": 4, "B": 3, "C": 2, "F": 1, "ERR": 0 };
    const currentRank = gradeRanks[grade] || 0;
    const requiredRank = gradeRanks[minGrade] || 3;

    if (currentRank < requiredRank) {
      console.error(`${ANSI.red}❌ [CI/CD Quality Gate]: Reprovado! A nota ${grade} é inferior à nota mínima exigida (${minGrade}).${ANSI.reset}\n`);
      process.exit(1);
    }

    console.log(`${ANSI.green}✅ [CI/CD Quality Gate]: Aprovado com sucesso! O deploy atende aos requisitos de segurança.${ANSI.reset}\n`);
    process.exit(0);
  } catch (err) {
    console.error(`\n${ANSI.red}❌ Falha na auditoria:${ANSI.reset} ${err.message}\n`);
    process.exit(1);
  }
}

async function runDns() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}❌ Erro: Domínio não especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec dns <dominio>${ANSI.reset}`);
    process.exit(1);
  }

  const config = loadObsidianConfig();
  const scope = validateTargetScope(domain, config);
  if (!scope.allowed) {
    printBanner();
    console.error(`${ANSI.red}🚫 [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
    console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}\n`);
    process.exit(1);
  }

  printBanner();
  console.log(`🔍 Consultando registros DNS e Anti-Phishing para ${ANSI.bold}${domain}${ANSI.reset}...\n`);

  try {
    const report = await auditDomainDnsSecurity(domain);
    console.log(`• Domínio:             ${report.domain}`);
    console.log(`• Score de Email:      ${report.emailSecurityScore} / 100`);
    console.log(`• Status:              ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "ALERTA"}${ANSI.reset}`);
    console.log(`• SPF:                 ${report.spf.present ? ANSI.green + "ATIVO (" + report.spf.qualifier + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`• DMARC:               ${report.dmarc.present ? ANSI.green + "ATIVO (p=" + report.dmarc.policy + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`• DNSSEC:              ${report.dnssecActive ? ANSI.green + "ATIVO" : ANSI.gray + "INATIVO"}${ANSI.reset}`);
    console.log(`\n======================================================================\n`);
  } catch (err) {
    console.error(`\n${ANSI.red}❌ Falha na auditoria DNS:${ANSI.reset} ${err.message}\n`);
  }
}

async function runScanDir() {
  const dirInput = args.find((a) => !a.startsWith("-") && a !== "scan-dir" && a !== "scan" && a !== "sast") || process.cwd();
  const isJson = args.includes("--json") || args.some((a) => a.startsWith("--format=json"));
  const isSarif = args.includes("--sarif") || args.some((a) => a.startsWith("--format=sarif"));
  const outputArg = args.find((a) => a.startsWith("--output=") || a.startsWith("-o="));
  const outputPath = outputArg ? outputArg.split("=")[1] : null;

  if (!isJson && !isSarif) printBanner();
  if (!isJson && !isSarif) console.log(`🔍 Varrendo arquivos e caçando segredos em ${ANSI.bold}${dirInput}${ANSI.reset}...\n`);

  const report = scanDirectoryForSecrets(dirInput);

  // Exportação SARIF v2.1.0 para GitHub Code Scanning / SonarQube
  if (isSarif) {
    const sarifDoc = convertSecretReportToSarif(report);
    const serialized = JSON.stringify(sarifDoc, null, 2);

    if (outputPath) {
      fs.writeFileSync(path.resolve(process.cwd(), outputPath), serialized, "utf-8");
      console.log(`${ANSI.green}✅ Relatório SARIF v2.1.0 gerado com sucesso em:${ANSI.reset} ${outputPath}`);
    } else {
      console.log(serialized);
    }
    process.exit(report.isClean ? 0 : 1);
  }

  if (isJson) {
    const serialized = JSON.stringify(report, null, 2);
    if (outputPath) {
      fs.writeFileSync(path.resolve(process.cwd(), outputPath), serialized, "utf-8");
      console.log(`${ANSI.green}✅ Relatório JSON salvo em:${ANSI.reset} ${outputPath}`);
    } else {
      console.log(serialized);
    }
    process.exit(report.isClean ? 0 : 1);
  }

  if (outputPath) {
    fs.writeFileSync(path.resolve(process.cwd(), outputPath), JSON.stringify(report, null, 2), "utf-8");
    console.log(`${ANSI.green}📁 Cópia do relatório salva em:${ANSI.reset} ${outputPath}\n`);
  }

  console.log(`======================================================================`);
  console.log(`📊 RELATÓRIO DO CAÇADOR DE SEGREDOS & SAST LOCAL`);
  console.log(`======================================================================`);
  console.log(`• Arquivos Analisados:     ${report.totalFilesScanned}`);
  console.log(`• Duração:                 ${report.scanDurationMs}ms`);
  console.log(`• Vulnerabilidades:        ${report.isClean ? ANSI.green + "0 (LIMPO)" : ANSI.red + report.findings.length + " ENCONTRADAS"}${ANSI.reset}`);
  console.log(`• Críticas:                ${report.criticalCount > 0 ? ANSI.red + report.criticalCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`• Altas:                   ${report.highCount > 0 ? ANSI.yellow + report.highCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`======================================================================\n`);

  if (report.findings.length > 0) {
    console.log(`⚠️  VULNERABILIDADES DETECTADAS:`);
    report.findings.forEach((f, idx) => {
      const color = f.severity === "CRITICAL" ? ANSI.red : ANSI.yellow;
      console.log(`\n  [#${idx + 1}] ${color}${ANSI.bold}[${f.severity}] ${f.description}${ANSI.reset}`);
      console.log(`      📁 Arquivo: ${ANSI.cyan}${f.filePath}:${f.lineNumber}${ANSI.reset}`);
      console.log(`      🔍 Trecho:  ${ANSI.gray}${f.snippet}${ANSI.reset}`);
    });
    console.log(`\n${ANSI.red}❌ [SAST Gate]: Foram encontrados segredos sensíveis no código. Remova-os antes de publicar!${ANSI.reset}\n`);
    process.exit(1);
  } else {
    console.log(`${ANSI.green}✅ [SAST Gate]: Nenhum segredo ou credencial vazada detectada no código!${ANSI.reset}\n`);
    process.exit(0);
  }
}

async function runJwt() {
  const token = args[1];
  if (!token) {
    console.error(`${ANSI.red}❌ Erro: Token JWT não especificado.${ANSI.reset}`);
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
  console.log(`🎟️ AUDITORIA DE SEGURANÇA DE TOKEN JWT\n`);

  if (!report.isValidStructure) {
    console.error(`${ANSI.red}❌ Formato inválido de JWT.${ANSI.reset}`);
    report.issues.forEach((i) => console.log(`  - ${i.message}`));
    process.exit(1);
  }

  const statusColor = report.status === "SECURE" ? ANSI.green : report.status === "WARNING" ? ANSI.yellow : ANSI.red;

  console.log(`• Algoritmo:           ${ANSI.bold}${report.algorithm}${ANSI.reset}`);
  console.log(`• Score de Segurança:  ${report.securityScore} / 100`);
  console.log(`• Status:              ${statusColor}${ANSI.bold}${report.status}${ANSI.reset}`);
  console.log(`• Assinatura Presente: ${report.signaturePresent ? ANSI.green + "SIM" : ANSI.red + "NÃO (alg: none)"}${ANSI.reset}`);
  console.log(`• Expiração:           ${report.hasExpiration ? (report.isExpired ? ANSI.red + "EXPIRADO" : ANSI.green + "VÁLIDO") : ANSI.yellow + "SEM EXPIRAÇÃO"}${ANSI.reset}`);

  console.log(`\n📜 HEADER DECODIFICADO:`);
  console.log(JSON.stringify(report.header, null, 2));

  console.log(`\n📦 PAYLOAD (CLAIMS):`);
  console.log(JSON.stringify(report.payload, null, 2));

  if (report.issues.length > 0) {
    console.log(`\n⚠️  RISCOS DETECTADOS:`);
    report.issues.forEach((iss) => {
      const color = iss.severity === "CRITICAL" ? ANSI.red : iss.severity === "HIGH" ? ANSI.yellow : ANSI.gray;
      console.log(`  ${color}[${iss.severity}] ${iss.message}${ANSI.reset}`);
    });
  }

  console.log(`\n======================================================================\n`);
  process.exit(report.status === "CRITICAL" ? 1 : 0);
}

async function runSubdomains() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}❌ Erro: Domínio não especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec subdomains <dominio>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🌐 Buscando subdomínios via Certificate Transparency Logs para ${ANSI.bold}${domain}${ANSI.reset}...\n`);

  const report = await discoverSubdomains(domain);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }

  console.log(`======================================================================`);
  console.log(`📊 SUPERFÍCIE DE ATAQUE PASSIVA (SUBDOMÍNIOS)`);
  console.log(`======================================================================`);
  console.log(`• Domínio Alvo:        ${report.domain}`);
  console.log(`• Total Descoberto:    ${ANSI.bold}${report.totalFound} subdomínios únicos${ANSI.reset}`);
  console.log(`• Fonte:               ${report.source}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  if (report.subdomains.length > 0) {
    report.subdomains.forEach((s) => console.log(`  ${ANSI.cyan}•${ANSI.reset} ${s}`));
  } else {
    console.log(`  Nenhum subdomínio adicional encontrado nos registros públicos.`);
  }

  console.log(`\n======================================================================\n`);
}

async function runEntropy() {
  const password = args[1];
  if (!password) {
    console.error(`${ANSI.red}❌ Erro: Senha não especificada.${ANSI.reset}`);
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
  console.log(`🔑 CALCULADORA DE ENTROPIA SHANNON & HASHCAT\n`);

  const strengthColor = entropy.strengthCategory === "VERY_STRONG" || entropy.strengthCategory === "STRONG" ? ANSI.green : entropy.strengthCategory === "FAIR" ? ANSI.yellow : ANSI.red;

  console.log(`• Tamanho da Senha:    ${entropy.length} caracteres`);
  console.log(`• Bits de Entropia:    ${ANSI.bold}${entropy.entropyBits} bits${ANSI.reset}`);
  console.log(`• Charset Estimado:    ${entropy.charsetSize} símbolos`);
  console.log(`• Nível de Força:      ${strengthColor}${ANSI.bold}${entropy.strengthCategory}${ANSI.reset}`);
  console.log(`• Tempo Estimado GPU:  ${ANSI.bold}${entropy.estimatedCrackTimeGpuCluster}${ANSI.reset} (Cluster RTX 4090 / Hashcat)`);
  console.log(`\n======================================================================\n`);
}

async function runWaf() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec waf <url>${ANSI.reset}`);
    process.exit(1);
  }

  const config = loadObsidianConfig();
  const scope = validateTargetScope(targetUrl, config);
  if (!scope.allowed) {
    printBanner();
    console.error(`${ANSI.red}🚫 [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
    console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}\n`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🛡️  Inspecionando assinaturas de WAF e Firewall de Borda para ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);

  const report = await detectWaf(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }

  const statusColor = report.detected ? ANSI.green : ANSI.yellow;

  console.log(`======================================================================`);
  console.log(`📊 DETECTOR DE WAF // WEB APPLICATION FIREWALL (WAFW00F ENGINE)`);
  console.log(`======================================================================`);
  console.log(`• Alvo:                ${report.targetUrl}`);
  console.log(`• Status do WAF:       ${statusColor}${ANSI.bold}${report.detected ? "ATIVO & DETECTADO" : "NÃO DETECTADO"}${ANSI.reset}`);
  console.log(`• Firewall / Shield:   ${ANSI.bold}${report.wafName}${ANSI.reset}`);
  console.log(`• Fabricante / Vendor: ${report.vendor}`);
  console.log(`• Nível de Confiança:  ${report.confidence}`);
  console.log(`• Fase de Detecção:    ${report.detectionPhase}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`• Recomendação:        ${report.recommendation}`);
  console.log(`======================================================================\n`);

  if (report.indicators.length > 0) {
    console.log(`🔍 EVIDÊNCIAS E ASSINATURAS IDENTIFICADAS:`);
    report.indicators.forEach((ind) => console.log(`  ${ANSI.cyan}•${ANSI.reset} ${ind}`));
  }

  console.log(`\n======================================================================\n`);
}

async function runPorts() {
  const host = args[1];
  if (!host) {
    console.error(`${ANSI.red}❌ Erro: Host / IP alvo não especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec ports <host>${ANSI.reset}`);
    process.exit(1);
  }

  const config = loadObsidianConfig();
  const scope = validateTargetScope(host, config);
  if (!scope.allowed) {
    printBanner();
    console.error(`${ANSI.red}🚫 [SCOPE GUARD]: Auditoria de portas bloqueada!${ANSI.reset}`);
    console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}\n`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🚪 [Nmap Engine] Auditando 12 portas críticas e caçando bancos de dados em ${ANSI.bold}${host}${ANSI.reset}...\n`);

  const report = await scanHostCriticalPorts(host);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallVerdict === "CRITICAL" ? 1 : 0);
  }

  const verdictColor = report.overallVerdict === "SECURE" ? ANSI.green : report.overallVerdict === "WARNING" ? ANSI.yellow : ANSI.red;

  console.log(`======================================================================`);
  console.log(`📊 RELATÓRIO DE AUDITORIA DE PORTAS CRÍTICAS & SERVIÇOS EXPOSTOS`);
  console.log(`======================================================================`);
  console.log(`• Host Auditado:       ${report.targetHost}`);
  console.log(`• Portas Analisadas:   ${report.totalScanned}`);
  console.log(`• Portas Abertas:      ${report.openCount > 0 ? ANSI.yellow + report.openCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`• Exposição Crítica:   ${report.criticalExposuresCount > 0 ? ANSI.red + report.criticalExposuresCount + " (RISCO GRAVE)" : ANSI.green + "0 (LIMPO)"}${ANSI.reset}`);
  console.log(`• Diagnóstico:         ${verdictColor}${ANSI.bold}${report.overallVerdict}${ANSI.reset}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  console.log(`📋 RESULTADO POR PORTA AUDITADA:`);
  report.results.forEach((r) => {
    const statusBadge = r.status === "OPEN" ? ANSI.red + "[OPEN]" : r.status === "FILTERED" ? ANSI.green + "[FILTERED]" : ANSI.gray + "[CLOSED]";
    console.log(`  ${statusBadge}${ANSI.reset} ${ANSI.bold}Porta ${r.port}/TCP${ANSI.reset} - ${r.service} (${r.responseTimeMs}ms)`);
    if (r.status === "OPEN" && (r.riskLevel === "CRITICAL" || r.riskLevel === "HIGH")) {
      console.log(`      ⚠️  ${ANSI.red}${ANSI.bold}RISCO:${ANSI.reset} ${r.exposureRisk}`);
      console.log(`      💡 ${ANSI.cyan}Mitigação:${ANSI.reset} ${r.mitigation}`);
    }
  });

  console.log(`\n======================================================================\n`);
  process.exit(report.overallVerdict === "CRITICAL" ? 1 : 0);
}

async function runSsl() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec ssl <url>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🔒 Inspecionando certificado SSL/TLS e criptografia para ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);

  const report = await analyzeSslTls(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.valid ? 0 : 1);
  }

  const gradeColor = report.grade === "A+" || report.grade === "A" ? ANSI.green : report.grade === "B" ? ANSI.yellow : ANSI.red;

  console.log(`======================================================================`);
  console.log(`📊 RELATÓRIO DE AUDITORIA SSL/TLS (SSL LABS ENGINE)`);
  console.log(`======================================================================`);
  console.log(`• Alvo Auditado:       ${report.targetUrl}`);
  console.log(`• Emissor (CA):        ${report.issuer}`);
  console.log(`• Sujeito (CN):        ${report.subject}`);
  console.log(`• Protocolo:           ${report.protocol}`);
  console.log(`• Algoritmo de Ass.:   ${report.signatureAlgorithm}`);
  console.log(`• Nota TLS:            ${gradeColor}${ANSI.bold}GRADE ${report.grade}${ANSI.reset}`);
  console.log(`• Status:              ${report.valid ? ANSI.green + "VÁLIDO & CONFIÁVEL" : ANSI.red + "INVÁLIDO / RISCO"}${ANSI.reset}`);
  console.log(`• Expiração:           ${report.validTo} (${report.daysUntilExpiry} dias restantes)`);
  console.log(`• Auto-assinado:       ${report.isSelfSigned ? ANSI.red + "SIM (RISCO)" : ANSI.green + "NÃO"}${ANSI.reset}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  if (report.subjectAltNames.length > 0) {
    console.log(`🌐 NOMES ALTERNATIVOS DO SUJEITO (SAN):`);
    report.subjectAltNames.slice(0, 10).forEach((san) => console.log(`  ${ANSI.cyan}•${ANSI.reset} ${san}`));
    if (report.subjectAltNames.length > 10) console.log(`  ... e mais ${report.subjectAltNames.length - 10} domínios.`);
    console.log("");
  }

  if (report.issues.length > 0) {
    console.log(`⚠️  VULNERABILIDADES & ALERTAS DE CERTIFICADO:`);
    report.issues.forEach((iss) => {
      const color = iss.severity === "CRITICAL" ? ANSI.red : iss.severity === "HIGH" ? ANSI.yellow : ANSI.gray;
      console.log(`  ${color}[${iss.severity}] ${iss.message}${ANSI.reset}`);
    });
    console.log(`\n======================================================================\n`);
  }

  process.exit(report.valid ? 0 : 1);
}

async function runTech() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec tech <url>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🧬 Identificando stack de tecnologias (Wappalyzer Engine) em ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);

  const report = await fingerprintTechStack(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }

  console.log(`======================================================================`);
  console.log(`📊 SUPERFÍCIE DE TECNOLOGIAS & FINGERPRINTING DE STACK`);
  console.log(`======================================================================`);
  console.log(`• Alvo Auditado:       ${report.targetUrl}`);
  console.log(`• Servidor Web:        ${report.serverHeader}`);
  console.log(`• X-Powered-By:        ${report.poweredBy}`);
  console.log(`• Total Identificado:  ${ANSI.bold}${report.totalDetected} tecnologias${ANSI.reset}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  if (report.detections.length > 0) {
    console.log(`🛠️  TECNOLOGIAS DETECTADAS:`);
    report.detections.forEach((t) => {
      console.log(`  ${ANSI.cyan}•${ANSI.reset} ${ANSI.bold}${t.name}${ANSI.reset} [${t.category}] (Confiança: ${t.confidence})`);
      console.log(`      🔍 Evidência: ${ANSI.gray}${t.evidence}${ANSI.reset}`);
    });
  } else {
    console.log(`  Nenhuma tecnologia identificável explicitamente (Ofuscação ativa).`);
  }

  console.log(`\n======================================================================\n`);
}

async function runMethods() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec methods <url>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`📡 Enumerando métodos HTTP e testando verbos perigosos em ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);

  const report = await analyzeHttpMethods(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
  }

  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;

  console.log(`======================================================================`);
  console.log(`📊 RELATÓRIO DE ENUMERAÇÃO DE MÉTODOS HTTP`);
  console.log(`======================================================================`);
  console.log(`• Alvo:                ${report.targetUrl}`);
  console.log(`• Métodos Permitidos:  ${ANSI.bold}${report.allowedMethods.join(", ")}${ANSI.reset}`);
  console.log(`• Métodos Perigosos:   ${report.riskyMethods.length > 0 ? ANSI.red + report.riskyMethods.join(", ") : ANSI.green + "NENHUM EXPOSTO"}${ANSI.reset}`);
  console.log(`• Diagnóstico Geral:   ${statusColor}${ANSI.bold}${report.overallStatus}${ANSI.reset}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  console.log(`📋 RESULTADO POR MÉTODO:`);
  report.results.forEach((m) => {
    const badge = m.risky ? ANSI.red + "[PERIGO]" : m.allowed ? ANSI.green + "[PERMITIDO]" : ANSI.gray + "[BLOQUEADO]";
    console.log(`  ${badge}${ANSI.reset} ${ANSI.bold}${m.method}${ANSI.reset} (HTTP ${m.statusCode}) — ${m.description}`);
  });

  console.log(`\n======================================================================\n`);
  process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
}

async function runRedirects() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec redirects <url>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🔀 Caçando Open Redirects (OWASP CWE-601) em ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);

  const report = await detectOpenRedirects(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.vulnerableCount > 0 ? 1 : 0);
  }

  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;

  console.log(`======================================================================`);
  console.log(`📊 DETECTOR DE OPEN REDIRECT (OWASP CWE-601)`);
  console.log(`======================================================================`);
  console.log(`• Alvo:                ${report.targetUrl}`);
  console.log(`• Parâmetros Testados: ${report.totalTested}`);
  console.log(`• Vulnerabilidades:    ${report.vulnerableCount > 0 ? ANSI.red + report.vulnerableCount + " VULNERÁVEL" : ANSI.green + "0 (SEGURO)"}${ANSI.reset}`);
  console.log(`• Diagnóstico:         ${statusColor}${ANSI.bold}${report.overallStatus}${ANSI.reset}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  if (report.results.length > 0) {
    console.log(`🔍 REDIRECIONAMENTOS IDENTIFICADOS:`);
    report.results.forEach((r) => {
      const color = r.isOpenRedirect ? ANSI.red : ANSI.yellow;
      console.log(`  ${color}• Parâmetro: '${r.parameter}'${ANSI.reset} -> ${r.redirectedTo}`);
    });
  } else {
    console.log(`  Nenhum redirecionamento aberto detectado nos parâmetros comuns.`);
  }

  console.log(`\n======================================================================\n`);
  process.exit(report.vulnerableCount > 0 ? 1 : 0);
}

async function runOrigin() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: Domínio ou URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec origin <url|dominio>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🔍 Caçando vazamentos de IP real e bypass de CDN/WAF em ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);

  const report = await analyzeOriginLeak(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallStatus === "CRITICAL_BYPASS" ? 1 : 0);
  }

  const statusColor = report.overallStatus === "SECURE" ? ANSI.green : report.overallStatus === "WARNING" ? ANSI.yellow : ANSI.red;

  console.log(`======================================================================`);
  console.log(`📊 DETECTOR DE ORIGIN BYPASS & VAZAMENTO DE IP REAL`);
  console.log(`======================================================================`);
  console.log(`• Domínio Analisado:    ${report.targetDomain}`);
  console.log(`• Protegido por CDN:    ${report.isBehindProxyOrCdn ? ANSI.green + "SIM (" + report.proxyProvider + ")" : ANSI.yellow + "NÃO (ORIGEM DIRETA)"}${ANSI.reset}`);
  console.log(`• IPs Públicos (Borda): ${report.primaryIps.join(", ") || "Nenhum"}`);
  console.log(`• Risco de Bypass:      ${statusColor}${ANSI.bold}${report.riskScore}/100 [${report.overallStatus}]${ANSI.reset}`);
  console.log(`• Duração da Análise:   ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  console.log(`📋 VETORES INSPECIONADOS:`);
  console.log(`  • Registros SPF/TXT:    ${report.testedVectors.spfIpsFound.length > 0 ? ANSI.yellow + report.testedVectors.spfIpsFound.join(", ") : ANSI.green + "Nenhum IP exposto"}${ANSI.reset}`);
  console.log(`  • Servidores de E-mail:  ${report.testedVectors.mxHostsFound.length > 0 ? report.testedVectors.mxHostsFound.join(", ") : "Nenhum MX detectado"}`);
  console.log(`  • Subdomínios Testados:  ${report.testedVectors.subdomainsProbed} sondados (${report.testedVectors.subdomainsExposed.length > 0 ? ANSI.red + report.testedVectors.subdomainsExposed.length + " expostos fora da CDN" : ANSI.green + "Todos protegidos"}${ANSI.reset})`);

  if (report.candidateOriginIps.length > 0) {
    console.log(`\n🎯 CANDIDATOS A IP REAL DE ORIGEM:`);
    report.candidateOriginIps.forEach((c) => {
      const matchBadge = c.virtualHostMatch ? ANSI.red + " [CONFIRMADO: VIRTUAL HOST MATCH]" : "";
      console.log(`  • IP: ${ANSI.bold}${c.ip}${ANSI.reset} | Vetor: ${c.sourceVector} ${c.discoveredHost ? "(" + c.discoveredHost + ")" : ""}${matchBadge}`);
    });
  }

  if (report.confirmedBypassIps.length > 0) {
    console.log(`\n${ANSI.red}🚨 ALERTA CRÍTICO: Vazamento de origem confirmado!${ANSI.reset}`);
    console.log(`O servidor físico responde diretamente em ${report.confirmedBypassIps.join(", ")}, permitindo que atacantes ignorem 100% da Cloudflare/WAF.`);
  }

  console.log(`\n🛡️  PATCH RECOMENDADO DE FIREWALL (UFW / NGINX):`);
  console.log(`  Para fechar conexões diretas na porta 443 e aceitar tráfego apenas da Cloudflare:`);
  console.log(`${ANSI.cyan}  sudo ufw default deny incoming\n  sudo ufw allow from 173.245.48.0/20 to any port 443 proto tcp\n  sudo ufw deny 443/tcp\n  sudo ufw reload${ANSI.reset}`);

  console.log(`\n======================================================================\n`);
  process.exit(report.overallStatus === "CRITICAL_BYPASS" ? 1 : 0);
}

async function runPhpAndVulns() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
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
      console.error(`${ANSI.red}🚫 [SCOPE GUARD]: Auditoria bloqueada!${ANSI.reset}`);
      console.error(`${ANSI.yellow}Motivo: ${scope.reason}${ANSI.reset}`);
    }
    process.exit(1);
  }

  if (!isJson) {
    printBanner();
    console.log(`🐘 Auditando vulnerabilidades críticas de PHP (CVE-2024-4577 / EOL), CVEs de Servidor e Exposições em ${ANSI.bold}${targetUrl}${ANSI.reset}...\n`);
  }

  const report = await analyzePhpAndWebVulnerabilities(targetUrl);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
  }

  const statusColor =
    report.overallStatus === "SECURE"
      ? ANSI.green
      : report.overallStatus === "WARNING"
        ? ANSI.yellow
        : ANSI.red;

  console.log(`======================================================================`);
  console.log(`${ANSI.bold}📊 AUDITORIA DE VULNERABILIDADES PHP, CVEs & EXPOSIÇÃO DE BORDA${ANSI.reset}`);
  console.log(`======================================================================`);
  console.log(`• Alvo Auditado:       ${report.targetUrl}`);
  console.log(`• Runtime PHP:         ${report.phpDetected ? ANSI.yellow + "DETECTADO" + (report.phpVersion ? ` (v${report.phpVersion})` : " (Versão Oculta)") : ANSI.green + "Não Identificado / Oculto"}${ANSI.reset}`);
  if (report.phpVersion) {
    console.log(`• Ciclo de Vida PHP:   ${report.phpIsEol ? ANSI.red + "END-OF-LIFE (SEM SUPORTE DE SEGURANÇA)" : ANSI.green + "SUPORTADO"}${ANSI.reset}`);
  }
  console.log(`• Servidor Web:        ${report.serverBanner}`);
  console.log(`• X-Powered-By:        ${report.poweredByBanner}`);
  console.log(`• Sistema Operacional: ${report.osHint}`);
  console.log(`• security.txt (9116): ${report.securityTxtPresent ? ANSI.green + "PRESENTE" : ANSI.yellow + "AUSENTE"}${ANSI.reset}`);
  console.log(`• Nota de Blindagem:   ${statusColor}${ANSI.bold}GRADE ${report.securityGrade} (Risco: ${report.riskScore}/100 - ${report.overallStatus})${ANSI.reset}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  if (report.cveFindings.length > 0) {
    console.log(`${ANSI.red}${ANSI.bold}🚨 VULNERABILIDADES CVE IDENTIFICADAS (${report.cveFindings.length}):${ANSI.reset}`);
    for (const cve of report.cveFindings) {
      const sevColor = cve.severity === "CRITICAL" ? ANSI.red : ANSI.yellow;
      console.log(`  • ${sevColor}${ANSI.bold}[${cve.severity} // CVSS ${cve.cvssScore}] ${cve.cveId}${ANSI.reset} (${cve.component} ${cve.detectedVersion})`);
      console.log(`    Título:   ${cve.title}`);
      console.log(`    Detalhe:  ${cve.description}`);
      console.log(`    Correção: ${ANSI.cyan}Atualizar para ${cve.patchedVersion}${ANSI.reset} — ${cve.remediation}\n`);
    }
  } else {
    console.log(`${ANSI.green}✅ Nenhuma versão vulnerável a CVEs críticas (como CVE-2024-4577) foi exposta nos banners.${ANSI.reset}\n`);
  }

  if (report.exposureFindings.length > 0) {
    console.log(`${ANSI.yellow}${ANSI.bold}🔍 EXPOSIÇÕES & PONTOS DE HARDENING (${report.exposureFindings.length}):${ANSI.reset}`);
    for (const exp of report.exposureFindings) {
      const sevColor = exp.severity === "CRITICAL" || exp.severity === "HIGH" ? ANSI.red : exp.severity === "MEDIUM" ? ANSI.yellow : ANSI.cyan;
      console.log(`  • ${sevColor}[${exp.severity}] ${exp.title}${ANSI.reset} (${exp.pathOrHeader})`);
      console.log(`    Evidência:  ${exp.evidence}`);
      console.log(`    Remediação: ${exp.remediation}\n`);
    }
  }

  console.log(`🛡️  DIRETIVAS DE BLINDAGEM RECOMENDADAS (PHP.INI):`);
  console.log(`${ANSI.cyan}${report.remediationConfig.phpIni}${ANSI.reset}\n`);
  console.log(`======================================================================\n`);
  process.exit(report.overallStatus === "CRITICAL" ? 1 : 0);
}

function runInitConfig() {
  printBanner();
  try {
    const configPath = generateDefaultConfigFile();
    console.log(`${ANSI.green}✅ Arquivo de configuração gerado com sucesso!${ANSI.reset}`);
    console.log(`📁 Local: ${ANSI.bold}${configPath}${ANSI.reset}`);
    console.log(`\nVocê pode configurar seu ${ANSI.cyan}scope.allowlist${ANSI.reset} e preferências de IA no arquivo.\n`);
  } catch (err) {
    console.error(`${ANSI.red}❌ Falha ao gerar arquivo de configuração:${ANSI.reset} ${err.message}`);
  }
}

function printHelp() {
  printBanner();
  console.log(`Arsenal de Comandos Disponíveis:

  ${ANSI.bold}chimeraguard audit <url>${ANSI.reset}           Audita cabeçalhos de borda, cookies, CORS e MITRE attack chain
    Opções:
      --min-grade=<A|B|C>         Define a nota mínima para o Quality Gate de CI/CD (padrão: B)
      --json                      Retorna o relatório completo em formato JSON

  ${ANSI.bold}chimeraguard origin <url>${ANSI.reset}          Caça vazamentos de IP real e bypass de Cloudflare/WAF (SPF, MX, Subdomínios)

  ${ANSI.bold}chimeraguard php <url>${ANSI.reset}             Audita CVEs críticas de PHP (CVE-2024-4577, 8926, EOL) e exposições (phpinfo, .env, .git)

  ${ANSI.bold}chimeraguard vulns <url>${ANSI.reset}           Scanner de CVEs de Servidores (Apache, Nginx, OpenSSL, IIS) e Exposições de Borda

  ${ANSI.bold}chimeraguard ssl <url>${ANSI.reset}             Auditoria de certificados SSL/TLS, validade, expiração e nota de segurança
  
  ${ANSI.bold}chimeraguard tech <url>${ANSI.reset}            Identificação de stack de tecnologias (Wappalyzer: React, Next, Nginx, CDNs)

  ${ANSI.bold}chimeraguard methods <url>${ANSI.reset}         Enumera métodos HTTP e caça verbos perigosos (TRACE/XST, PUT, DELETE)

  ${ANSI.bold}chimeraguard redirects <url>${ANSI.reset}       Detecta falhas de Open Redirect nos parâmetros de URL (OWASP CWE-601)

  ${ANSI.bold}chimeraguard waf <url>${ANSI.reset}             Detector de WAF & Firewall de Borda (22+ assinaturas: Cloudflare, AWS, etc)

  ${ANSI.bold}chimeraguard ports <host>${ANSI.reset}          Auditoria de 37 portas TCP críticas (Redis, Mongo, MySQL, Postgres, RDP, etc)

  ${ANSI.bold}chimeraguard scan-dir [pasta]${ANSI.reset}      Caçador de segredos & SAST local (45+ patterns: AWS, Stripe, Slack, Discord)
  
  ${ANSI.bold}chimeraguard jwt <token>${ANSI.reset}           Auditor de tokens JWT (detecta alg: none, expiração e decodifica claims)

  ${ANSI.bold}chimeraguard subdomains <dominio>${ANSI.reset}  Descoberta passiva de subdomínios via Certificate Transparency

  ${ANSI.bold}chimeraguard dns <dominio>${ANSI.reset}         Inspeciona registros anti-phishing SPF, DMARC e DNSSEC

  ${ANSI.bold}chimeraguard entropy <senha>${ANSI.reset}       Calcula bits de Shannon e tempo de quebra em GPU cluster

  ${ANSI.bold}chimeraguard init-config${ANSI.reset}           Gera o template de configuração de escopo e IA

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
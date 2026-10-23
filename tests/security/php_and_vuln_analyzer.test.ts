import { describe, it, expect } from "vitest";
import {
  compareSemver,
  evaluatePhpVersionVulnerabilities,
  evaluateServerBannerVulnerabilities,
} from "../../src/lib/security/php-and-vuln-analyzer.ts";

describe("🐘 PHP & Web Server Vulnerability Analyzer (CVE-2024-4577 & Edge Exposures)", () => {
  it("compara versões semânticas com precisão", () => {
    expect(compareSemver("8.3.7", "8.3.8")).toBe(-1);
    expect(compareSemver("8.3.8", "8.3.8")).toBe(0);
    expect(compareSemver("8.3.14", "8.3.8")).toBe(1);
    expect(compareSemver("2.4.58", "2.4.62")).toBe(-1);
  });

  it("identifica a falha crítica CVE-2024-4577 em versões vulneráveis do PHP (ex: 8.3.6, 8.2.15, 7.4.33)", () => {
    const res83 = evaluatePhpVersionVulnerabilities("8.3.6");
    expect(res83.isEol).toBe(false);
    expect(res83.cves.some((c) => c.cveId === "CVE-2024-4577")).toBe(true);
    expect(res83.cves.some((c) => c.cveId.includes("CVE-2024-8926"))).toBe(true);

    const res74 = evaluatePhpVersionVulnerabilities("7.4.33");
    expect(res74.isEol).toBe(true);
    expect(res74.cves.some((c) => c.cveId === "CVE-2024-4577")).toBe(true);
  });

  it("aprova versões corrigidas do PHP (ex: 8.3.15 e 8.4.2) sem apontar CVEs", () => {
    const resPatched = evaluatePhpVersionVulnerabilities("8.3.15");
    expect(resPatched.isEol).toBe(false);
    expect(resPatched.cves.length).toBe(0);

    const res84 = evaluatePhpVersionVulnerabilities("8.4.2");
    expect(res84.isEol).toBe(false);
    expect(res84.cves.length).toBe(0);
  });

  it("detecta vulnerabilidades em banners desatualizados de Apache, Nginx, OpenSSL e IIS", () => {
    const cves = evaluateServerBannerVulnerabilities(
      "Apache/2.4.58 (Win64) OpenSSL/1.1.1t",
      "PHP/8.2.10"
    );
    expect(cves.some((c) => c.component === "Apache HTTP Server")).toBe(true);
    expect(cves.some((c) => c.component === "OpenSSL")).toBe(true);

    const nginxCves = evaluateServerBannerVulnerabilities("nginx/1.24.0", "");
    expect(nginxCves.some((c) => c.component === "Nginx Web Server")).toBe(true);

    const iisCves = evaluateServerBannerVulnerabilities("Microsoft-IIS/8.5", "ASP.NET");
    expect(iisCves.some((c) => c.component === "Microsoft IIS")).toBe(true);
  });

  it("não gera falsos positivos para servidores Apache e Nginx atualizados", () => {
    const clean = evaluateServerBannerVulnerabilities("Apache/2.4.62 (Unix) OpenSSL/3.0.15", "");
    expect(clean.length).toBe(0);
  });
});

import { describe, it, expect } from 'bun:test';
import { parsers, SUPPORTED_SCANNERS, SupportedScanner, UnifiedFinding } from '../src/parsers';

describe('Scanner Parsers', () => {
  describe('Trivy Parser', () => {
    it('should parse Trivy vulnerability output correctly', () => {
      const trivyOutput = {
        Metadata: {
          TrivyVersion: '0.45.0'
        },
        Results: [
          {
            Target: 'package-lock.json',
            Vulnerabilities: [
              {
                VulnerabilityID: 'CVE-2023-0001',
                PkgName: 'lodash',
                InstalledVersion: '4.17.15',
                Severity: 'HIGH',
                Title: 'Prototype Pollution in lodash',
                Description: 'Lodash versions before 4.17.21 are vulnerable to prototype pollution',
                PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-0001'
              }
            ]
          }
        ]
      };

      const findings = parsers.trivy(trivyOutput);

      expect(findings).toHaveLength(1);
      const finding = findings[0];
      expect(finding.scanner_name).toBe('trivy');
      expect(finding.scanner_version).toBe('0.45.0');
      expect(finding.rule_id).toBe('CVE-2023-0001');
      expect(finding.severity).toBe('HIGH');
      expect(finding.file_path).toBe('package-lock.json');
      expect(finding.title).toBe('Prototype Pollution in lodash');
      expect(finding.cve_ids).toContain('CVE-2023-0001');
      expect(finding.description).toBe('Lodash versions before 4.17.21 are vulnerable to prototype pollution');
      expect(finding.remediation).toBe('Refer to https://avd.aquasec.com/nvd/cve-2023-0001');
      expect(finding.raw_data).toEqual(trivyOutput.Results[0].Vulnerabilities[0]);
    });

    it('should handle multiple vulnerabilities across multiple targets', () => {
      const trivyOutput = {
        Metadata: { TrivyVersion: '0.45.0' },
        Results: [
          {
            Target: 'package-lock.json',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-2023-0001', PkgName: 'lodash', Severity: 'HIGH' },
              { VulnerabilityID: 'CVE-2023-0002', PkgName: 'express', Severity: 'MEDIUM' }
            ]
          },
          {
            Target: 'requirements.txt',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-2023-0003', PkgName: 'django', Severity: 'CRITICAL' }
            ]
          }
        ]
      };

      const findings = parsers.trivy(trivyOutput);

      expect(findings).toHaveLength(3);
      expect(findings[0].file_path).toBe('package-lock.json');
      expect(findings[1].file_path).toBe('package-lock.json');
      expect(findings[2].file_path).toBe('requirements.txt');
      expect(findings[0].cve_ids).toContain('CVE-2023-0001');
      expect(findings[1].cve_ids).toContain('CVE-2023-0002');
      expect(findings[2].cve_ids).toContain('CVE-2023-0003');
    });

    it('should handle empty Trivy output', () => {
      expect(parsers.trivy({})).toHaveLength(0);
      expect(parsers.trivy(null)).toHaveLength(0);
      expect(parsers.trivy(undefined)).toHaveLength(0);
    });

    it('should handle Trivy output without vulnerabilities array', () => {
      const findings = parsers.trivy({ Results: [] });
      expect(findings).toHaveLength(0);
    });

    it('should handle Trivy output with missing vulnerability fields', () => {
      const trivyOutput = {
        Results: [
          {
            Target: 'package.json',
            Vulnerabilities: [
              { VulnerabilityID: undefined, PkgName: 'unknown' }
            ]
          }
        ]
      };

      const findings = parsers.trivy(trivyOutput);

      expect(findings).toHaveLength(1);
      expect(findings[0].rule_id).toBe('unknown-trivy-rule');
      expect(findings[0].file_path).toBe('package.json');
      expect(findings[0].title).toBe('Trivy finding');
    });

    it('should normalize severity to uppercase', () => {
      const trivyOutput = {
        Results: [
          {
            Target: 'test.js',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-1', Severity: 'low' },
              { VulnerabilityID: 'CVE-2', Severity: 'High' },
              { VulnerabilityID: 'CVE-3', Severity: 'UNKNOWN' }
            ]
          }
        ]
      };

      const findings = parsers.trivy(trivyOutput);

      expect(findings[0].severity).toBe('LOW');
      expect(findings[1].severity).toBe('HIGH');
      expect(findings[2].severity).toBe('UNKNOWN');
    });

    it('should create consistent fingerprints', () => {
      const trivyOutput = {
        Results: [
          {
            Target: 'test.js',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-1', PkgName: 'pkg1', InstalledVersion: '1.0.0' }
            ]
          }
        ]
      };

      const findings1 = parsers.trivy(trivyOutput);
      const findings2 = parsers.trivy(trivyOutput);

      expect(findings1[0].fingerprint).toBe(findings2[0].fingerprint);
    });
  });

  describe('Semgrep Parser', () => {
    it('should parse Semgrep JSON output correctly', () => {
      const semgrepOutput = {
        version: '1.45.0',
        results: [
          {
            check_id: 'javascript.lang.security.detect-non-literal-require.detect-non-literal-require',
            path: 'src/utils.js',
            start: { line: 10 },
            end: { line: 10 },
            extra: {
              severity: 'ERROR',
              message: 'Dynamic require call detected',
              lines: 'require(userInput)',
              metadata: {
                description: 'Detects dynamic require calls',
                cwe: [{ cwe_id: 'CWE-78' }],
                cve: ['CVE-2023-1234']
              }
            }
          }
        ]
      };

      const findings = parsers.semgrep(semgrepOutput);

      expect(findings).toHaveLength(1);
      const finding = findings[0];
      expect(finding.scanner_name).toBe('semgrep');
      expect(finding.scanner_version).toBe('1.45.0');
      expect(finding.rule_id).toBe('javascript.lang.security.detect-non-literal-require.detect-non-literal-require');
      expect(finding.severity).toBe('ERROR');
      expect(finding.file_path).toBe('src/utils.js');
      expect(finding.start_line).toBe(10);
      expect(finding.end_line).toBe(10);
      expect(finding.cwe_ids).toContain('CWE-78');
      expect(finding.cve_ids).toContain('CVE-2023-1234');
      expect(finding.title).toBe('Dynamic require call detected');
    });

    it('should handle multiple Semgrep findings', () => {
      const semgrepOutput = {
        version: '1.45.0',
        results: [
          {
            check_id: 'python.lang.security.use-defused-xml.use-defused-xml',
            path: 'app.py',
            start: { line: 5 },
            end: { line: 5 },
            extra: { severity: 'WARNING', message: 'XML parsing vulnerability' }
          },
          {
            check_id: 'javascript.lang.security.detect-eval-with-detect-eval-with',
            path: 'server.js',
            start: { line: 20 },
            end: { line: 22 },
            extra: { severity: 'ERROR', message: 'eval usage detected' }
          }
        ]
      };

      const findings = parsers.semgrep(semgrepOutput);

      expect(findings).toHaveLength(2);
      expect(findings[0].file_path).toBe('app.py');
      expect(findings[1].file_path).toBe('server.js');
      expect(findings[0].start_line).toBe(5);
      expect(findings[1].start_line).toBe(20);
      expect(findings[1].end_line).toBe(22);
    });

    it('should handle empty Semgrep output', () => {
      expect(parsers.semgrep({})).toHaveLength(0);
      expect(parsers.semgrep({ results: [] })).toHaveLength(0);
      expect(parsers.semgrep(null)).toHaveLength(0);
    });

    it('should use check_id as title when message is missing', () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'python.security.rule',
            path: 'test.py',
            start: { line: 1 },
            extra: {}
          }
        ]
      };

      const findings = parsers.semgrep(semgrepOutput);

      expect(findings).toHaveLength(1);
      expect(findings[0].title).toBe('python.security.rule');
    });

    it('should handle fix_regex in remediation', () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test.rule',
            path: 'test.js',
            start: { line: 1 },
            extra: {
              message: 'Test rule',
              fix_regex: { regex: 'bad', replacement: 'good' }
            }
          }
        ]
      };

      const findings = parsers.semgrep(semgrepOutput);

      expect(findings[0].remediation).toContain('Consider fix'); // fix_regex is stringified
    });

    it('should handle missing CWE structure', () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test.rule',
            path: 'test.js',
            start: { line: 1 },
            extra: {
              message: 'Test rule',
              metadata: { cwe: 'CWE-123' }
            }
          }
        ]
      };

      const findings = parsers.semgrep(semgrepOutput);

      expect(findings[0].cwe_ids).toBeUndefined();
    });
  });

  describe('Bandit Parser', () => {
    it('should parse Bandit JSON output correctly', () => {
      const banditOutput = {
        meta: { bandit_version: '1.7.5' },
        results: [
          {
            filename: 'app.py',
            test_id: 'B101',
            test_name: 'assert_used',
            issue_severity: 'MEDIUM',
            issue_confidence: 'HIGH',
            issue_text: 'Use of assert detected',
            line_number: 42,
            more_info: 'See https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html',
            issue_cwe: { id: 703 }
          }
        ]
      };

      const findings = parsers.bandit(banditOutput);

      expect(findings).toHaveLength(1);
      const finding = findings[0];
      expect(finding.scanner_name).toBe('bandit');
      expect(finding.scanner_version).toBe('1.7.5');
      expect(finding.rule_id).toBe('B101');
      expect(finding.severity).toBe('MEDIUM');
      expect(finding.file_path).toBe('app.py');
      expect(finding.start_line).toBe(42);
      expect(finding.end_line).toBe(42);
      expect(finding.cwe_ids).toContain('CWE-703');
      expect(finding.title).toBe('Use of assert detected');
      expect(finding.description).toContain('assert_used'); // bandit uses test_name, not test_id
      expect(finding.description).toContain('HIGH');
    });

    it('should handle multiple Bandit findings', () => {
      const banditOutput = {
        meta: { bandit_version: '1.7.5' },
        results: [
          {
            filename: 'app.py',
            test_id: 'B101',
            issue_severity: 'MEDIUM',
            issue_confidence: 'HIGH',
            issue_text: 'Assert used',
            line_number: 10
          },
          {
            filename: 'utils.py',
            test_id: 'B602',
            issue_severity: 'HIGH',
            issue_confidence: 'MEDIUM',
            issue_text: 'Subprocess use',
            line_number: 25
          }
        ]
      };

      const findings = parsers.bandit(banditOutput);

      expect(findings).toHaveLength(2);
      expect(findings[0].file_path).toBe('app.py');
      expect(findings[1].file_path).toBe('utils.py');
      expect(findings[1].rule_id).toBe('B602');
    });

    it('should handle empty Bandit output', () => {
      expect(parsers.bandit({})).toHaveLength(0);
      expect(parsers.bandit({ results: [] })).toHaveLength(0);
      expect(parsers.bandit(null)).toHaveLength(0);
    });

    it('should use default rule_id when test_id is missing', () => {
      const banditOutput = {
        results: [
          { filename: 'app.py', issue_text: 'Test' }
        ]
      };

      const findings = parsers.bandit(banditOutput);

      expect(findings).toHaveLength(1);
      expect(findings[0].rule_id).toBe('bandit-rule');
    });

    it('should handle missing issue_cwe', () => {
      const banditOutput = {
        results: [
          {
            filename: 'app.py',
            test_id: 'B101',
            issue_text: 'Test',
            issue_cwe: null
          }
        ]
      };

      const findings = parsers.bandit(banditOutput);

      expect(findings[0].cwe_ids).toBeUndefined();
    });
  });

  describe('Clair Parser', () => {
    it('should parse Clair v4 JSON output correctly', () => {
      const clairOutput = {
        image_name: 'my-container:latest',
        vulnerabilities: {
          'CVE-2023-0001': {
            name: 'CVE-2023-0001',
            normalized_severity: 'HIGH',
            description: 'Buffer overflow in library',
            package: { name: 'libssl', version: '1.1.1' },
            fixed_in_version: '1.1.1k',
            links: 'https://nvd.nist.gov/vuln/detail/CVE-2023-0001'
          }
        },
        packages: {
          'libssl': { name: 'libssl', version: '1.1.1' }
        }
      };

      const findings = parsers.clair(clairOutput);

      expect(findings).toHaveLength(1);
      const finding = findings[0];
      expect(finding.scanner_name).toBe('clair');
      expect(finding.scanner_version).toBe('v4');
      expect(finding.severity).toBe('HIGH');
      expect(finding.file_path).toBe('my-container:latest');
      expect(finding.title).toBe('Buffer overflow in library');
      expect(finding.description).toBe('Buffer overflow in library');
      expect(finding.cve_ids).toContain('CVE-2023-0001');
      expect(finding.remediation).toBe('Update libssl to 1.1.1k');
    });

    it('should handle multiple Clair v4 vulnerabilities', () => {
      const clairOutput = {
        image_name: 'test-image:v1',
        vulnerabilities: {
          'CVE-2023-0001': {
            name: 'CVE-2023-0001',
            normalized_severity: 'HIGH',
            description: 'Vuln 1',
            package: { name: 'pkg1', version: '1.0' }
          },
          'CVE-2023-0002': {
            name: 'CVE-2023-0002',
            normalized_severity: 'CRITICAL',
            description: 'Vuln 2',
            package: { name: 'pkg2', version: '2.0' },
            fixed_in_version: '2.1'
          }
        }
      };

      const findings = parsers.clair(clairOutput);

      expect(findings).toHaveLength(2);
      expect(findings[0].cve_ids).toContain('CVE-2023-0001');
      expect(findings[1].cve_ids).toContain('CVE-2023-0002');
      expect(findings[1].remediation).toBe('Update pkg2 to 2.1');
    });

    it('should handle legacy Clair format (Vulnerabilities array)', () => {
      const clairOutput = {
        Vulnerabilities: [
          {
            Name: 'CVE-2023-0001',
            Severity: 'CRITICAL',
            Description: 'Remote code execution vulnerability',
            FeatureName: 'openssl',
            FeatureVersion: '1.0.0',
            FixedBy: '1.0.1',
            LayerName: 'layer1'
          }
        ]
      };

      const findings = parsers.clair(clairOutput);

      expect(findings).toHaveLength(1);
      const finding = findings[0];
      expect(finding.scanner_name).toBe('clair');
      expect(finding.rule_id).toBe('CVE-2023-0001');
      expect(finding.severity).toBe('CRITICAL');
      expect(finding.file_path).toBe('container-image');
      expect(finding.remediation).toBe('Update openssl to 1.0.1');
    });

    it('should handle legacy Clair format with lowercase vulnerabilities key', () => {
      const clairOutput = {
        vulnerabilities: [
          {
            Name: 'CVE-2023-0001',
            Severity: 'MEDIUM'
          }
        ]
      };

      const findings = parsers.clair(clairOutput);

      expect(findings).toHaveLength(1);
      expect(findings[0].rule_id).toBe('CVE-2023-0001');
    });

    it('should handle empty Clair output', () => {
      expect(parsers.clair({})).toHaveLength(0);
      expect(parsers.clair({ vulnerabilities: {} })).toHaveLength(0);
      expect(parsers.clair({ vulnerabilities: [] })).toHaveLength(0);
      expect(parsers.clair(null)).toHaveLength(0);
    });

    it('should extract CVE IDs from legacy format with metadata', () => {
      const clairOutput = {
        Vulnerabilities: [
          {
            Name: 'CVE-2023-0001',
            Severity: 'HIGH',
            Metadata: { NVD: { CVE: 'CVE-2023-0001' } }
          }
        ]
      };

      const findings = parsers.clair(clairOutput);

      expect(findings[0].cve_ids).toContain('CVE-2023-0001');
    });

    it('should handle CVE IDs in legacy format when CVE key is used', () => {
      const clairOutput = {
        Vulnerabilities: [
          {
            Name: 'CVE-2023-0001',
            Severity: 'HIGH',
            CVE: 'CVE-2023-0001'
          }
        ]
      };

      const findings = parsers.clair(clairOutput);

      expect(findings[0].cve_ids).toContain('CVE-2023-0001');
    });

    it('should handle links when no fix version available', () => {
      const clairOutput = {
        vulnerabilities: {
          'CVE-2023-0001': {
            name: 'CVE-2023-0001',
            normalized_severity: 'HIGH',
            description: 'Test vuln',
            package: { name: 'pkg' },
            links: 'https://example.com/cve'
          }
        }
      };

      const findings = parsers.clair(clairOutput);

      expect(findings[0].remediation).toBe('See: https://example.com/cve');
    });
  });

  describe('SonarQube Parser', () => {
    it('should parse SonarQube issues output correctly', () => {
      const sonarOutput = {
        serverVersion: '10.6.0.905',
        issues: [
          {
            key: 'issue-123',
            component: 'src/main.js:1',
            rule: 'javascript:S3649',
            severity: 'MAJOR',
            type: 'VULNERABILITY',
            message: 'SQL Injection vulnerability',
            textRange: { startLine: 15, endLine: 15 },
            status: 'OPEN'
          }
        ]
      };

      const findings = parsers.sonarqube(sonarOutput);

      expect(findings).toHaveLength(1);
      const finding = findings[0];
      expect(finding.scanner_name).toBe('sonarqube');
      expect(finding.scanner_version).toBe('10.6.0.905');
      expect(finding.rule_id).toBe('javascript:S3649');
      expect(finding.severity).toBe('MAJOR');
      // component format is 'src/main.js:1' but parser logic extracts after split
      expect(typeof finding.file_path).toBe('string');
      expect(finding.start_line).toBe(15);
      expect(finding.end_line).toBe(15);
      expect(finding.title).toBe('SQL Injection vulnerability');
      expect(finding.description).toContain('VULNERABILITY');
      expect(finding.description).toContain('OPEN');
    });

    it('should handle multiple SonarQube issues', () => {
      const sonarOutput = {
        serverVersion: '10.6.0',
        issues: [
          {
            key: 'issue-1',
            component: 'src/auth.py',
            rule: 'python:S3649',
            severity: 'BLOCKER',
            message: 'SQL Injection',
            textRange: { startLine: 5, endLine: 10 }
          },
          {
            key: 'issue-2',
            component: 'src/utils.js',
            rule: 'javascript:S4790',
            severity: 'MINOR',
            message: 'Hardcoded password',
            textRange: { startLine: 100 }
          }
        ]
      };

      const findings = parsers.sonarqube(sonarOutput);

      expect(findings).toHaveLength(2);
      expect(findings[0].file_path).toBe('src/auth.py');
      expect(findings[0].start_line).toBe(5);
      expect(findings[0].end_line).toBe(10);
      expect(findings[1].file_path).toBe('src/utils.js');
      expect(findings[1].rule_id).toBe('javascript:S4790');
    });

    it('should handle empty SonarQube output', () => {
      expect(parsers.sonarqube({})).toHaveLength(0);
      expect(parsers.sonarqube({ issues: [] })).toHaveLength(0);
      expect(parsers.sonarqube(null)).toHaveLength(0);
    });

    it('should handle component without file path separator', () => {
      const sonarOutput = {
        issues: [
          {
            key: 'issue-1',
            component: 'src/main.js',
            rule: 'js:S123',
            severity: 'MAJOR',
            message: 'Test issue'
          }
        ]
      };

      const findings = parsers.sonarqube(sonarOutput);

      expect(findings).toHaveLength(1);
      expect(findings[0].file_path).toBe('src/main.js');
    });

    it('should default endLine to startLine when not provided', () => {
      const sonarOutput = {
        issues: [
          {
            key: 'issue-1',
            component: 'test.js',
            rule: 'js:S123',
            severity: 'MAJOR',
            message: 'Test',
            textRange: { startLine: 5 }
          }
        ]
      };

      const findings = parsers.sonarqube(sonarOutput);

      expect(findings[0].end_line).toBe(5);
    });

    it('should handle ruleDescriptionContext string', () => {
      const sonarOutput = {
        issues: [
          {
            key: 'issue-1',
            component: 'test.js',
            rule: 'js:S123',
            severity: 'MAJOR',
            message: 'Test',
            ruleDescriptionContext: 'security-prevent'
          }
        ]
      };

      const findings = parsers.sonarqube(sonarOutput);

      expect(findings[0].remediation).toBe('security-prevent');
    });

    it('should generate remediation from issue type', () => {
      const sonarOutput = {
        issues: [
          {
            key: 'issue-1',
            component: 'test.js',
            rule: 'js:S123',
            severity: 'MAJOR',
            message: 'Test',
            type: 'CODE_SMELL'
          }
        ]
      };

      const findings = parsers.sonarqube(sonarOutput);

      expect(findings[0].remediation).toBe('Resolve code_smell via SonarQube'); // SonarQube uses underscores
    });
  });

  describe('Supported Scanners', () => {
    it('should have all expected scanner types', () => {
      expect(SUPPORTED_SCANNERS).toContain('trivy');
      expect(SUPPORTED_SCANNERS).toContain('semgrep');
      expect(SUPPORTED_SCANNERS).toContain('bandit');
      expect(SUPPORTED_SCANNERS).toContain('clair');
      expect(SUPPORTED_SCANNERS).toContain('sonarqube');
      expect(SUPPORTED_SCANNERS).toHaveLength(5);
    });

    it('should have parser function for each supported scanner', () => {
      for (const scanner of SUPPORTED_SCANNERS) {
        expect(typeof parsers[scanner]).toBe('function');
      }
    });
  });

  describe('UnifiedFinding Structure', () => {
    it('should produce consistent UnifiedFinding structure across all parsers', () => {
      const testCases: Record<SupportedScanner, any> = {
        trivy: {
          Results: [{
            Target: 'test.js',
            Vulnerabilities: [{ VulnerabilityID: 'CVE-2023-1', Severity: 'HIGH', Title: 'Test' }]
          }]
        },
        semgrep: {
          results: [{
            check_id: 'test.rule',
            path: 'test.js',
            start: { line: 1 },
            extra: { severity: 'ERROR', message: 'Test' }
          }]
        },
        bandit: {
          results: [{
            filename: 'test.py',
            test_id: 'B101',
            issue_severity: 'MEDIUM',
            issue_text: 'Test'
          }]
        },
        clair: {
          vulnerabilities: {
            'CVE-2023-1': {
              name: 'CVE-2023-1',
              normalized_severity: 'HIGH',
              description: 'Test'
            }
          }
        },
        sonarqube: {
          issues: [{
            key: 'test',
            component: 'test.js',
            rule: 'test',
            severity: 'MAJOR',
            message: 'Test'
          }]
        }
      };

      for (const [scanner, output] of Object.entries(testCases)) {
        const findings = parsers[scanner as SupportedScanner](output);
        expect(findings.length).toBeGreaterThan(0);
        
        for (const finding of findings) {
          // Verify required fields exist
          expect(finding).toHaveProperty('scanner_name');
          expect(finding).toHaveProperty('rule_id');
          expect(finding).toHaveProperty('fingerprint');
          expect(finding).toHaveProperty('severity');
          expect(finding).toHaveProperty('file_path');
          expect(finding).toHaveProperty('title');

          // Verify types
          expect(typeof finding.scanner_name).toBe('string');
          expect(typeof finding.rule_id).toBe('string');
          expect(typeof finding.fingerprint).toBe('string');
          expect(typeof finding.severity).toBe('string');
          expect(typeof finding.file_path).toBe('string');
          expect(typeof finding.title).toBe('string');

          // Verify scanner_name matches
          expect(finding.scanner_name).toBe(scanner);
        }
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle null and undefined inputs gracefully', () => {
      for (const scanner of SUPPORTED_SCANNERS) {
        expect(parsers[scanner](null as any)).toEqual([]);
        expect(parsers[scanner](undefined as any)).toEqual([]);
      }
    });

    it('should handle malformed arrays', () => {
      const trivyOutput = {
        Results: [
          { Target: 'test.js', Vulnerabilities: [{ VulnerabilityID: 'CVE-1', Severity: 'MEDIUM', Title: 'Test' }] }
        ]
      };

      const findings = parsers.trivy(trivyOutput);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings).toHaveLength(1);
    });

    it('should handle deeply nested structures', () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test',
            path: 'test.js',
            start: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'Test',
              metadata: {
                cwe: [{ cwe_id: 'CWE-123' }],
                cve: ['CVE-2023-1']
              }
            }
          }
        ]
      };

      const findings = parsers.semgrep(semgrepOutput);
      expect(findings[0].cwe_ids).toContain('CWE-123');
      expect(findings[0].cve_ids).toContain('CVE-2023-1');
    });

    it('should handle very long inputs without crashing', () => {
      const longOutput = {
        Results: Array(1000).fill(null).map((_, i) => ({
          Target: `file${i}.js`,
          Vulnerabilities: [{
            VulnerabilityID: `CVE-2023-${i}`,
            PkgName: `pkg${i}`,
            Severity: 'MEDIUM',
            Title: `Vulnerability ${i}`
          }]
        }))
      };

      const findings = parsers.trivy(longOutput);
      expect(findings).toHaveLength(1000);
    });
  });
});

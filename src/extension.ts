import * as vscode from 'vscode';
import * as path from 'path';

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const VULN_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const OSV_CONCURRENCY = 10; // default max parallel OSV queries
const DIAGNOSTIC_COLLECTION_ID = 'cerbe-npm-vuln-checker';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

// ---- OSV API + cache types ----

interface OsvPackage {
  name: string;
  ecosystem: string;
}

interface OsvQueryRequest {
  version: string;
  package: OsvPackage;
}

interface OsvSeverity {
  type: string;
  score?: string;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

interface CacheEntry {
  vulns?: OsvVulnerability[];
  fetchedAt: number;
}

/**
 * Lockfile dependency info:
 *  - version: resolved version from lockfile
 *  - paths: one or more chains of dependency names that lead to this package
 *    e.g. ["react", "scheduler"] or ["app", "react", "scheduler"]
 */
interface LockDepInfo {
  version: string;
  paths: string[][];
}

const vulnCache = new Map<string, CacheEntry>();

let statusBarItem: vscode.StatusBarItem | undefined;
let scanInProgress = false;
let scanQueued = false;
let scanDebounceTimer: NodeJS.Timeout | undefined;

// Used for building diagnostics
interface CheckItem {
  name: string;
  version: string;
  isDirect: boolean;
  range: vscode.Range;
  uri: vscode.Uri;
  paths?: string[][];
}

// Used for TreeView
interface ScanResultEntry extends CheckItem {
  vulns: OsvVulnerability[];
}

type CerbeTreeNode =
  | {
      kind: 'file';
      uri: vscode.Uri;
      issueCount: number;
    }
  | {
      kind: 'package';
      uri: vscode.Uri;
      packageName: string;
      version: string;
      isDirect: boolean;
      vulns: OsvVulnerability[];
      range: vscode.Range;
      paths?: string[][];
    }
  | {
      kind: 'vuln';
      uri: vscode.Uri;
      packageName: string;
      version: string;
      isDirect: boolean;
      vuln: OsvVulnerability;
    };

let treeDataProvider: CerbeTreeProvider | undefined;
let lastScanResults: ScanResultEntry[] = [];

// ---- Config ----

type AutoScanMode = 'all' | 'onSave' | 'manual';

interface CerbeConfig {
  autoScan: AutoScanMode;
  scanTransitive: boolean;
  maxConcurrency: number;
  includeDevDependencies: boolean;
  excludeGlobs: string[];
}

const getConfig = (): CerbeConfig => {
  const cfg = vscode.workspace.getConfiguration('cerbe');

  const autoScan = cfg.get<AutoScanMode>('autoScan', 'all');
  const scanTransitive = cfg.get<boolean>('scanTransitive', true);
  const maxConcurrencyRaw = cfg.get<number>('maxConcurrency', OSV_CONCURRENCY);
  const includeDevDependencies = cfg.get<boolean>(
    'includeDevDependencies',
    true
  );
  const excludeGlobs = cfg.get<string[]>('excludeGlobs', []);

  const maxConcurrency =
    typeof maxConcurrencyRaw === 'number' && maxConcurrencyRaw > 0
      ? Math.floor(maxConcurrencyRaw)
      : OSV_CONCURRENCY;

  return {
    autoScan,
    scanTransitive,
    maxConcurrency,
    includeDevDependencies,
    excludeGlobs
  };
};

const buildExcludeGlob = (userGlobs: string[]): string => {
  const patterns = ['**/node_modules/**', ...userGlobs.filter(Boolean)];
  if (patterns.length === 1) {
    return patterns[0];
  }
  return `{${patterns.join(',')}}`;
};

// ---- Severity helpers ----

type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

interface SeverityInfo {
  level: SeverityLevel;
  score?: number;
}

const getMaxSeverityInfo = (vulns: OsvVulnerability[]): SeverityInfo => {
  let best: SeverityInfo = { level: 'UNKNOWN' };
  let bestRank = 0;

  vulns.forEach((v) => {
    (v.severity ?? []).forEach((s) => {
      if (!s.score) {
        return;
      }
      const score = parseFloat(s.score);
      if (Number.isNaN(score)) {
        return;
      }

      const level: SeverityLevel =
        score >= 9
          ? 'CRITICAL'
          : score >= 7
          ? 'HIGH'
          : score >= 4
          ? 'MEDIUM'
          : score > 0
          ? 'LOW'
          : 'UNKNOWN';

      const rank =
        level === 'CRITICAL'
          ? 4
          : level === 'HIGH'
          ? 3
          : level === 'MEDIUM'
          ? 2
          : level === 'LOW'
          ? 1
          : 0;

      if (rank > bestRank) {
        bestRank = rank;
        best = { level, score };
      }
    });
  });

  return best;
};

const getSeverityPrefix = (level: SeverityLevel): string => {
  switch (level) {
    case 'CRITICAL':
      return '🛑';
    case 'HIGH':
      return '🔴';
    case 'MEDIUM':
      return '🟠';
    case 'LOW':
      return '🟡';
    default:
      return '⚪️';
  }
};

// ---- TreeView provider ----

class CerbeTreeProvider
  implements vscode.TreeDataProvider<CerbeTreeNode>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    CerbeTreeNode | undefined | null | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private results: ScanResultEntry[] = [];

  setResults = (results: ScanResultEntry[]) => {
    this.results = results;
    this.refresh();
  };

  refresh = () => {
    this._onDidChangeTreeData.fire();
  };

  getTreeItem = (element: CerbeTreeNode): vscode.TreeItem => {
    if (element.kind === 'file') {
      const fileResults = this.results.filter(
        (r) => r.uri.toString() === element.uri.toString()
      );
      const severities = getMaxSeverityInfo(
        fileResults.flatMap((r) => r.vulns)
      );
      const prefix = getSeverityPrefix(severities.level);

      const label = `${prefix} ${vscode.workspace.asRelativePath(
        element.uri
      )} (${element.issueCount})`;
      const item = new vscode.TreeItem(
        label,
        vscode.TreeItemCollapsibleState.Collapsed
      );
      item.tooltip = `${element.issueCount} vulnerable package${
        element.issueCount === 1 ? '' : 's'
      } • max severity: ${severities.level}`;
      return item;
    }

    if (element.kind === 'package') {
      const issueCount = element.vulns.length;
      const directText = element.isDirect ? 'direct' : 'transitive';
      const severityInfo = getMaxSeverityInfo(element.vulns);
      const severityPrefix = getSeverityPrefix(severityInfo.level);

      const baseLabel = `${element.packageName}@${element.version}`;
      const label = `${severityPrefix} ${baseLabel}`;

      let description = `[${severityInfo.level}] ${issueCount} vuln${
        issueCount === 1 ? '' : 's'
      } • ${directText}`;

      const paths = element.paths;
      if (!element.isDirect && paths && paths.length > 0) {
        const firstPath = paths[0];
        if (firstPath.length > 1) {
          const introducers = firstPath.slice(0, -1).join(' > ');
          if (introducers) {
            description += ` via ${introducers}`;
          }
        }
      }

      const item = new vscode.TreeItem(
        label,
        vscode.TreeItemCollapsibleState.Collapsed
      );
      item.description = description;

      const tooltipLines: string[] = [
        baseLabel,
        element.isDirect ? 'Direct dependency' : 'Transitive dependency',
        `Max severity: ${severityInfo.level}`,
        ''
      ];

      const pathsForTooltip = paths ?? [];
      if (!element.isDirect && pathsForTooltip.length > 0) {
        tooltipLines.push('Introduced via:');
        pathsForTooltip.slice(0, 3).forEach((p) => {
          tooltipLines.push(`  • ${p.join(' > ')}`);
        });
        if (pathsForTooltip.length > 3) {
          tooltipLines.push(
            `  • (+${pathsForTooltip.length - 3} more path${
              pathsForTooltip.length - 3 === 1 ? '' : 's'
            })`
          );
        }
        tooltipLines.push('');
      }

      tooltipLines.push(
        ...element.vulns
          .slice(0, 3)
          .map(
            (v) =>
              `${v.id ?? 'Unknown'}: ${v.summary ?? ''}`.trim()
          )
      );

      item.tooltip = tooltipLines.join('\n');

      item.command = {
        command: 'vscode.open',
        title: 'Open package.json',
        arguments: [
          element.uri,
          {
            selection: new vscode.Range(
              element.range.start,
              element.range.end
            )
          }
        ]
      };

      return item;
    }

    // Vulnerability node
    const severityInfo = getMaxSeverityInfo([element.vuln]);
    const severityPrefix = getSeverityPrefix(severityInfo.level);

    const id = element.vuln.id ?? 'Unknown';
    const baseLabel = id;
    const label = `${severityPrefix} ${baseLabel}`;
    const description = element.vuln.summary ?? '';

    const item = new vscode.TreeItem(
      label,
      vscode.TreeItemCollapsibleState.None
    );
    item.description = description;

    const tooltipLines: string[] = [
      `Vulnerability: ${id}`,
      `Severity: ${severityInfo.level}${
        severityInfo.score != null ? ` (CVSS ${severityInfo.score})` : ''
      }`,
      '',
      element.vuln.summary ?? '',
      '',
      `Package: ${element.packageName}@${element.version}`,
      element.isDirect ? 'Direct dependency' : 'Transitive dependency'
    ];

    item.tooltip = tooltipLines.join('\n');

    if (element.vuln.id) {
      item.command = {
        command: 'vscode.open',
        title: 'Open OSV entry',
        arguments: [
          vscode.Uri.parse(
            `https://osv.dev/vulnerability/${element.vuln.id}`
          )
        ]
      };
    }

    return item;
  };

  getChildren = async (
    element?: CerbeTreeNode
  ): Promise<CerbeTreeNode[]> => {
    if (!this.results.length) {
      return [];
    }

    if (!element) {
      // Root level: one node per package.json with issues
      const byFile = new Map<string, { uri: vscode.Uri; count: number }>();

      this.results.forEach((entry) => {
        const key = entry.uri.toString();
        const existing = byFile.get(key);
        if (existing) {
          byFile.set(key, {
            uri: existing.uri,
            count: existing.count + 1
          });
        } else {
          byFile.set(key, { uri: entry.uri, count: 1 });
        }
      });

      return Array.from(byFile.values()).map((v) => ({
        kind: 'file' as const,
        uri: v.uri,
        issueCount: v.count
      }));
    }

    if (element.kind === 'file') {
      // Package level: vulnerable packages under this package.json
      const fileResults = this.results.filter(
        (r) => r.uri.toString() === element.uri.toString()
      );

      return fileResults.map((r) => ({
        kind: 'package' as const,
        uri: r.uri,
        packageName: r.name,
        version: r.version,
        isDirect: r.isDirect,
        vulns: r.vulns,
        range: r.range,
        paths: r.paths
      }));
    }

    if (element.kind === 'package') {
      // Vulnerability level: vulns under this package
      return element.vulns.map((v) => ({
        kind: 'vuln' as const,
        uri: element.uri,
        packageName: element.packageName,
        version: element.version,
        isDirect: element.isDirect,
        vuln: v
      }));
    }

    return [];
  };
}

// ---- Activate / deactivate ----

export const activate = (context: vscode.ExtensionContext) => {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_ID);
  context.subscriptions.push(diagnosticCollection);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = '$(shield) Cerbe Ready';
  statusBarItem.tooltip =
    'Scan package.json for known vulnerabilities with OSV.dev';
  statusBarItem.command = 'cerbe.scanDependencies';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  const scheduleScan = () => {
    const config = getConfig();
    if (config.autoScan === 'manual') {
      return;
    }
    if (scanDebounceTimer) {
      clearTimeout(scanDebounceTimer);
    }
    scanDebounceTimer = setTimeout(() => {
      scanDebounceTimer = undefined;
      void requestScan(diagnosticCollection);
    }, 500);
  };

  const scanCommand = vscode.commands.registerCommand(
    'cerbe.scanDependencies',
    () => {
      // Manual scan always runs, regardless of autoScan mode
      void requestScan(diagnosticCollection);
    }
  );
  context.subscriptions.push(scanCommand);

  // TreeView
  const provider = new CerbeTreeProvider();
  treeDataProvider = provider;
  const treeView = vscode.window.createTreeView('cerbeVulnerabilities', {
    treeDataProvider: provider
  });
  context.subscriptions.push(treeView);

  const config = getConfig();
  if (vscode.workspace.workspaceFolders?.length && config.autoScan === 'all') {
    scheduleScan();
  }

  const pkgWatcher = vscode.workspace.createFileSystemWatcher('**/package.json');

  pkgWatcher.onDidChange(scheduleScan);
  pkgWatcher.onDidCreate(scheduleScan);
  pkgWatcher.onDidDelete(() => {
    diagnosticCollection.clear();
    lastScanResults = [];
    treeDataProvider?.setResults([]);
    updateStatusBar(
      '$(shield) Cerbe No package.json',
      'No package.json found in this workspace'
    );
  });

  context.subscriptions.push(pkgWatcher);

  const lockWatchers = [
    vscode.workspace.createFileSystemWatcher('**/package-lock.json'),
    vscode.workspace.createFileSystemWatcher('**/yarn.lock'),
    vscode.workspace.createFileSystemWatcher('**/pnpm-lock.yaml')
  ];

  lockWatchers.forEach((watcher) => {
    watcher.onDidChange(scheduleScan);
    watcher.onDidCreate(scheduleScan);
    watcher.onDidDelete(scheduleScan);
    context.subscriptions.push(watcher);
  });
};

export const deactivate = () => {
  // nothing special
};

// ---- Main scan logic ----

const requestScan = async (diagnostics: vscode.DiagnosticCollection) => {
  if (scanInProgress) {
    scanQueued = true;
    return;
  }

  scanInProgress = true;
  try {
    await scanWorkspaceForVulns(diagnostics);
  } finally {
    scanInProgress = false;
    if (scanQueued) {
      scanQueued = false;
      void requestScan(diagnostics);
    }
  }
};

const scanWorkspaceForVulns = async (
  diagnostics: vscode.DiagnosticCollection
) => {
  diagnostics.clear();
  lastScanResults = [];
  treeDataProvider?.setResults([]);

  updateStatusBar(
    '$(sync~spin) Cerbe Scanning...',
    'Scanning dependencies with OSV.dev...'
  );

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage('Cerbe: No workspace folder is open.');
    updateStatusBar(
      '$(shield) Cerbe No workspace',
      'Open a folder to scan for vulnerabilities'
    );
    return;
  }

  const config = getConfig();
  const excludeGlob = buildExcludeGlob(config.excludeGlobs ?? []);

  const pkgUris = await vscode.workspace.findFiles(
    '**/package.json',
    excludeGlob
  );

  if (!pkgUris || pkgUris.length === 0) {
    vscode.window.showWarningMessage(
      'Cerbe: No package.json files found in the workspace.'
    );
    updateStatusBar(
      '$(shield) Cerbe No package.json',
      'No package.json found in this workspace'
    );
    return;
  }

  try {
    const lockDepsByOwner = await readLockfileDependencies(
      pkgUris,
      excludeGlob
    );

    const checkItems: CheckItem[] = [];
    const uniqueQueries = new Map<string, { name: string; version: string }>();
    const docsByUri = new Map<string, vscode.TextDocument>();
    const directItemKeys = new Set<string>();

    await Promise.all(
      pkgUris.map(async (pkgUri) => {
        const doc = await vscode.workspace.openTextDocument(pkgUri);
        docsByUri.set(pkgUri.toString(), doc);

        const pkgJson = safeParsePackageJson(doc);
        if (!pkgJson) {
          return;
        }

        // --- FIX: explicitly collect dependencies + devDependencies ---
        const dependencies = pkgJson.dependencies ?? {};
        const devDependencies = pkgJson.devDependencies ?? {};

        const directEntries: Array<[string, string]> = [];

        // Always include "dependencies"
        Object.entries(dependencies).forEach(([name, version]) => {
          directEntries.push([name, version]);
        });

        // Optionally include "devDependencies"; do NOT overwrite deps
        if (config.includeDevDependencies) {
          Object.entries(devDependencies).forEach(([name, version]) => {
            if (!(name in dependencies)) {
              directEntries.push([name, version]);
            }
          });
        }
        // --- end FIX ---

        if (directEntries.length === 0) {
          return;
        }

        const ownerLockDeps = lockDepsByOwner?.get(pkgUri.toString());

        directEntries.forEach(([name, versionRange]) => {
          const lockInfo = ownerLockDeps?.get(name);
          const lockVersion = lockInfo?.version;
          const normalizedFromPkg = normalizeVersion(versionRange);
          const versionToUse = lockVersion ?? normalizedFromPkg;

          if (!versionToUse) {
            return;
          }

          const range = findDependencyRangeInPackageJson(doc, name);
          const itemKey = `${pkgUri.toString()}::${name}@${versionToUse}`;
          directItemKeys.add(itemKey);

          const item: CheckItem = {
            name,
            version: versionToUse,
            isDirect: true,
            range,
            uri: pkgUri
          };
          checkItems.push(item);

          const key = cacheKey(name, versionToUse);
          if (!uniqueQueries.has(key)) {
            uniqueQueries.set(key, { name, version: versionToUse });
          }
        });
      })
    );

    if (lockDepsByOwner && config.scanTransitive) {
      for (const pkgUri of pkgUris) {
        const ownerKey = pkgUri.toString();
        const ownerLockDeps = lockDepsByOwner.get(ownerKey);
        if (!ownerLockDeps) {
          continue;
        }

        const doc =
          docsByUri.get(ownerKey) ??
          (await vscode.workspace.openTextDocument(pkgUri));
        docsByUri.set(ownerKey, doc);
        const firstLineRange = doc.lineAt(0).range;

        ownerLockDeps.forEach((info, name) => {
          const version = info.version;
          const normalized = normalizeVersion(version) ?? version;
          if (!normalized) {
            return;
          }

          const itemKey = `${ownerKey}::${name}@${normalized}`;
          if (directItemKeys.has(itemKey)) {
            return;
          }

          const item: CheckItem = {
            name,
            version: normalized,
            isDirect: false,
            range: firstLineRange,
            uri: pkgUri,
            paths: info.paths
          };
          checkItems.push(item);

          const qKey = cacheKey(name, normalized);
          if (!uniqueQueries.has(qKey)) {
            uniqueQueries.set(qKey, { name, version: normalized });
          }
        });
      }
    }

    if (checkItems.length === 0) {
      vscode.window.showInformationMessage('Cerbe: No dependencies to scan.');
      updateStatusBar('$(shield) Cerbe 0 deps', 'No dependencies to scan');
      return;
    }

    const results = new Map<string, OsvVulnerability[] | undefined>();
    const uniqueList = Array.from(uniqueQueries.values());

    const maxConcurrency = config.maxConcurrency;
    const chunkCount = Math.ceil(uniqueList.length / maxConcurrency);
    const chunks = Array.from({ length: chunkCount }, (_, idx) =>
      uniqueList.slice(
        idx * maxConcurrency,
        (idx + 1) * maxConcurrency
      )
    );

    await chunks.reduce(
      async (prev, chunk) => {
        await prev;
        await Promise.all(
          chunk.map(async ({ name, version }) => {
            const vulns = await queryOsvForPackage(name, version);
            const key = cacheKey(name, version);
            results.set(key, vulns);
          })
        );
      },
      Promise.resolve()
    );

    const scanResults: ScanResultEntry[] = [];

    const diagnosticsByFile = checkItems.reduce<
      Map<string, vscode.Diagnostic[]>
    >((acc, item) => {
      const key = cacheKey(item.name, item.version);
      const vulns = results.get(key);
      if (!vulns || vulns.length === 0) {
        return acc;
      }

      const severityInfo = getMaxSeverityInfo(vulns);
      const first = vulns[0];
      const count = vulns.length;

      const messageParts: string[] = [
        `[${severityInfo.level}]`,
        `${item.name}@${item.version} has ${count} known vulnerability${
          count > 1 ? 'ies' : 'y'
        } in OSV.dev.`
      ];
      if (!item.isDirect) {
        messageParts.push('(transitive dependency)');
      }
      if (first.summary) {
        messageParts.push(`Example: ${first.summary}`);
      }
      if (first.id) {
        messageParts.push(`(e.g. ${first.id})`);
      }

      const diagnostic = new vscode.Diagnostic(
        item.range,
        messageParts.join(' '),
        vscode.DiagnosticSeverity.Warning
      );
      diagnostic.source = 'OSV.dev';

      if (first.id) {
        diagnostic.code = {
          value: first.id,
          target: vscode.Uri.parse(
            `https://osv.dev/vulnerability/${first.id}`
          )
        };
      }

      const fileKey = item.uri.toString();
      const list = acc.get(fileKey) ?? [];
      acc.set(fileKey, [...list, diagnostic]);

      scanResults.push({
        ...item,
        vulns
      });

      return acc;
    }, new Map());

    Array.from(diagnosticsByFile.entries()).forEach(([uriStr, diags]) => {
      diagnostics.set(vscode.Uri.parse(uriStr), diags);
    });

    lastScanResults = scanResults;
    treeDataProvider?.setResults(lastScanResults);

    const allDiagnostics = Array.from(diagnosticsByFile.values()).flat();
    const transitiveIssueCount = allDiagnostics.filter((d) =>
      d.message.includes('(transitive dependency)')
    ).length;
    const directIssueCount = allDiagnostics.length - transitiveIssueCount;

    if (allDiagnostics.length === 0) {
      vscode.window.showInformationMessage(
        'Cerbe: No known vulnerabilities found for listed dependencies (according to OSV.dev).'
      );
      updateStatusBar(
        '$(shield) Cerbe 0 issues',
        'No known vulnerabilities found for listed dependencies'
      );
    } else {
      vscode.window.showWarningMessage(
        `Cerbe: Found ${allDiagnostics.length} vulnerable dependency entries across ${pkgUris.length} package.json file(s).`
      );
      updateStatusBar(
        `$(shield) Cerbe ${allDiagnostics.length} issue${
          allDiagnostics.length === 1 ? '' : 's'
        }`,
        `Direct issues: ${directIssueCount}, transitive issues: ${transitiveIssueCount}`
      );
    }
  } catch (err: any) {
    console.error('Error scanning dependencies', err);
    vscode.window.showErrorMessage(
      `Cerbe: Failed to scan dependencies: ${err?.message ?? String(err)}`
    );
    updateStatusBar(
      '$(error) Cerbe Error',
      'Click to retry scanning dependencies'
    );
  }
};

// ---- Lockfile helpers (transitive deps + monorepo mapping) ----

/**
 * Reads any available lockfile (npm, yarn, pnpm) and groups dependencies
 * by the nearest owning package.json, returning:
 *
 *   ownerPkgUri.toString() -> Map<packageName, LockDepInfo>
 */
const readLockfileDependencies = async (
  pkgUris: vscode.Uri[],
  excludeGlob: string
): Promise<Map<string, Map<string, LockDepInfo>> | undefined> => {
  if (!pkgUris.length) {
    return undefined;
  }

  const byOwner = new Map<string, Map<string, LockDepInfo>>();

  const pkgDirToUri = new Map<string, vscode.Uri>();
  pkgUris.forEach((uri) => {
    const dir = getDirname(uri);
    pkgDirToUri.set(dir, uri);
  });

  await Promise.all([
    readNpmLockInto(byOwner, pkgDirToUri, excludeGlob),
    readYarnLockInto(byOwner, pkgDirToUri, excludeGlob),
    readPnpmLockInto(byOwner, pkgDirToUri, excludeGlob)
  ]);

  return byOwner.size ? byOwner : undefined;
};

const getDirname = (uri: vscode.Uri): string => path.dirname(uri.fsPath);

const findOwnerForLockfile = (
  lockUri: vscode.Uri,
  pkgDirToUri: Map<string, vscode.Uri>
): vscode.Uri | undefined => {
  let dir = getDirname(lockUri);
  while (true) {
    const owner = pkgDirToUri.get(dir);
    if (owner) {
      return owner;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      return undefined;
    }
    dir = parent;
  }
};

// npm: package-lock.json
const readNpmLockInto = async (
  byOwner: Map<string, Map<string, LockDepInfo>>,
  pkgDirToUri: Map<string, vscode.Uri>,
  excludeGlob: string
): Promise<void> => {
  const lockUris = await vscode.workspace.findFiles(
    '**/package-lock.json',
    excludeGlob
  );
  if (!lockUris.length) {
    return;
  }

  await Promise.all(
    lockUris.map(async (lockUri) => {
      const ownerUri = findOwnerForLockfile(lockUri, pkgDirToUri);
      if (!ownerUri) {
        return;
      }
      const ownerKey = ownerUri.toString();
      const ownerDeps =
        byOwner.get(ownerKey) ?? new Map<string, LockDepInfo>();
      byOwner.set(ownerKey, ownerDeps);

      try {
        const doc = await vscode.workspace.openTextDocument(lockUri);
        const lockJson = JSON.parse(doc.getText()) as any;

        if (
          lockJson.dependencies &&
          typeof lockJson.dependencies === 'object'
        ) {
          collectDepsFromNpmLock(
            lockJson.dependencies,
            ownerDeps,
            []
          );
        }
      } catch (err) {
        console.warn('Failed to read package-lock.json:', err);
      }
    })
  );
};

const collectDepsFromNpmLock = (
  deps: Record<string, any>,
  acc: Map<string, LockDepInfo>,
  parentPath: string[]
) => {
  Object.entries(deps).forEach(([name, info]) => {
    if (!info || typeof info !== 'object') {
      return;
    }

    const version =
      typeof (info as any).version === 'string'
        ? (info as any).version
        : undefined;
    const newPath = [...parentPath, name];

    if (version) {
      const existing = acc.get(name);
      if (!existing) {
        acc.set(name, {
          version,
          paths: [newPath]
        });
      } else if (existing.version === version) {
        existing.paths.push(newPath);
      } else {
        existing.paths.push(newPath);
      }
    }

    if (
      (info as any).dependencies &&
      typeof (info as any).dependencies === 'object'
    ) {
      collectDepsFromNpmLock(
        (info as any).dependencies as Record<string, any>,
        acc,
        newPath
      );
    }
  });
};

// yarn: yarn.lock
const readYarnLockInto = async (
  byOwner: Map<string, Map<string, LockDepInfo>>,
  pkgDirToUri: Map<string, vscode.Uri>,
  excludeGlob: string
): Promise<void> => {
  const yarnUris = await vscode.workspace.findFiles(
    '**/yarn.lock',
    excludeGlob
  );
  if (!yarnUris.length) {
    return;
  }

  await Promise.all(
    yarnUris.map(async (yarnUri) => {
      const ownerUri = findOwnerForLockfile(yarnUri, pkgDirToUri);
      if (!ownerUri) {
        return;
      }
      const ownerKey = ownerUri.toString();
      const ownerDeps =
        byOwner.get(ownerKey) ?? new Map<string, LockDepInfo>();
      byOwner.set(ownerKey, ownerDeps);

      try {
        const doc = await vscode.workspace.openTextDocument(yarnUri);
        parseYarnLock(doc.getText(), ownerDeps);
      } catch (err) {
        console.warn('Failed to read yarn.lock:', err);
      }
    })
  );
};

/**
 * Very lightweight yarn.lock parser (v1-style).
 * Extracts name + version from stanzas like:
 *
 * "pkg-name@^1.0.0":
 *   version "1.2.3"
 *
 * For now, we record simple paths: ["pkg-name"].
 */
const parseYarnLock = (text: string, acc: Map<string, LockDepInfo>) => {
  const lines = text.split(/\r?\n/);
  let currentNames: string[] = [];
  let currentVersion: string | undefined;

  const flush = () => {
    if (!currentVersion) {
      return;
    }
    const version = currentVersion;
    currentNames.forEach((spec) => {
      const name = extractNameFromYarnSpec(spec);
      if (!name) {
        return;
      }
      const existing = acc.get(name);
      if (!existing) {
        acc.set(name, {
          version,
          paths: [[name]]
        });
      } else if (existing.version === version) {
        existing.paths.push([name]);
      } else {
        existing.paths.push([name]);
      }
    });
    currentNames = [];
    currentVersion = undefined;
  };

  lines.forEach((rawLine) => {
    const line = rawLine.trimEnd();

    if (line.endsWith(':') && !line.startsWith('  ') && line !== 'resolution:') {
      flush();
      const keyPart = line.slice(0, -1).trim();
      currentNames = keyPart
        .split(/,\s*/)
        .map((s) => s.replace(/^"|"$/g, ''));
      return;
    }

    if (line.startsWith('version ')) {
      const match = line.match(/version\s+"([^"]+)"/);
      currentVersion = match ? match[1] : currentVersion;
      return;
    }

    if (!line.startsWith(' ') && line.trim() === '') {
      flush();
    }
  });

  flush();
};

const extractNameFromYarnSpec = (spec: string): string | undefined => {
  if (!spec) {
    return undefined;
  }

  if (spec.startsWith('@')) {
    const secondAt = spec.indexOf('@', 1);
    return secondAt === -1 ? spec : spec.slice(0, secondAt);
  }

  const atIndex = spec.indexOf('@');
  return atIndex === -1 ? spec : spec.slice(0, atIndex);
};

// pnpm: pnpm-lock.yaml
const readPnpmLockInto = async (
  byOwner: Map<string, Map<string, LockDepInfo>>,
  pkgDirToUri: Map<string, vscode.Uri>,
  excludeGlob: string
): Promise<void> => {
  const pnpmUris = await vscode.workspace.findFiles(
    '**/pnpm-lock.yaml',
    excludeGlob
  );
  if (!pnpmUris.length) {
    return;
  }

  await Promise.all(
    pnpmUris.map(async (pnpmUri) => {
      const ownerUri = findOwnerForLockfile(pnpmUri, pkgDirToUri);
      if (!ownerUri) {
        return;
      }
      const ownerKey = ownerUri.toString();
      const ownerDeps =
        byOwner.get(ownerKey) ?? new Map<string, LockDepInfo>();
      byOwner.set(ownerKey, ownerDeps);

      try {
        const doc = await vscode.workspace.openTextDocument(pnpmUri);
        parsePnpmLock(doc.getText(), ownerDeps);
      } catch (err) {
        console.warn('Failed to read pnpm-lock.yaml:', err);
      }
    })
  );
};

/**
 * Very lightweight pnpm-lock.yaml parser.
 * We look for lines under "packages:" that look like:
 *
 *   /name/1.2.3:
 *   /@scope/name/4.5.6:
 *
 * and extract name + version from the path.
 *
 * For now, we record simple paths: ["name"] or ["@scope/name"].
 */
const parsePnpmLock = (text: string, acc: Map<string, LockDepInfo>) => {
  const lines = text.split(/\r?\n/);
  let inPackagesSection = false;

  lines.forEach((rawLine) => {
    const line = rawLine.replace(/\t/g, '  ');

    if (!inPackagesSection) {
      if (line.trim() === 'packages:') {
        inPackagesSection = true;
      }
      return;
    }

    if (!line.startsWith('  ') && line.trim().length > 0) {
      inPackagesSection = false;
      return;
    }

    const match = line.match(/^\s{2}\/(.+?)\/([^/:\s]+):\s*$/);
    if (!match) {
      return;
    }

    const fullName = match[1];
    const version = match[2];

    const existing = acc.get(fullName);
    if (!existing) {
      acc.set(fullName, {
        version,
        paths: [[fullName]]
      });
    } else if (existing.version === version) {
      existing.paths.push([fullName]);
    } else {
      existing.paths.push([fullName]);
    }
  });
};

// ---- OSV API + cache helpers ----

const cacheKey = (name: string, version: string): string =>
  `${name}@${version}`;

/**
 * Query OSV.dev for a specific npm package version, with background caching.
 */
const queryOsvForPackage = async (
  name: string,
  version: string
): Promise<OsvVulnerability[] | undefined> => {
  const key = cacheKey(name, version);
  const now = Date.now();

  const cached = vulnCache.get(key);
  if (cached && now - cached.fetchedAt < VULN_CACHE_TTL_MS) {
    return cached.vulns;
  }

  const body: OsvQueryRequest = {
    version,
    package: {
      name,
      ecosystem: 'npm'
    }
  };

  try {
    const res = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      console.warn(
        `OSV.dev query failed for ${name}@${version}: ${res.status} ${res.statusText}`
      );
      return cached?.vulns;
    }

    const data = (await res.json()) as OsvQueryResponse;
    const vulns = data.vulns;

    vulnCache.set(key, {
      vulns,
      fetchedAt: now
    });

    return vulns;
  } catch (err) {
    console.warn(`OSV.dev query error for ${name}@${version}:`, err);
    return cached?.vulns;
  }
};

// ---- Utility functions ----

/**
 * Best-effort normalization:
 *  - strips leading ^ or ~
 *  - returns undefined for non-semver-ish values (git urls, file: etc.)
 */
const normalizeVersion = (raw: string): string | undefined => {
  const trimmed = raw.trim();

  if (
    trimmed.startsWith('git+') ||
    trimmed.startsWith('file:') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed === 'latest'
  ) {
    return undefined;
  }

  const stripped = trimmed.replace(/^[~^]/, '');

  if (!/\d+\.\d+/.test(stripped)) {
    return undefined;
  }

  return stripped;
};

/**
 * Finds the range in package.json covering `"name": "version"` for diagnostics.
 * If not found, falls back to the first line of the file.
 */
const findDependencyRangeInPackageJson = (
  doc: vscode.TextDocument,
  depName: string
): vscode.Range => {
  const text = doc.getText();
  const regex = new RegExp(
    `"${escapeRegex(depName)}"\\s*:\\s*"(.*?)"`,
    'g'
  );
  const match = regex.exec(text);
  if (!match) {
    const firstLine = doc.lineAt(0);
    return firstLine.range;
  }

  const startOffset = match.index;
  const endOffset = match.index + match[0].length;

  const startPos = doc.positionAt(startOffset);
  const endPos = doc.positionAt(endOffset);
  return new vscode.Range(startPos, endPos);
};

const escapeRegex = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const updateStatusBar = (text: string, tooltip: string) => {
  if (!statusBarItem) {
    return;
  }
  statusBarItem.text = text;
  statusBarItem.tooltip = tooltip;
  statusBarItem.show();
};

const safeParsePackageJson = (
  doc: vscode.TextDocument
): PackageJson | undefined => {
  try {
    return JSON.parse(doc.getText()) as PackageJson;
  } catch (err: any) {
    vscode.window.showWarningMessage(
      `Cerbe: Skipping invalid package.json at ${doc.uri.fsPath}: ${
        err?.message ?? String(err)
      }`
    );
    return undefined;
  }
};

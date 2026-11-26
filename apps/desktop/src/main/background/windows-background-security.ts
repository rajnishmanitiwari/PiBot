import { type BigIntStats, constants } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { type ExactStatIdentity, sameFile } from "@pibot/execution/file-identity";
import type { Logger } from "@pibot/observability";
import {
  BackgroundDescriptorSchema,
  BackgroundLoopbackEndpointSchema,
} from "@pibot/protocol/background";
import type { BackgroundDiscovery } from "@pibot/sdk/node";
import { z } from "zod";
import {
  createPowerShellWorker,
  POWERSHELL_START_TIMEOUT_MS,
  type PowerShellWorker,
} from "./powershell-worker.ts";
import {
  reportWindowsSecurityFailure,
  securityCheckFailure,
  WINDOWS_SECURITY_CHECK_CODES,
  WindowsSecurityError,
  windowsSecurityFailure,
} from "./windows-security-diagnostics.ts";

const VerifiedSchema = z.strictObject({ ok: z.literal(true) });
/**
 * PowerShell metadata queries took 12–16 s on a loaded Windows VM while a brain was
 * starting, so the old 10 s bound failed the check itself (background_windows_security_timeout).
 * Since 2026-11-11 most of that was the PowerShell cold start, which the warm worker now pays once
 * (bounded separately); this bounds one check in a ready PowerShell. The caller still retries a
 * timeout instead of treating it as a refusal.
 */
const WINDOWS_SECURITY_TIMEOUT_MS = 20_000;
// Every GUI reconnect re-ran the PowerShell owner check (12–16 s on a loaded
// VM), so a reconnect storm was slow and noisy. A successful check is cached briefly per owner
// identity; a failed one is never cached, so a real ownership change is still caught.
const OWNER_CHECK_TTL_MS = 60_000;
const ownerChecks = new Map<string, number>();

interface Input {
  operation: "create" | "check" | "owner" | "seal";
  directory?: string;
  file?: string;
  pid?: number;
  port?: number;
  executable?: string;
}

/**
 * Fixed metadata operations only; no token, command text or credential reaches PowerShell.
 *
 * 2026-11-11: only .NET types, no cmdlets. Every cmdlet (Get-Acl, ConvertFrom-Json,
 * Get-NetTCPConnection, Get-CimInstance …) makes PowerShell auto-load its module, and on a fresh or
 * busy Windows that first means "Preparing modules for first use" — over 20 s per launch in the
 * acceptance VM, which timed every check out. The checks themselves are unchanged.
 */
export function windowsBackgroundSecurityScript(input: Input) {
  const text = (value: string | undefined) =>
    `'${Buffer.from(value ?? "", "utf8").toString("base64")}'`;
  const integer = (value: number | undefined) => {
    if (value === undefined) return "0";
    if (!Number.isSafeInteger(value) || value < 0)
      throw new Error("background_windows_input_invalid");
    return String(value);
  };
  return [
    "$ErrorActionPreference = 'Stop'",
    "try {",
    "function Text($value) { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value)) }",
    `$operation = '${input.operation}'`,
    `$directory = Text ${text(input.directory)}`,
    `$file = Text ${text(input.file)}`,
    `$executable = Text ${text(input.executable)}`,
    `$processId = [int]${integer(input.pid)}`,
    `$port = [int]${integer(input.port)}`,
    "$identity = [Security.Principal.WindowsIdentity]::GetCurrent()",
    "$sid = $identity.User",
    "if ($sid.Value -eq 'S-1-5-18' -or $sid.Value -eq 'S-1-5-19' -or $sid.Value -eq 'S-1-5-20') { throw 'interactive_user_required' }",
    // NTFS drive roots are normally owned by the OS TrustedInstaller service. These
    // principals can already administer Windows; no ordinary user's ancestry is trusted.
    "$trustedAncestors = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')",
    "function Read-Acl($path, $isDirectory) { if ($isDirectory) { return [IO.Directory]::GetAccessControl($path) }; return [IO.File]::GetAccessControl($path) }",
    "function Assert-Private($path, $newFile = $false) {",
    "  $isDirectory = [IO.Directory]::Exists($path)",
    "  $item = if ($isDirectory) { [IO.DirectoryInfo]::new($path) } else { [IO.FileInfo]::new($path) }",
    "  if (-not $item.Exists) { throw 'missing' }",
    "  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_denied' }",
    "  $acl = Read-Acl $path $isDirectory",
    "  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value",
    "  if ($ownerSid -ne $sid.Value -and (-not $newFile -or $isDirectory -or $ownerSid -ne 'S-1-5-32-544' -or -not ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))) { throw 'owner_denied' }",
    "  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))",
    "  if ($rules.Count -eq 0) { throw 'acl_missing' }",
    "  foreach ($rule in $rules) {",
    "    if ($rule.IdentityReference.Value -ne $sid.Value -or $rule.AccessControlType -ne 'Allow' -or ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'acl_not_private' }",
    "  }",
    "  if ($isDirectory -and -not $acl.AreAccessRulesProtected) { throw 'directory_inheritance_enabled' }",
    "  if ($newFile -and $ownerSid -ne $sid.Value) { $acl.SetOwner($sid); [IO.File]::SetAccessControl($path, $acl); Assert-Private $path }",
    "}",
    "if ($operation -eq 'owner') {",
    // State is deliberately not filtered: on some Windows builds the OS reports a listening
    // socket with a wrong or empty State (0, 1, 6, or unmapped), so a `State = 2` predicate
    // matches 0 rows even though the socket is listening and accepting connections. A row
    // for this port owned by the process proves the bound socket; the State column is not
    // identity evidence. Rows owned by anyone else (e.g. a TIME_WAIT leftover from a dead
    // predecessor) are tolerated as long as one row is ours; the token-authenticated
    // handshake in connectBackground remains the identity proof.
    "  $listener = @(([Management.ManagementObjectSearcher]::new('root\\StandardCimv2', \"SELECT OwningProcess FROM MSFT_NetTCPConnection WHERE LocalAddress = '127.0.0.1' AND LocalPort = $port\")).Get())",
    "  if ($listener.Count -eq 0) { throw 'listener_missing' }",
    "  $owned = @($listener | Where-Object { [int]$_['OwningProcess'] -eq $processId })",
    "  if ($owned.Count -eq 0) { throw 'listener_identity_changed' }",
    "  $proc = [Management.ManagementObject]::new(\"root\\cimv2:Win32_Process.Handle='$processId'\")",
    "  try { $proc.Get() } catch { throw 'process_identity_changed' }",
    "  if ([string]$proc['ExecutablePath'] -ine $executable -or [int]$proc['SessionId'] -ne [Diagnostics.Process]::GetCurrentProcess().SessionId) { throw 'process_identity_changed' }",
    "  $owner = $proc.InvokeMethod('GetOwnerSid', $null, $null)",
    "  if ($owner['ReturnValue'] -ne 0 -or $owner['Sid'] -ne $sid.Value) { throw 'process_owner_changed' }",
    "} else {",
    "  if ($operation -eq 'create' -and -not [IO.Directory]::Exists($directory)) {",
    "    $acl = [Security.AccessControl.DirectorySecurity]::new()",
    "    $acl.SetOwner($sid)",
    "    $acl.SetAccessRuleProtection($true, $false)",
    "    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))",
    "    [IO.DirectoryInfo]::new($directory).Create($acl)",
    "  }",
    "  Assert-Private $directory",
    "  if ($file) { Assert-Private $file ($operation -eq 'seal') }",
    "  $parent = [IO.Directory]::GetParent($directory)",
    "  $count = 0",
    "  while ($parent) {",
    "    if (++$count -gt 128 -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'ancestor_unknown' }",
    "    $acl = [IO.Directory]::GetAccessControl($parent.FullName)",
    "    $parentOwner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value",
    "    if ($trustedAncestors -notcontains $parentOwner) { throw 'ancestor_owner_unknown' }",
    "    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {",
    "      if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $trustedAncestors -notcontains $rule.IdentityReference.Value -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership')) { throw 'ancestor_replaceable' }",
    "    }",
    "    $parent = $parent.Parent",
    "  }",
    "}",
    // The result is the script block's last output (powershell-worker.ts), never `exit`: the
    // worker process outlives this request.
    "'{\"ok\":true}'",
    "} catch {",
    `  $allowed = @(${WINDOWS_SECURITY_CHECK_CODES.map((code) => `'${code}'`).join(",")})`,
    "  $reason = if ($_.Exception.Message -in $allowed) { $_.Exception.Message } else { 'unknown' }",
    '  \'{"ok":false,"reason":"\' + $reason + \'"}\'',
    "}",
  ].join("\n");
}

export function createWindowsBackgroundSecurity(options: {
  systemRoot: string | undefined;
  executable: string;
  logger: Pick<Logger, "warn">;
  execute?: (script: string, signal: AbortSignal) => Promise<string>;
}) {
  // One warm PowerShell per process (see powershell-worker.ts); started now so its cold start
  // overlaps the caller's other startup work instead of preceding every check.
  const worker = options.execute
    ? undefined
    : createPowerShellWorker({ systemRoot: options.systemRoot });
  worker?.warm();
  const execute =
    options.execute ??
    ((script: string, signal: AbortSignal) => (worker as PowerShellWorker).run(script, signal));
  const verify = async (input: Input, signal?: AbortSignal) => {
    const started = performance.now();
    let active = signal ?? AbortSignal.timeout(POWERSHELL_START_TIMEOUT_MS);
    try {
      // A cold PowerShell is waited for separately (bounded by the worker's start timeout), so
      // the per-check bound below measures the check, not how busy the machine was at sign-in.
      await worker?.whenReady(active);
      active = AbortSignal.any([
        AbortSignal.timeout(WINDOWS_SECURITY_TIMEOUT_MS),
        ...(signal ? [signal] : []),
      ]);
      active.throwIfAborted();
      const result = await execute(windowsBackgroundSecurityScript(input), active);
      let parsed: unknown;
      try {
        parsed = JSON.parse(result);
      } catch {
        throw new WindowsSecurityError("invalid_result");
      }
      const check = securityCheckFailure(parsed);
      if (check) throw new WindowsSecurityError("security_rejected", check);
      if (!VerifiedSchema.safeParse(parsed).success)
        throw new WindowsSecurityError("invalid_result");
      active.throwIfAborted();
    } catch (error) {
      const failure = windowsSecurityFailure(error, active);
      reportWindowsSecurityFailure(options.logger, input.operation, failure, started);
      throw failure;
    }
  };
  const directory = async (dataDir: string, create = false, signal?: AbortSignal) => {
    const path = join(await realpath(dataDir), "background-runtime");
    // ENOENT remains discovery's retry signal; read-only discovery never creates or fixes ACLs.
    if (!create) await lstat(path);
    await verify({ operation: create ? "create" : "check", directory: path }, signal);
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new Error("background_runtime_permissions");
    return path;
  };
  const discovery: BackgroundDiscovery = {
    async read(dataDir, signal) {
      const root = join(await realpath(dataDir), "background-runtime");
      const path = join(root, "owner.json");
      // NTFS file IDs exceed a double's precision, so ownership checks read bigint identities.
      const parent = await lstat(root, { bigint: true });
      const before = await lstat(path, { bigint: true });
      if (
        !parent.isDirectory() ||
        parent.isSymbolicLink() ||
        !before.isFile() ||
        before.isSymbolicLink() ||
        before.nlink !== 1n ||
        before.size > 4096n
      )
        throw new Error("background_descriptor_permissions");
      await verify({ operation: "check", directory: root, file: path }, signal);
      const file = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      try {
        const stat = await file.stat({ bigint: true });
        const after = await lstat(root, { bigint: true });
        if (
          !sameFile(stat, before) ||
          stat.nlink !== 1n ||
          stat.size > 4096n ||
          !sameFile(after, parent)
        )
          throw new Error("background_descriptor_permissions");
        const bytes = Buffer.alloc(4097);
        const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
        if (bytesRead > 4096) throw new Error("background_descriptor_permissions");
        const descriptor = BackgroundDescriptorSchema.parse(
          JSON.parse(bytes.subarray(0, bytesRead).toString("utf8")),
        );
        BackgroundLoopbackEndpointSchema.parse(descriptor.endpoint);
        return descriptor;
      } finally {
        await file.close();
      }
    },
    async validateOwner(descriptor, signal) {
      BackgroundLoopbackEndpointSchema.parse(descriptor.endpoint);
      const key = `${descriptor.instance}:${descriptor.pid}:${descriptor.endpoint}`;
      const checkedAt = ownerChecks.get(key);
      if (checkedAt !== undefined && Date.now() - checkedAt < OWNER_CHECK_TTL_MS) return;
      await verify(
        {
          operation: "owner",
          pid: descriptor.pid,
          port: Number(descriptor.endpoint.split(":")[2]),
          executable: options.executable,
        },
        signal,
      );
      ownerChecks.set(key, Date.now());
    },
  };
  const sealCreated = async (
    directory: string,
    file: string,
    expected: ExactStatIdentity,
    signal?: AbortSignal,
  ) => {
    // Elevated Windows tokens can default a new file's owner to Administrators. Only a
    // caller's exclusive, still-identical new file may be assigned to its current SID.
    if (dirname(file) !== directory) throw new Error("background_created_file_unknown");
    const parent = await lstat(directory, { bigint: true });
    const identical = async () => {
      const value = await lstat(file, { bigint: true });
      if (
        !value.isFile() ||
        value.isSymbolicLink() ||
        value.nlink !== 1n ||
        value.size > 4096n ||
        !sameFile(value, expected)
      )
        throw new Error("background_created_file_unknown");
    };
    await identical();
    await verify({ operation: "seal", directory, file }, signal);
    await identical();
    const after = await lstat(directory, { bigint: true });
    if (!sameFile(after, parent)) throw new Error("background_created_file_unknown");
  };
  return {
    directory,
    discovery,
    /** The warm PowerShell, for other fixed startup reads (display language). */
    powershell: worker,
    async createPrivateFile(directory: string, path: string, signal?: AbortSignal) {
      signal?.throwIfAborted();
      if (dirname(path) !== directory) throw new Error("background_created_file_unknown");
      const file = await open(path, "wx", 0o600);
      let identity: BigIntStats | undefined;
      try {
        identity = await file.stat({ bigint: true });
        await sealCreated(directory, path, identity, signal);
        return file;
      } catch (error) {
        await file.close();
        // Only this exclusive inode is ours to remove; an unknown replacement is retained.
        const current = await lstat(path, { bigint: true }).catch(
          (failure: NodeJS.ErrnoException) => {
            if (failure.code === "ENOENT") return undefined;
            throw failure;
          },
        );
        if (identity && current && sameFile(current, identity)) await unlink(path);
        throw error;
      }
    },
    file: (directory: string, file: string, signal?: AbortSignal) =>
      verify({ operation: "check", directory, file }, signal),
  };
}
export type WindowsBackgroundSecurity = ReturnType<typeof createWindowsBackgroundSecurity>;

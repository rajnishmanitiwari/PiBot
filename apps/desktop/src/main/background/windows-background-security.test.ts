import { describe, expect, it } from "vitest";
import { windowsBackgroundSecurityScript } from "./windows-background-security.ts";

// The owner check runs on Windows only, but the script is a pure string builder, so its
// listener query is pinned here without PowerShell: on some Windows builds the OS reports a
// listening socket with a wrong or empty TCP state, and a `State = 2` predicate matched 0 rows
// even though the socket was listening (w01fb0ss/PiBot#15).
describe("windowsBackgroundSecurityScript owner check", () => {
  const ownerScript = () =>
    windowsBackgroundSecurityScript({
      operation: "owner",
      pid: 1234,
      port: 56789,
      executable: "C:\\Program Files\\Pi Bot\\Pi Bot.exe",
    });

  it("does not filter the listener query on the TCP state column", () => {
    const script = ownerScript();
    expect(script).not.toContain("State = 2");
    expect(script).toContain(
      "SELECT OwningProcess FROM MSFT_NetTCPConnection WHERE LocalAddress = '127.0.0.1' AND LocalPort = $port",
    );
  });

  it("accepts the listener when any row for the port is owned by the process", () => {
    const script = ownerScript();
    expect(script).toContain(
      "$owned = @($listener | Where-Object { [int]$_['OwningProcess'] -eq $processId })",
    );
    expect(script).toContain("if ($owned.Count -eq 0) { throw 'listener_identity_changed' }");
  });

  it("rejects a listener row owned by another process", () => {
    const script = ownerScript();
    expect(script).toContain(
      "$foreign = @($listener | Where-Object { $p = [int]$_['OwningProcess']; $p -ne $processId -and $p -ne 0 -and $p -ne 4 })",
    );
    expect(script).toContain("if ($foreign.Count -gt 0) { throw 'listener_identity_changed' }");
  });

  it("tolerates rows owned by the System Idle/System process", () => {
    // A TIME_WAIT leftover from a dead predecessor is reported under PID 0 or 4.
    expect(ownerScript()).toContain("$p -ne 0 -and $p -ne 4");
  });

  it("still reports a missing listener when the query returns no rows", () => {
    expect(ownerScript()).toContain("if ($listener.Count -eq 0) { throw 'listener_missing' }");
  });

  it("checks ownership in order: rows exist, then no foreign row, then one is owned by the process", () => {
    // The script is one static program carrying every branch, so the order of the lines
    // inside the owner block is what pins the logic.
    const script = ownerScript();
    const query = script.indexOf("SELECT OwningProcess FROM MSFT_NetTCPConnection");
    const missing = script.indexOf("if ($listener.Count -eq 0) { throw 'listener_missing' }");
    const foreign = script.indexOf(
      "if ($foreign.Count -gt 0) { throw 'listener_identity_changed' }",
    );
    const owned = script.indexOf(
      "$owned = @($listener | Where-Object { [int]$_['OwningProcess'] -eq $processId })",
    );
    const changed = script.indexOf("if ($owned.Count -eq 0) { throw 'listener_identity_changed' }");
    expect(query).toBeGreaterThan(-1);
    expect(missing).toBeGreaterThan(query);
    expect(foreign).toBeGreaterThan(missing);
    expect(owned).toBeGreaterThan(foreign);
    expect(changed).toBeGreaterThan(owned);
  });

  it("rejects a non-integer pid", () => {
    expect(() =>
      windowsBackgroundSecurityScript({ operation: "owner", pid: 1.5, port: 1 }),
    ).toThrow("background_windows_input_invalid");
  });
});

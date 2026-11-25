import type { ImageContent } from "@earendil-works/pi-ai";
import { describe, expect, it } from "vitest";
import { requeue, SessionAdditions } from "../src/session/session-additions.ts";

type Call = { mode: "steer" | "followUp"; text: string; images?: ImageContent[] };

type TrackedInput = { text: string; mode: "steer" | "followUp"; images?: ImageContent[] };

function fakeQueue(steering: string[], followUp: string[]) {
  const calls: Call[] = [];
  return {
    calls,
    session: {
      clearQueue: () => ({ steering: [...steering], followUp: [...followUp] }),
      steer: async (text: string, images?: ImageContent[]) => {
        calls.push({ mode: "steer", text, ...(images ? { images } : {}) });
      },
      followUp: async (text: string, images?: ImageContent[]) => {
        calls.push({ mode: "followUp", text, ...(images ? { images } : {}) });
      },
    },
  };
}

function tracked(entries: [string, TrackedInput][]) {
  const additions = new SessionAdditions();
  for (const [id, input] of entries) additions.queued.set(id, input);
  return additions;
}

function order(calls: Call[]) {
  return calls.map((call) => `${call.mode}:${call.text}`);
}

describe("requeue", () => {
  it("keeps each queue in native order and puts the switched input last", async () => {
    const { calls, session } = fakeQueue(["first", "sdk-only", "second"], ["later"]);
    const images = [{} as ImageContent];
    const additions = tracked([
      ["second-id", { text: "second", mode: "steer" }],
      ["first-id", { text: "first", mode: "steer", images }],
      ["later-id", { text: "later", mode: "followUp" }],
    ]);
    expect(await requeue(additions, session, "later-id", "steer")).toBe(true);
    expect(order(calls)).toEqual(["steer:first", "steer:sdk-only", "steer:second", "steer:later"]);
    expect(calls.find((call) => call.text === "first")?.images).toBe(images);
  });

  it("leaves a queue in native order when nothing switches", async () => {
    const { calls, session } = fakeQueue(["b", "a"], []);
    const additions = tracked([
      ["a-id", { text: "a", mode: "steer" }],
      ["b-id", { text: "b", mode: "steer" }],
    ]);
    expect(await requeue(additions, session, "missing-id", "followUp")).toBe(false);
    expect(order(calls)).toEqual(["steer:b", "steer:a"]);
  });

  it("drops an input pi already took and reports switching it as false", async () => {
    const { calls, session } = fakeQueue(["kept"], []);
    const additions = tracked([
      ["kept-id", { text: "kept", mode: "steer" }],
      ["gone-id", { text: "gone", mode: "steer" }],
    ]);
    expect(await requeue(additions, session, "gone-id", "followUp")).toBe(false);
    expect(order(calls)).toEqual(["steer:kept"]);
  });
});

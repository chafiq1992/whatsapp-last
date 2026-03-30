import React from "react";
import { useAudio } from "./AudioManager";

export default function GlobalAudioBar() {
  const { currentUrl, isPlaying, positionSec, durationSec, playbackRate, toggle, stop, cycleSpeed, seek } = useAudio();
  if (!currentUrl) return null;

  const pct = durationSec > 0 ? Math.min(100, Math.max(0, (positionSec / durationSec) * 100)) : 0;
  const waveformBars = [0.3, 0.75, 0.5, 0.9, 0.4, 0.7, 0.45, 0.85, 0.55, 0.65, 0.35, 0.8, 0.5, 0.72];
  const fmt = (s) => {
    if (!isFinite(s)) return "0:00";
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return `${m}:${String(sec).padStart(2, '0')}`;
  };

  return (
    <div className="pointer-events-auto flex justify-center">
      <div className="w-full rounded-[28px] border border-gray-700/80 bg-gray-900/95 px-3 py-3 shadow-[0_12px_30px_rgba(0,0,0,0.35)] backdrop-blur-md">
        <div className="flex items-center gap-3">
        <button
          className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500 text-gray-950 transition hover:bg-emerald-400"
          onClick={() => toggle()}
          title={isPlaying ? "Pause" : "Play"}
        >
          {isPlaying ? (
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 16 16">
              <rect x="3" y="2" width="3" height="12" />
              <rect x="10" y="2" width="3" height="12" />
            </svg>
          ) : (
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 16 16">
              <polygon points="3,2 13,8 3,14" />
            </svg>
          )}
        </button>
        <button
          className="h-8 rounded-full bg-gray-800 px-3 text-xs font-medium text-gray-100 transition hover:bg-gray-700"
          onClick={cycleSpeed}
          title="Playback speed"
        >
          {`${playbackRate}x`}
        </button>
        <div className="min-w-0 flex-1 select-none">
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="text-[11px] font-medium uppercase tracking-[0.24em] text-emerald-300/85">
              Voice Playback
            </span>
            <div className="flex items-center gap-2 text-[11px] text-gray-300">
              <span className="w-10 text-right tabular-nums">{fmt(positionSec)}</span>
              <span className="text-gray-500">/</span>
              <span className="w-10 tabular-nums">{fmt(durationSec)}</span>
            </div>
          </div>
          <div className="relative">
            <div className="pointer-events-none absolute inset-x-0 top-1/2 flex h-10 -translate-y-1/2 items-center gap-1 px-2">
              {waveformBars.map((height, index) => {
                const progress = waveformBars.length <= 1 ? 1 : index / (waveformBars.length - 1);
                const isActive = progress <= pct / 100;
                return (
                  <span
                    key={`wave-${index}`}
                    className={`flex-1 rounded-full transition-colors ${isActive ? "bg-emerald-300/90" : "bg-gray-700/90"}`}
                    style={{ height: `${Math.round(12 + height * 20)}px` }}
                  />
                );
              })}
            </div>
            <input
              className="h-10 w-full cursor-pointer appearance-none bg-transparent opacity-0"
              type="range"
              min={0}
              max={1000}
              step={1}
              value={Math.round(pct * 10)}
              onChange={(e) => { const f = (Number(e.target.value) / 1000); seek(f); }}
              aria-label="Audio playback position"
            />
          </div>
        </div>
        <button
          className="flex h-9 items-center rounded-full bg-gray-800 px-3 text-xs font-medium text-gray-100 transition hover:bg-red-500 hover:text-white"
          onClick={stop}
          title="Stop"
        >
          Close
        </button>
        </div>
      </div>
    </div>
  );
}



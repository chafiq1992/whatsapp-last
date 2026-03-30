import React from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
} from '@xyflow/react';
import { Plus, AlertTriangle } from 'lucide-react';

/**
 * PlusEdge — custom edge that shows a "+" insert button at the midpoint.
 * Also displays an error indicator if data.error is set.
 */
export default function PlusEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
  label,
  source,
  target,
  sourceHandleId,
}) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const hasError = !!data?.error;
  const edgeStyle = {
    strokeWidth: 2,
    stroke: hasError ? '#ef4444' : '#94a3b8',
    ...style,
    ...(hasError ? { strokeDasharray: '6 3' } : {}),
  };

  const handleInsertClick = (evt) => {
    evt.stopPropagation();
    if (data?.onEdgeInsert) {
      data.onEdgeInsert(evt, {
        id,
        source,
        target,
        sourceHandle: sourceHandleId,
      });
    }
  };

  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={edgeStyle} />
      <EdgeLabelRenderer>
        <div
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            pointerEvents: 'all',
          }}
          className="nodrag nopan"
        >
          {/* "+" insert button */}
          <button
            onClick={handleInsertClick}
            className="w-7 h-7 rounded-full bg-white border-2 border-slate-300 flex items-center justify-center 
                       cursor-pointer hover:border-blue-500 hover:bg-blue-50 hover:scale-125 
                       transition-all shadow-md group z-10"
            title="Insert step here"
          >
            <Plus className="w-3.5 h-3.5 text-slate-400 group-hover:text-blue-600 transition-colors" />
          </button>

          {/* Error badge */}
          {hasError && (
            <div
              className="absolute -top-8 left-1/2 -translate-x-1/2 flex items-center gap-1 
                         bg-rose-600 text-white text-[9px] font-semibold px-2 py-0.5 rounded-full 
                         shadow-lg whitespace-nowrap z-20 animate-pulse"
              title={data.error}
            >
              <AlertTriangle className="w-2.5 h-2.5" />
              {String(data.error).length > 30
                ? String(data.error).slice(0, 30) + '…'
                : data.error}
            </div>
          )}

          {/* Edge label (e.g. "✓ Yes" / "✗ No") */}
          {label && (
            <div
              className="absolute top-8 left-1/2 -translate-x-1/2 text-[10px] font-semibold 
                         text-slate-500 bg-white/90 px-2 py-0.5 rounded shadow-sm 
                         border border-slate-200 whitespace-nowrap"
            >
              {label}
            </div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

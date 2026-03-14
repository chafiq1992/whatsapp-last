import React, { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  applyNodeChanges,
  applyEdgeChanges,
  useReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { nodeTypes } from './CustomNodes';
import Sidebar from './Sidebar';

function FlowContextWrapper({ rules, onEdit, onOpenNew }) {
  const reactFlowInstance = useReactFlow();
  
  // Create nodes from rules dynamically
  const initialData = useMemo(() => {
    const nodes = [];
    const edges = [];
    
    rules.forEach((rule, idx) => {
      // Calculate a simple grid layout for the flows 
      // 2 columns, unlimited rows
      const col = idx % 2;
      const row = Math.floor(idx / 2);
      
      const xOffset = col * 800 + 100;
      const yOffset = row * 300 + 100;
      
      const triggerId = `trigger-${rule.id}`;
      const actionId = `action-${rule.id}`;

      nodes.push({
        id: triggerId,
        type: 'triggerNode',
        position: { x: xOffset, y: yOffset },
        data: { rule, onEdit },
        draggable: true,
      });

      nodes.push({
        id: actionId,
        type: 'actionNode',
        position: { x: xOffset + 400, y: yOffset },
        data: { rule, onEdit },
        draggable: true,
      });

      edges.push({
        id: `edge-${rule.id}`,
        source: triggerId,
        target: actionId,
        type: 'smoothstep',
        animated: rule.enabled,
        style: { stroke: rule.enabled ? '#3b82f6' : '#cbd5e1', strokeWidth: 2 },
      });
    });

    return { nodes, edges };
  }, [rules, onEdit]);

  const [nodes, setNodes] = useState(initialData.nodes);
  const [edges, setEdges] = useState(initialData.edges);

  // Sync state if rules change externally
  useEffect(() => {
    setNodes((nds) => {
      // Keep existing positions if possible
      return initialData.nodes.map(n => {
        const existingNode = nds.find(e => e.id === n.id);
        return existingNode ? { ...n, position: existingNode.position } : n;
      });
    });
    setEdges(initialData.edges);
  }, [initialData]);

  const onNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    [setNodes]
  );
  
  const onEdgesChange = useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    [setEdges]
  );

  const onDragOver = useCallback((event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event) => {
      event.preventDefault();

      const type = event.dataTransfer.getData('application/reactflow');
      const presetData = event.dataTransfer.getData('application/preset');

      if (!type || !presetData) {
        return;
      }

      // Convert pixel drops to coordinates correctly
      const position = reactFlowInstance.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      const preset = JSON.parse(presetData);
      
      // Prompt creation of new rule with preset
      if (onOpenNew) {
        onOpenNew(preset);
      }
    },
    [reactFlowInstance, onOpenNew]
  );

  return (
    <div className="flex w-full h-[calc(100vh-48px)]">
      <div className="flex-1 h-full" onDrop={onDrop} onDragOver={onDragOver}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.2}
          maxZoom={1.5}
        >
          <Background color="#cbd5e1" gap={16} size={1} />
          <Controls className="bg-white shadow-xl border border-slate-200 rounded-lg overflow-hidden" />
          <MiniMap 
            nodeColor={(n) => {
              if (n.type === 'triggerNode') return '#10b981';
              if (n.type === 'actionNode') return '#3b82f6';
              return '#cbd5e1';
            }}
            maskColor="rgba(248, 250, 252, 0.7)"
            className="border border-slate-200 rounded-lg shadow-sm"
          />
        </ReactFlow>
      </div>
      <Sidebar onOpenNew={onOpenNew} />
    </div>
  );
}

export default function AutomationCanvas({ rules, onEdit, onOpenNew }) {
  return (
    <ReactFlowProvider>
      <FlowContextWrapper rules={rules} onEdit={onEdit} onOpenNew={onOpenNew} />
    </ReactFlowProvider>
  );
}

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
import { Plus, MessageSquare, Timer, MessageSquareText } from 'lucide-react';

function FlowContextWrapper({ rules, onEdit, onOpenNew }) {
  const [popover, setPopover] = useState(null);
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
      
      const hasCondition = rule.condition && Object.keys(rule.condition).length > 0;
      
      const triggerId = `trigger-${rule.id}`;
      const actionId = `action-${rule.id}`;
      const conditionId = `condition-${rule.id}`;

      nodes.push({
        id: triggerId,
        type: 'triggerNode',
        position: { x: xOffset, y: yOffset },
        data: { rule, onEdit },
        draggable: true,
      });

      if (hasCondition) {
        nodes.push({
          id: conditionId,
          type: 'conditionNode',
          position: { x: xOffset + 350, y: yOffset },
          data: { rule, onEdit },
          draggable: true,
        });

        nodes.push({
          id: actionId,
          type: 'actionNode',
          position: { x: xOffset + 700, y: yOffset },
          data: { rule, onEdit },
          draggable: true,
        });

        edges.push({
          id: `edge-t-c-${rule.id}`,
          source: triggerId,
          target: conditionId,
          type: 'smoothstep',
          animated: rule.enabled,
          style: { stroke: rule.enabled ? '#3b82f6' : '#cbd5e1', strokeWidth: 2 },
        });

        edges.push({
          id: `edge-c-a-${rule.id}`,
          source: conditionId,
          target: actionId,
          type: 'smoothstep',
          animated: rule.enabled,
          style: { stroke: rule.enabled ? '#3b82f6' : '#cbd5e1', strokeWidth: 2 },
        });
      } else {
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
      }
    });

    return { nodes, edges };
  }, [rules, onEdit, reactFlowInstance]);

  const [nodes, setNodes] = useState(initialData.nodes);
  const [edges, setEdges] = useState(initialData.edges);

  const onAddStep = useCallback((event, rule) => {
    event.stopPropagation();
    event.preventDefault();
    
    // Position the popover near the mouse click
    const rect = event.currentTarget.getBoundingClientRect();
    const popupWidth = 260;
    
    let xOffset = rect.right + 10;
    if (xOffset + popupWidth > window.innerWidth - 20) {
      // If there's no room on the right, display it on the left of the + button
      xOffset = rect.left - popupWidth - 10;
    }
    
    setPopover({
      ruleId: rule?.id,
      x: xOffset,
      y: Math.min(rect.top, window.innerHeight - 300),
    });
  }, []);

  // Update node data to include onAddStep callback whenever rules or the callback change
  useEffect(() => {
    setNodes((nds) => {
      // Keep existing positions if possible, re-inject fresh onEdit/onAddStep
      return initialData.nodes.map(n => {
        const existingNode = nds.find(e => e.id === n.id);
        const position = existingNode ? existingNode.position : n.position;
        return {
          ...n,
          position,
          data: {
            ...n.data,
            onAddStep
          }
        };
      });
    });
    setEdges(initialData.edges);
  }, [initialData, onAddStep]);

  const closePopover = useCallback(() => setPopover(null), []);

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

      {/* Popover for Action Selection */}
      {popover && (
        <>
          <div className="fixed inset-0 z-40" onClick={closePopover} onContextMenu={(e)=>{e.preventDefault(); closePopover()}} />
          <div 
            className="fixed z-50 bg-white border border-slate-200 rounded-xl shadow-xl w-64 overflow-hidden"
            style={{ left: popover.x, top: popover.y }}
          >
            <div className="bg-slate-50 px-3 py-2 border-b text-xs font-semibold text-slate-600">
              Add next step
            </div>
            <div className="p-2 space-y-1">
              <button 
                className="w-full text-left px-3 py-2 text-sm rounded hover:bg-slate-100 flex items-center gap-2"
                onClick={() => {
                  const ruleObj = rules.find(r => r.id === popover.ruleId);
                  if (ruleObj && onEdit) {
                    const modifiedRule = { ...ruleObj, actions: [...(ruleObj.actions || []), { type: "send_whatsapp_text", to: "{{ phone }}", text: "New message" }] };
                    onEdit(modifiedRule);
                  }
                  closePopover();
                }}
              >
                <MessageSquare className="w-4 h-4 text-blue-500" />
                <span>Send Message</span>
              </button>
              
              <button 
                className="w-full text-left px-3 py-2 text-sm rounded hover:bg-slate-100 flex items-center gap-2"
                onClick={() => {
                  const ruleObj = rules.find(r => r.id === popover.ruleId);
                  if (ruleObj && onEdit) {
                    const modifiedRule = { ...ruleObj, actions: [...(ruleObj.actions || []), { type: "send_whatsapp_template", to: "{{ phone }}", template_name: "", language: "en" }] };
                    onEdit(modifiedRule);
                  }
                  closePopover();
                }}
              >
                <MessageSquareText className="w-4 h-4 text-emerald-500" />
                <span>Send Template</span>
              </button>

              <button 
                className="w-full text-left px-3 py-2 text-sm rounded hover:bg-slate-100 flex items-center gap-2"
                onClick={() => {
                  const ruleObj = rules.find(r => r.id === popover.ruleId);
                  if (ruleObj && onEdit) {
                    const modifiedRule = { ...ruleObj, actions: [...(ruleObj.actions || []), { type: "delay", delay: "10m" }] };
                    onEdit(modifiedRule);
                  }
                  closePopover();
                }}
              >
                <Timer className="w-4 h-4 text-amber-500" />
                <span>Add Delay</span>
              </button>

              <div className="border-t border-slate-100 my-1 pt-1"></div>

              <button 
                className="w-full text-left px-3 py-2 text-sm rounded hover:bg-slate-100 flex items-center gap-2"
                onClick={() => {
                  const ruleObj = rules.find(r => r.id === popover.ruleId);
                  if (ruleObj && onEdit) {
                    // Injecting a default condition structure
                    const modifiedRule = { 
                      ...ruleObj, 
                      condition: { ...(ruleObj.condition || {}), match: "all", rules: [] } 
                    };
                    onEdit(modifiedRule);
                  }
                  closePopover();
                }}
              >
                <Plus className="w-4 h-4 text-indigo-500" />
                <span>Add Condition (Logic)</span>
              </button>
            </div>
          </div>
        </>
      )}
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

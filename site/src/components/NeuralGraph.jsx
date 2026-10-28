import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import '../css/neural-graph.css';

const HOME = '_home';

const GEO = new THREE.SphereGeometry(1, 16, 16);
const MAT = {
  home: new THREE.MeshBasicMaterial({ color: 0xffffff }),
  index: new THREE.MeshBasicMaterial({ color: 0xaaaaaa }),
  file: new THREE.MeshBasicMaterial({ color: 0x666666 }),
  tool: new THREE.MeshBasicMaterial({ color: 0xff003c }),
  cve: new THREE.MeshBasicMaterial({ color: 0xffaa00 }),
};

const linkPoints = [];
for (let i = 0; i <= 10; i++) {
  const t = i / 10;
  // Толщина: 0.3 у основания, 0.05 в середине
  const radius = 0.3 - Math.sin(t * Math.PI) * 0.25;
  linkPoints.push(new THREE.Vector2(radius, t - 0.5));
}
const LINK_GEO = new THREE.LatheGeometry(linkPoints, 6);
const LINK_MAT = {
  hierarchy: new THREE.MeshBasicMaterial({ color: 0xaaaaaa, opacity: 0.6, transparent: true, side: THREE.DoubleSide }),
  tool: new THREE.MeshBasicMaterial({ color: 0xff003c, opacity: 0.8, transparent: true, side: THREE.DoubleSide }),
  cve: new THREE.MeshBasicMaterial({ color: 0xffaa00, opacity: 0.8, transparent: true, side: THREE.DoubleSide }),
};

const getLinkObject = (link) => {
  const tgt = typeof link.target === 'object' ? link.target : { id: link.target };
  const src = typeof link.source === 'object' ? link.source : { id: link.source };
  let mat = LINK_MAT.hierarchy;
  if (tgt.group === 'tool' || src.group === 'tool') mat = LINK_MAT.tool;
  else if (tgt.group === 'cve' || src.group === 'cve') mat = LINK_MAT.cve;
  const mesh = new THREE.Mesh(LINK_GEO, mat);
  mesh.frustumCulled = false;
  return mesh; // Возвращаем именно Mesh, без Group
};

const updateLinkPosition = (obj, { start, end }, link) => {
  if (!obj) return false;
  let s = start;
  let e = end;
  if (!s || typeof s.x !== 'number') s = link.source;
  if (!e || typeof e.x !== 'number') e = link.target;
  if (!s || !e || typeof s.x !== 'number' || typeof e.x !== 'number') return false;

  const dx = e.x - s.x;
  const dy = e.y - s.y;
  const dz = e.z - s.z;
  const length = Math.sqrt(dx*dx + dy*dy + dz*dz);
  
  if (length === 0) return false;

  obj.position.set(s.x + dx/2, s.y + dy/2, s.z + dz/2);
  obj.scale.set(1, length, 1);

  const dir = new THREE.Vector3(dx, dy, dz).normalize();
  const up = new THREE.Vector3(0, 1, 0);
  obj.quaternion.setFromUnitVectors(up, dir);

  return true; // КРИТИЧЕСКИ ВАЖНО: говорим библиотеке, что мы всё обновили
};

const getNodeObject = (node) => {
  let mat = MAT.file;
  let scale = 1.4;
  if (node.id === HOME) { mat = MAT.home; scale = 3.5; }
  else if (node.group === 'tool') { mat = MAT.tool; scale = 3.0; }
  else if (node.group === 'cve') { mat = MAT.cve; scale = 2.0; }
  else if (node.is_index) { mat = MAT.index; scale = 2.2; }

  const mesh = new THREE.Mesh(GEO, mat);
  mesh.scale.set(scale, scale, scale);
  return mesh;
};

const getNodeLabel = (node) => {
  if (node.id === HOME) return 'MethodMan';
  return node.label || node.id;
};

const readFocusFromUrl = () => {
  if (typeof window === 'undefined') return null;
  const q = new URLSearchParams(window.location.search);
  return q.get('focus') || null;
};

const buildVisible = (graph, focus) => {
  if (!graph || !graph.hierarchy || !graph.brain) return { nodes: [], links: [] };
  const tree = graph.hierarchy.tree;
  const allBrainNodes = graph.brain.nodes;
  const nodeMap = new Map(allBrainNodes.map(n => [n.id, n]));

  if (!focus) {
    return graph.brain;
  }

  if (focus.startsWith('tool:') || focus.startsWith('cve:')) {
    const connectedIds = new Set([focus]);
    const visibleLinks = [];
    for (const l of graph.brain.links) {
      const s = typeof l.source === 'object' ? l.source.id : l.source;
      const t = typeof l.target === 'object' ? l.target.id : l.target;
      if (s === focus || t === focus) {
        connectedIds.add(s);
        connectedIds.add(t);
        visibleLinks.push(l);
      }
    }
    const nodes = Array.from(connectedIds).map(id => nodeMap.get(id)).filter(Boolean);
    return { nodes, links: visibleLinks };
  }

  // 1. Gather all descendants of focus
  const baseIds = new Set();
  const addDescendants = (id) => {
    baseIds.add(id);
    const n = tree[id];
    if (n && n.children) n.children.forEach(addDescendants);
  };
  addDescendants(focus);

  // 2. Gather neural links where source is in baseIds (captures tools/CVEs)
  const visibleIds = new Set([...baseIds]);
  const visibleLinks = [];
  const seenLinks = new Set();

  for (const l of graph.brain.links) {
    const s = l.source.id || l.source;
    const t = l.target.id || l.target;
    if (baseIds.has(s)) {
      visibleIds.add(s);
      visibleIds.add(t);
      const key = s + '->' + t;
      if (!seenLinks.has(key)) {
        seenLinks.add(key);
        visibleLinks.push(l);
      }
    }
  }

  // 3. Add hierarchy links for structure (parent-child)
  for (const l of graph.hierarchy.links) {
    const s = l.source.id || l.source;
    const t = l.target.id || l.target;
    if (baseIds.has(s) && baseIds.has(t)) {
      const key = s + '->' + t;
      if (!seenLinks.has(key)) {
        seenLinks.add(key);
        visibleLinks.push(l);
      }
    }
  }

  const nodes = Array.from(visibleIds).map(id => nodeMap.get(id)).filter(Boolean);
  return { nodes, links: visibleLinks };
};

export default function NeuralGraph() {
  const [graph, setGraph] = useState(null);
  const [focus, setFocus] = useState(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [error, setError] = useState(null);
  const containerRef = useRef(null);
  const graphRef = useRef(null);
  const bloomAddedRef = useRef(false);

  useEffect(() => {
    setFocus(readFocusFromUrl());
    const onPop = () => setFocus(readFocusFromUrl());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  useEffect(() => {
    fetch('/graph.json')
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(setGraph)
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setSize({ width: el.clientWidth, height: el.clientHeight });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const visible = useMemo(() => buildVisible(graph, focus), [graph, focus]);

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg || visible.nodes.length === 0) return;
    if (fg.controls()) fg.controls().zoomSpeed = 2.5;
    
    // Физика: раздвигаем узлы
    if (fg.d3Force('charge')) fg.d3Force('charge').strength(-30);
    if (fg.d3Force('link')) fg.d3Force('link').distance(10);
    fg.d3ReheatSimulation();
    if (!bloomAddedRef.current) {
      const el = containerRef.current;
      const w = el ? el.clientWidth : 800;
      const h = el ? el.clientHeight : 600;
      const bloomPass = new UnrealBloomPass(new THREE.Vector2(w, h), 0.6, 0.5, 0.2);
      fg.postProcessingComposer().addPass(bloomPass);
      bloomAddedRef.current = true;
    }
    const t = setTimeout(() => {
      if (graphRef.current) graphRef.current.zoomToFit(800, 80);
    }, 400);
    return () => clearTimeout(t);
  }, [visible]);

  const goTo = useCallback((nextFocus) => {
    const url = new URL(window.location.href);
    if (nextFocus) url.searchParams.set('focus', nextFocus);
    else url.searchParams.delete('focus');
    window.history.pushState({}, '', url.toString());
    setFocus(nextFocus);
  }, []);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== 'Escape') return;
      if (!focus) return;
      if (focus.startsWith('tool:') || focus.startsWith('cve:')) { goTo(null); return; }
      const node = graph && graph.hierarchy ? graph.hierarchy.tree[focus] : null;
      goTo(node && node.parent ? node.parent : null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [focus, graph, goTo]);

  const handleNodeClick = useCallback((node) => {
    if (!node) return;
    if (node.id === HOME) { goTo(null); return; }
    if (node.group === 'tool' || node.group === 'cve') { goTo(node.id); return; }
    const entry = graph && graph.hierarchy ? graph.hierarchy.tree[node.id] : null;
    const hasChildren = entry && entry.children && entry.children.length > 0;
    if (hasChildren) { goTo(node.id); return; }
    if (node.url) window.location.href = node.url;
  }, [graph, goTo]);

  const crumbs = useMemo(() => {
    if (!graph || !graph.hierarchy) return [];
    const list = [{ id: HOME, label: 'MethodMan' }];
    if (!focus) return list;
    if (focus.startsWith('tool:') || focus.startsWith('cve:')) {
      const n = graph.brain.nodes.find((x) => x.id === focus);
      list.push({ id: focus, label: n ? n.label : focus });
      return list;
    }
    const ids = [];
    let cur = focus;
    while (cur && graph.hierarchy.tree[cur]) {
      ids.unshift(cur);
      cur = graph.hierarchy.tree[cur].parent;
    }
    for (const id of ids) {
      const n = graph.hierarchy.tree[id];
      list.push({ id, label: (n && n.label) || id });
    }
    return list;
  }, [graph, focus]);
  const status = error
    ? 'LOAD ERROR: ' + error
    : visible.nodes.length + ' nodes / ' + visible.links.length + ' links' + (focus ? ' / focus=' + focus : '');

  return (
    <div className="app">
      <header className="hud">
        <span className="brand">METHODMAN / GRAPH</span>
        <nav className="crumbs">
          {crumbs.map((c, i) => (
            <span key={c.id} className="crumb-item">
              {i > 0 && <span className="sep">/</span>}
              <button
                type="button"
                className={'crumb' + (i === crumbs.length - 1 ? ' active' : '')}
                onClick={() => goTo(c.id === HOME ? null : c.id)}
              >
                {c.label}
              </button>
            </span>
          ))}
        </nav>
        <span className="status">{status}</span>
      </header>
      <main className="stage" ref={containerRef}>
        {size.width > 0 && visible.nodes.length > 0 && (
          <ForceGraph3D
            ref={graphRef}
            graphData={visible}
            width={size.width}
            height={size.height}
            backgroundColor="#000000"
            nodeThreeObject={getNodeObject}
            nodeLabel={getNodeLabel}
            onNodeClick={handleNodeClick}
            onNodeHover={(node) => {
              if (!node) { document.body.style.cursor = 'default'; return; }
              const isClickable = node.id === HOME || node.url || node.group === 'tool' || node.group === 'cve' || (node.children && node.children.length > 0);
              document.body.style.cursor = isClickable ? 'pointer' : 'default';
            }}
            linkColor={(l) => {
              const tgt = typeof l.target === 'object' ? l.target : { id: l.target };
              const src = typeof l.source === 'object' ? l.source : { id: l.source };
              if (tgt.group === 'tool' || src.group === 'tool') return '#ff003c';
              if (tgt.group === 'cve' || src.group === 'cve') return '#ffaa00';
              return '#aaaaaa';
            }}
            linkThreeObject={getLinkObject}
            linkPositionUpdate={updateLinkPosition}
            rendererConfig={{ antialias: true, alpha: false }}
            warmupTicks={100}
            cooldownTicks={150}
            d3AlphaDecay={0.02}
            d3VelocityDecay={0.3}
          />
        )}
        {!error && (!graph || visible.nodes.length === 0) && (
          <p className="hint">{graph ? 'empty focus' : 'loading graph.json...'}</p>
        )}
      </main>
      <footer className="hud foot">
        <span>{graph && graph.meta ? graph.meta.brain_total + ' nodes indexed' : '...'}</span>
        <span>Press Esc to go up · click to drill in or visit</span>
      </footer>
    </div>
  );
}

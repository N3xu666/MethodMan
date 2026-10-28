import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import '../css/neural-graph.css';

const HOME = '_home';
const TOP_LABEL = { writeups: 'WRITEUPS', reference: 'REFERENCE' };

const getNodeObject = (node) => {
  const group = new THREE.Group();
  const coreGeo = new THREE.SphereGeometry(1, 16, 16);
  const coreMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
  group.add(new THREE.Mesh(coreGeo, coreMat));
  let scale = 1.6;
  if (node.id === HOME) scale = 3.2;
  else if (node.is_index) scale = 2.2;
  else scale = 1.4;
  group.scale.set(scale, scale, scale);
  return group;
};

const getNodeLabel = (node) => {
  if (node.id === HOME) return 'MethodMan';
  const parts = [node.label || node.id];
  if (node.top) parts.push(TOP_LABEL[node.top] || node.top);
  return parts.join(' | ');
};

const readFocusFromUrl = () => {
  if (typeof window === 'undefined') return null;
  const q = new URLSearchParams(window.location.search);
  const f = q.get('focus');
  return f && f.length ? f : null;
};

const buildVisible = (graph, focus) => {
  if (!graph || !graph.tree || !graph.nodes) return { nodes: [], links: [] };
  const tree = graph.tree;
  if (!focus) {
    const top = graph.nodes.filter((n) => n.depth === 1 && n.id !== HOME);
    const nodes = top.concat([{ id: HOME, label: 'MethodMan', depth: -1, parent: null, ancestors: [], url: '/', is_index: true }]);
    const links = top.map((n) => ({ source: n.id, target: HOME }));
    return { nodes, links };
  }
  const parent = tree[focus];
  if (!parent) return { nodes: [], links: [] };
  const children = (parent.children || []).map((id) => graph.nodes.find((n) => n.id === id)).filter(Boolean);
  const nodes = [{ id: parent.id, label: parent.label, depth: parent.depth, parent: parent.parent, top: parent.top, url: parent.url, is_index: true }].concat(children);
  const links = children.map((c) => ({ source: c.id, target: parent.id }));
  return { nodes, links };
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
    if (!bloomAddedRef.current) {
      const el = containerRef.current;
      const w = el ? el.clientWidth : 800;
      const h = el ? el.clientHeight : 600;
      const bloomPass = new UnrealBloomPass(new THREE.Vector2(w, h), 1.5, 0.4, 0.1);
      fg.postProcessingComposer().addPass(bloomPass);
      bloomAddedRef.current = true;
    }
    const t = setTimeout(() => {
      if (graphRef.current) graphRef.current.zoomToFit(800, 80);
    }, 400);
    return () => clearTimeout(t);
  }, [visible]);

  const goTo = useCallback((next) => {
    const url = new URL(window.location.href);
    if (next) url.searchParams.set('focus', next);
    else url.searchParams.delete('focus');
    window.history.pushState({}, '', url.toString());
    setFocus(next);
  }, []);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== 'Escape') return;
      if (!focus) return;
      const node = graph && graph.tree ? graph.tree[focus] : null;
      goTo(node && node.parent ? node.parent : null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [focus, graph, goTo]);

  const handleNodeClick = useCallback((node) => {
    if (!node) return;
    if (node.id === HOME) return;
    const entry = graph && graph.tree ? graph.tree[node.id] : null;
    const hasChildren = entry && entry.children && entry.children.length > 0;
    if (hasChildren) {
      goTo(node.id);
      return;
    }
    if (node.url) window.location.href = node.url;
  }, [graph, goTo]);

  const crumbs = useMemo(() => {
    if (!graph || !graph.tree) return [];
    const list = [{ id: HOME, label: 'MethodMan' }];
    if (!focus) return list;
    const entry = graph.tree[focus];
    if (!entry) return list;
    const ids = [];
    let cur = focus;
    while (cur && graph.tree[cur]) {
      ids.unshift(cur);
      cur = graph.tree[cur].parent;
    }
    for (const id of ids) {
      const n = graph.tree[id];
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
              document.body.style.cursor = node && node.id !== HOME ? 'pointer' : 'default';
            }}
            linkColor={() => '#aaaaaa'}
            linkOpacity={0.6}
            linkWidth={0.5}
            rendererConfig={{ antialias: true, alpha: false }}
            warmupTicks={50}
            cooldownTicks={200}
          />
        )}
        {!error && (!graph || visible.nodes.length === 0) && (
          <p className="hint">{graph ? 'empty focus' : 'loading graph.json...'}</p>
        )}
      </main>
      <footer className="hud foot">
        <span>{graph && graph.meta ? graph.meta.total + ' nodes indexed' : '...'}</span>
        <span>Press Esc to go up · click a node to drill in</span>
      </footer>
    </div>
  );
}
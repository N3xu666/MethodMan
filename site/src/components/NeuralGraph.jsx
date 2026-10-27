import { useEffect, useRef, useState } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import '../css/neural-graph.css';

const getNodeObject = (node) => {
  const group = new THREE.Group();
  const coreGeo = new THREE.SphereGeometry(1, 16, 16);
  const coreMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
  group.add(new THREE.Mesh(coreGeo, coreMat));
  let scale = 1.5;
  if (node.group === 'category') scale = 2.5;
  if (node.group === 'cve') scale = 1;
  group.scale.set(scale, scale, scale);
  return group;
};

export default function NeuralGraph() {
  const [data, setData] = useState({ nodes: [], links: [] });
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [error, setError] = useState(null);
  const containerRef = useRef(null);
  const graphRef = useRef(null);
  const bloomAddedRef = useRef(false);

  useEffect(() => {
    fetch('/graph.json')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setData)
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

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg || data.nodes.length === 0) return;

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
      if (graphRef.current) graphRef.current.zoomToFit(1000, 60);
    }, 1000);
    return () => clearTimeout(t);
  }, [data]);

  const handleNodeClick = (node) => {
    if (node.group === 'category' || node.group === 'cve') return;
    if (!node.slug || !node.category_slug) return;
    window.location.href = `/writeups/${node.category_slug}/${node.slug}`;
  };

  const getNodeLabel = (node) => {
    if (node.group === 'cve') return node.label;
    if (node.group === 'category') return node.label;
    const parts = [node.label];
    if (node.os) parts.push(node.os);
    if (node.difficulty) parts.push(node.difficulty);
    return parts.join(' | ');
  };

  return (
    <div className="app">
      <header className="hud">
        <span className="brand">METHODMAN / GRAPH</span>
        <span className="status">
          {error
            ? `LOAD ERROR: ${error}`
            : `${data.nodes.length} nodes / ${data.links.length} links`}
        </span>
      </header>
      <main className="stage" ref={containerRef}>
        {size.width > 0 && data.nodes.length > 0 && (
          <ForceGraph3D
            ref={graphRef}
            graphData={data}
            width={size.width}
            height={size.height}
            backgroundColor="#000000"
            nodeThreeObject={getNodeObject}
            nodeLabel={getNodeLabel}
            onNodeClick={handleNodeClick}
            onNodeHover={(node) => {
              document.body.style.cursor = node && (node.group === 'machine' || node.slug) ? 'pointer' : 'default';
            }}
            linkColor={() => '#aaaaaa'}
            linkOpacity={0.6}
            linkWidth={0.5}
            rendererConfig={{ antialias: true, alpha: false }}
            warmupTicks={50}
            cooldownTicks={200}
          />
        )}
        {!error && data.nodes.length === 0 && (
          <p className="hint">loading graph.json...</p>
        )}
      </main>
      <footer className="hud foot">
        <span>24 published + 6 stubs</span>
        <span>3D force-graph - Phase 2</span>
      </footer>
    </div>
  );
}
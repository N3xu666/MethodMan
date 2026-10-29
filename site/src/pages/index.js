import React, { useState } from 'react';
import Layout from '@theme/Layout';
import BrowserOnly from '@docusaurus/BrowserOnly';
import Link from '@docusaurus/Link';
import LiveThreats from '@site/src/components/LiveThreats';
import styles from './index.module.css';

export default function Home() {
  const [lastSync, setLastSync] = useState('...');

  return (
    <Layout title="MethodMan / NEURAL PORT" description="Neural graph of MethodMan pentest walkthroughs" noFooter={true}>
      <div className={styles.layout}>
        
        {/* ВЕРХНЯЯ СТРОКА (Контент) */}
        <div className={styles.leftCol}>
          <Link to="/reference" className={styles.card}>
            <div className={styles.cardLabel}>REFERENCE</div>
            <div className={styles.cardDesc}>Applications / AI / Cloud / Networks / OSINT</div>
          </Link>
          <Link to="/writeups" className={styles.card}>
            <div className={styles.cardLabel}>WRITEUPS</div>
            <div className={styles.cardDesc}>HTB walkthroughs - Linux / Windows / AD</div>
          </Link>
        </div>

        <div className={styles.centerCol}>
          <BrowserOnly fallback={<div style={{background:'#000',height:'100%'}} />}>
            {() => {
              const NeuralGraph = require('@site/src/components/NeuralGraph').default;
              return <NeuralGraph />;
            }}
          </BrowserOnly>
        </div>

        <div className={styles.rightCol}>
          <div className={styles.threatsHeader}>LIVE THREATS</div>
          <LiveThreats onSync={setLastSync} />
        </div>

        {/* НИЖНЯЯ СТРОКА (Статус-бар) */}
        <div className={styles.leftFooter}>SYSTEM READY</div>
        <div className={styles.centerFooter}>PRESS ESC TO GO UP · CLICK TO DRILL IN OR VISIT</div>
        <div className={styles.rightFooter}>Last sync: {lastSync}</div>

      </div>
    </Layout>
  );
}
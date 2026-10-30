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
            <div className={styles.cardDesc}>Applications / AI / Cloud / Infrastructure / Networks / Virtualization / Information Security / OSINT / Anonymity & OpSec</div>
          </Link>
          <Link to="/writeups" className={styles.card}>
            <div className={styles.cardLabel}>WRITEUPS</div>
            <div className={styles.cardDesc}>Hack The Box / All Machines / Season 12 / OSCP (Linux, Windows, Active Directory and Networks) / Pro Labs</div>
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
        <div className={styles.rightFooter} style={{ display: 'block', textAlign: 'center', width: '100%', padding: '10px 0' }}><span style={{ display: 'inline-block', transform: 'translateX(-6px)' }}>Last sync: {lastSync}</span></div>

      </div>
    </Layout>
  );
}
import React from 'react';
import Head from '@docusaurus/Head';
import BrowserOnly from '@docusaurus/BrowserOnly';
import Link from '@docusaurus/Link';
import styles from './index.module.css';

export default function Home() {
  return (
    <>
      <Head>
        <title>MethodMan / Graph</title>
        <meta name="description" content="Neural graph of MethodMan pentest walkthroughs" />
      </Head>
      
      <div className={styles.layout}>
        {/* ЛЕВАЯ КОЛОНКА */}
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

        {/* ЦЕНТРАЛЬНАЯ КОЛОНКА (ГРАФ) */}
        <div className={styles.centerCol}>
          <BrowserOnly fallback={<div style={{background:'#000',height:'100%'}} />}>
            {() => {
              const NeuralGraph = require('@site/src/components/NeuralGraph').default;
              return <NeuralGraph />;
            }}
          </BrowserOnly>
        </div>

        {/* ПРАВАЯ КОЛОНКА (УГРОЗЫ) */}
        <div className={styles.rightCol}>
          <div className={styles.threatsHeader}>LIVE THREATS</div>
          <div className={styles.threatsPlaceholder}>
            Waiting for CVE feed...
          </div>
        </div>
      </div>
    </>
  );
}
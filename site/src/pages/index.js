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
      <BrowserOnly fallback={<div style={{background:'#000',height:'100vh'}} />}>
        {() => {
          const NeuralGraph = require('@site/src/components/NeuralGraph').default;
          return <NeuralGraph />;
        }}
      </BrowserOnly>
      <div className={styles.navCards}>
        <Link to="/writeups" className={styles.card}>
          <div className={styles.cardLabel}>WRITEUPS</div>
          <div className={styles.cardDesc}>HTB walkthroughs - Linux / Windows / AD</div>
        </Link>
        <Link to="/reference" className={styles.card}>
          <div className={styles.cardLabel}>REFERENCE</div>
          <div className={styles.cardDesc}>Applications / AI / Cloud / Networks / OSINT</div>
        </Link>
      </div>
    </>
  );
}
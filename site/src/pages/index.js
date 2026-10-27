import React from 'react';
import Head from '@docusaurus/Head';
import BrowserOnly from '@docusaurus/BrowserOnly';

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
    </>
  );
}
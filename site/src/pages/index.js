import React from 'react';
import Head from '@docusaurus/Head';
import NeuralGraph from '@site/src/components/NeuralGraph';

export default function Home() {
  return (
    <>
      <Head>
        <title>MethodMan / Graph</title>
        <meta name="description" content="Neural graph of MethodMan pentest walkthroughs" />
      </Head>
      <NeuralGraph />
    </>
  );
}
import { FunctionComponent } from 'react';
import Head from 'next/head';
import { EuiEmptyPrompt, EuiButton } from '@elastic/eui';
import Wrapper from '../components/home/wrapper';
import Link from 'next/link';

const NotFound: FunctionComponent = () => (
  <>
    <Head><title>404 — Multi-SIEM Detection Rules Explorer</title></Head>
    <Wrapper>
      <EuiEmptyPrompt
        iconType="alert"
        title={<h2>Page not found</h2>}
        body={<p>The page you are looking for does not exist.</p>}
        actions={
          <Link href="/" passHref>
            <EuiButton color="primary" fill>Go back home</EuiButton>
          </Link>
        }
      />
    </Wrapper>
  </>
);

export default NotFound;

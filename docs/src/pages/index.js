import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import Heading from '@theme/Heading';
import styles from './index.module.css';

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();

  return (
    <header className={clsx(styles.hero)}>
      <div className={styles.heroInner}>
        <Heading as="h1" className={styles.title}>
          {siteConfig.title}
        </Heading>

        <p className={styles.subtitle}>
          {siteConfig.tagline}
        </p>

        <div className={styles.buttons}>
          <Link
            className={clsx('button button--primary button--lg', styles.primaryBtn)}
            to="/docs/intro"
          >
            Get Started 🚀
          </Link>

          <Link
            className={clsx('button button--outline button--lg', styles.secondaryBtn)}
            to="https://github.com/OgunwandeBukunmi/credo"
          >
            GitHub ⭐
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home() {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout
      title={siteConfig.title}
      description="Credo – pluggable authentication, mail providers, and database adapters"
    >
      <HomepageHeader />
      <main>
        <HomepageFeatures className={clsx(styles.hero)} />
      </main>
    </Layout>
  );
}

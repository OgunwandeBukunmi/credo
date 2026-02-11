import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';


const FeatureList = [
  {
    title: 'Secure Identity',
    description: (
      <>
        Credo Auth implements industry-standard protocols like OIDC and OAuth2,
        ensuring your application's identity layer is secure and reliable.
      </>
    ),
  },
  {
    title: 'Developer First',
    description: (
      <>
        Get started quickly with our intuitive SDKs and comprehensive documentation
        designed to make authentication integration a breeze.
      </>
    ),
  },
  {
    title: 'Enterprise Ready',
    description: (
      <>
        Built with scalability in mind, Credo Auth supports multi-tenancy,
        RBAC, and custom branding to meet the needs of any organization.
      </>
    ),
  },
];


function Feature({ Svg, title, description }) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures({ className }) {
  return (
    <section className={className}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

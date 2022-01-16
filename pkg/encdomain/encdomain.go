package encdomain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	routev1 "github.com/openshift/api/route/v1"
	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	letsencryptv1beta1 "github.com/operatingopenshift/le-operator/api/v1beta1"
)

const (
	ChallengePath string = "/.well-known/acme-challenge"
	UsageLabel    string = "operatingopenshift.org/usage"
)

type EncryptedDomainManager struct {
	client client.Client
}

type LeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LeUser) GetEmail() string {
	return u.Email
}
func (u LeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func New(client client.Client) EncryptedDomainManager {
	return EncryptedDomainManager{client}
}

func (r *EncryptedDomainManager) GetManagingDomain(ctx context.Context, route routev1.Route) *letsencryptv1beta1.EncryptedDomain {
	matchingDomains := []letsencryptv1beta1.EncryptedDomain{}

	options := client.ListOptions{
		Namespace: route.Namespace,
	}
	domains := letsencryptv1beta1.EncryptedDomainList{}
	r.client.List(ctx, &domains, &options)

	for _, domain := range domains.Items {
		hostnameRegex, err := regexp.Compile(domain.Spec.MatchingHostnames)
		if err != nil {
			continue
		}
		if hostnameRegex.MatchString(route.Spec.Host) {
			matchingDomains = append(matchingDomains, domain)
		}
		_, ok := domain.Status.GeneratedCertificates[route.Spec.Host]
		if ok {
			return &domain
		}
	}

	if len(matchingDomains) > 0 {
		return &matchingDomains[0]
	}
	return nil
}

func (m *EncryptedDomainManager) InitializeLeClient(ctx context.Context, domain letsencryptv1beta1.EncryptedDomain) (client *lego.Client, user LeUser, stopProcessing bool, err error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/InitializeLeClient")
	// Create a user. New accounts need an email and private key to start.
	log.Info("Ensuring private key is set")
	privateKey, stopProcessing, err := m.ensurePrivateKey(ctx, domain)
	if stopProcessing || err != nil {
		log.Info("Private Key newly generated or error happened, returning")
		//log.Info("Private Key: " + fmt.Sprintf("%v", privateKey))
		return nil, LeUser{}, true, err
	}
	//log.Info("Private Key: " + fmt.Sprintf("%v", privateKey))

	myUser := LeUser{
		Email: domain.Spec.RegistrationMail,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	if domain.Spec.CADirInsecureSSL {
		log.Info("Ignoring insecure SSL on CA directory")
		config.HTTPClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}

	config.CADirURL = domain.Spec.CADir
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err = lego.NewClient(config)
	if err != nil {
		return nil, myUser, true, err
	}

	// The challenge will always be exported on port 80 externally since we use a route to expose it, independent of the port specified here
	provider := http01.NewProviderServer("", "5002")
	err = client.Challenge.SetHTTP01Provider(provider)
	if err != nil {
		return client, myUser, true, err
	}

	return client, myUser, false, nil
}

func (r *EncryptedDomainManager) ensurePrivateKey(ctx context.Context, domain letsencryptv1beta1.EncryptedDomain) (*ecdsa.PrivateKey, bool, error) {
	if domain.Status.PrivateKey != "" {
		key, err := decodePrivateKey(domain)
		if err == nil {
			return key, false, nil
		}
	}

	rsa.GenerateKey(rand.Reader, 256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, err
	}

	domain.Status.PrivateKey, err = encodePrivateKey(privateKey)
	if err != nil {
		return nil, false, err
	}

	err = r.client.Status().Update(ctx, &domain)
	if err != nil {
		return nil, false, err
	}

	return privateKey, true, nil
}

func decodePrivateKey(domain letsencryptv1beta1.EncryptedDomain) (key *ecdsa.PrivateKey, err error) {
	keyBytes, err := base64.RawStdEncoding.DecodeString(domain.Status.PrivateKey)
	if err != nil {
		return
	}
	key, err = x509.ParseECPrivateKey(keyBytes)
	return
}

func encodePrivateKey(key *ecdsa.PrivateKey) (keyString string, err error) {
	bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	keyString = base64.RawStdEncoding.EncodeToString(bytes)
	return
}

func (m *EncryptedDomainManager) EnsureCertificate(ctx context.Context, client *lego.Client, domain letsencryptv1beta1.EncryptedDomain, route routev1.Route) (routeModified bool, domainModified bool, err error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/EnsureCertificate")
	r := m
	// Check if one of the already existing certificates can be used for this route
	dueForRenewal := r.DueForRenewal(domain, route.Spec.Host)
	if !dueForRenewal {
		if route.Spec.TLS == nil || route.Spec.TLS.Certificate != domain.Status.GeneratedCertificates[route.Spec.Host].Certificate || route.Spec.TLS.Key != domain.Status.GeneratedCertificates[route.Spec.Host].Key {
			route.Spec.TLS = &routev1.TLSConfig{
				Certificate: domain.Status.GeneratedCertificates[route.Spec.Host].Certificate,
				Key:         domain.Status.GeneratedCertificates[route.Spec.Host].Key,
			}

			log.Info("Certificate already exists. Updating route " + route.Name + " in namespace " + route.Namespace)
			err = r.client.Update(ctx, &route)
			if err != nil {
				return
			}
			routeModified = true

		} else {
			log.Info("Nothing to do for route " + route.Name)
		}
		return
	}

	// Set up route for ACME challenge
	err = r.ensureAcmeProxyConfigMap(ctx, route)
	if err != nil {
		return
	}

	err = r.ensureAcmeProxyDeployment(ctx, route)
	if err != nil {
		return
	}

	err = r.ensureAcmeSvc(ctx, route)
	if err != nil {
		return
	}

	err = r.ensureAcmeRoute(ctx, route)
	if err != nil {
		return
	}

	// Request certificates
	log.Info("Requesting certificates for domain " + route.Spec.Host)
	request := certificate.ObtainRequest{
		Domains: []string{route.Spec.Host},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return
	}

	if certificates == nil {
		err = fmt.Errorf("certificate request succeeded, but nil certificate returned")
		return
	}

	//log.Info("Certificate received: " + fmt.Sprintf("%v", *certificates))
	log.Info("Certificate received! ")

	route.Spec.TLS = &routev1.TLSConfig{
		Certificate: string(certificates.Certificate[:]),
		Key:         string(certificates.PrivateKey[:]),
	}

	log.Info("Updating route " + route.Name + " in namespace " + route.Namespace)
	err = r.client.Update(ctx, &route)
	if err != nil {
		return
	}
	routeModified = true

	if domain.Status.GeneratedCertificates == nil {
		domain.Status.GeneratedCertificates = map[string]letsencryptv1beta1.GeneratedCertificate{}
	}

	domain.Status.GeneratedCertificates[route.Spec.Host] = letsencryptv1beta1.GeneratedCertificate{
		Hostname:    route.Spec.Host,
		Certificate: route.Spec.TLS.Certificate,
		Key:         route.Spec.TLS.Key,
	}

	log.Info("Updating encrypteddomain " + domain.Name + " in namespace " + domain.Namespace)
	err = r.client.Status().Update(ctx, &domain)
	if err != nil {
		return
	}
	domainModified = true

	err = r.CleanupAcmeChallenge(ctx, route)
	return
}

func (r *EncryptedDomainManager) CleanupAcmeChallenge(ctx context.Context, route routev1.Route) error {

	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name + "-acme-challenge",
			Namespace: route.Namespace,
		},
	}
	err := r.client.Delete(ctx, &deployment)
	if err != nil {
		return err
	}

	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name + "-acme-challenge",
			Namespace: route.Namespace,
		},
	}
	err = r.client.Delete(ctx, &svc)
	if err != nil {
		return err
	}

	challengeRoute := routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name + "-acme-challenge",
			Namespace: route.Namespace,
		},
	}
	err = r.client.Delete(ctx, &challengeRoute)
	if err != nil {
		return err
	}
	return nil
}

func (r *EncryptedDomainManager) DueForRenewal(domain letsencryptv1beta1.EncryptedDomain, host string) bool {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/DueForRenewal")
	if domain.Status.GeneratedCertificates == nil {
		log.Info("No certificates generated for domain, generating certificates")
		return true
	}
	certs, ok := domain.Status.GeneratedCertificates[host]
	if !ok {
		log.Info("No certificates found for host " + host + ", generating certificates")
		return true
	}
	block, _ := pem.Decode([]byte(certs.Certificate))
	if block == nil {
		log.Info("failed to parse certificate PEM for hostname " + host + ", renewing.")
		return true
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Info("Invalid certificate found for hostname " + host + ", renewing. Error was " + fmt.Sprintf("%v", err))
		return true
	}
	if time.Until(certificate.NotAfter) < 15*24*time.Hour {
		log.Info("Certificate will expire in less than 15 days for host " + host + ", renewing")
		return true
	}
	return false
}

func (r *EncryptedDomainManager) ensureAcmeProxyConfigMap(ctx context.Context, route routev1.Route) (err error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/ensureAcmeProxyConfigMap")
	desiredConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "le-operator-challenge-proxy-config",
			Namespace: route.Namespace,
			Labels: map[string]string{
				UsageLabel: "acme-challenge",
			},
		},
		Data: map[string]string{
			"nginx.conf": `
events {
  worker_connections 1024;
}

http {
  server {
    listen 5002;
	server_name localhost;
    location / {
      proxy_pass  http://le-operator-acme-challenge.le-operator-system.svc.cluster.local:5002;
	  proxy_set_header Host            $host;
	  proxy_set_header X-Forwarded-For $remote_addr;
    }
  }
}
`,
		},
	}

	actualConfigMap := corev1.ConfigMap{}
	err = r.client.Get(ctx, types.NamespacedName{Name: desiredConfigMap.Name, Namespace: desiredConfigMap.Namespace}, &actualConfigMap)
	if err != nil {
		if !errors.IsNotFound(err) {
			return
		}
		// Challenge route doesn't exist
		log.Info("Creating config " + desiredConfigMap.Name + " in namespace " + desiredConfigMap.Namespace)
		err = r.client.Create(ctx, &desiredConfigMap)
		return
	}
	log.Info("Updating config " + desiredConfigMap.Name + " in namespace " + desiredConfigMap.Namespace)
	actualConfigMap.Data = desiredConfigMap.Data
	err = r.client.Update(ctx, &actualConfigMap)
	return
}
func (r *EncryptedDomainManager) ensureAcmeProxyDeployment(ctx context.Context, route routev1.Route) (err error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/ensureAcmeProxyDeployment")
	desiredDeployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name + "-acme-challenge",
			Namespace: route.Namespace,
			Labels: map[string]string{
				UsageLabel: "acme-challenge",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					UsageLabel: "acme-challenge",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						UsageLabel: "acme-challenge",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "proxy",
							Image: "nginx",
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "challenge-proxy-config",
									MountPath: "/etc/nginx/",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "challenge-proxy-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "le-operator-challenge-proxy-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	actualDeployment := appsv1.Deployment{}
	err = r.client.Get(ctx, types.NamespacedName{Name: desiredDeployment.Name, Namespace: desiredDeployment.Namespace}, &actualDeployment)
	if err != nil {
		if !errors.IsNotFound(err) {
			return
		}
		// Challenge route doesn't exist
		log.Info("Creating challenge deployment " + desiredDeployment.Name + " in namespace " + desiredDeployment.Namespace)
		err = r.client.Create(ctx, &desiredDeployment)
		return
	}
	log.Info("Updating challenge deployment " + desiredDeployment.Name + " in namespace " + desiredDeployment.Namespace)
	actualDeployment.Spec = desiredDeployment.Spec
	err = r.client.Update(ctx, &actualDeployment)
	return
}

func (r *EncryptedDomainManager) ensureAcmeRoute(ctx context.Context, route routev1.Route) (err error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/ensureRoute")

	// Create route for hostname:5002/.well-known/acme-challenge
	desiredChallengeRoute := routev1.Route{
		Spec: routev1.RouteSpec{
			Path: ChallengePath,
			Host: route.Spec.Host,
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromInt(5002),
			},
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: route.Name + "-acme-challenge",
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name + "-acme-challenge",
			Namespace: route.Namespace,
			Labels: map[string]string{
				UsageLabel: "acme-challenge",
			},
			Annotations: map[string]string{
				"router.openshift.io/haproxy.health.check.interval": "10ms",
			},
		},
	}

	challengeRoute := routev1.Route{}
	err = r.client.Get(ctx, types.NamespacedName{Name: desiredChallengeRoute.Name, Namespace: desiredChallengeRoute.Namespace}, &challengeRoute)
	if err != nil {
		if !errors.IsNotFound(err) {
			return
		}
		// Challenge route doesn't exist
		log.Info("Creating challenge route " + desiredChallengeRoute.Spec.Host + " in namespace " + desiredChallengeRoute.Namespace)
		err = r.client.Create(ctx, &desiredChallengeRoute)
		return
	}
	log.Info("Updating challenge route " + desiredChallengeRoute.Spec.Host + " in namespace " + desiredChallengeRoute.Namespace)
	challengeRoute.Spec = desiredChallengeRoute.Spec
	err = r.client.Update(ctx, &challengeRoute)
	return
}

func (r *EncryptedDomainManager) ensureAcmeSvc(ctx context.Context, route routev1.Route) (err error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain/ensureSvc")

	// Create svc that routes ACME traffic to the operator namespace
	desiredChallengeSvc := corev1.Service{
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				UsageLabel: "acme-challenge",
			},
			Ports: []corev1.ServicePort{
				{
					Port:       5002,
					TargetPort: intstr.FromInt(5002),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name + "-acme-challenge",
			Namespace: route.Namespace,
			Labels: map[string]string{
				UsageLabel: "acme-challenge",
			},
		},
	}

	challengeSvc := corev1.Service{}
	err = r.client.Get(ctx, types.NamespacedName{Name: desiredChallengeSvc.Name, Namespace: desiredChallengeSvc.Namespace}, &challengeSvc)
	if err != nil {
		if !errors.IsNotFound(err) {
			return
		}
		// Challenge svc doesn't exist
		log.Info("Creating challenge svc " + desiredChallengeSvc.Name + " in namespace " + desiredChallengeSvc.Namespace)
		err = r.client.Create(ctx, &desiredChallengeSvc)
		return
	}
	log.Info("Updating challenge svc " + desiredChallengeSvc.Name + " in namespace " + desiredChallengeSvc.Namespace)
	challengeSvc.Spec.Ports = desiredChallengeSvc.Spec.Ports
	challengeSvc.Spec.Type = desiredChallengeSvc.Spec.Type
	challengeSvc.Spec.Selector = desiredChallengeSvc.Spec.Selector
	err = r.client.Update(ctx, &challengeSvc)
	return
}

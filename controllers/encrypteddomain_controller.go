/*
Copyright 2022 Manuel Dewald.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"

	routev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"

	errors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	letsencryptv1beta1 "github.com/NautiluX/mockstruct/api/v1beta1"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// EncryptedDomainReconciler reconciles a EncryptedDomain object
type EncryptedDomainReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=letsencrypt.operatingopenshift.org,resources=encrypteddomains,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=letsencrypt.operatingopenshift.org,resources=encrypteddomains/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=letsencrypt.operatingopenshift.org,resources=encrypteddomains/finalizers,verbs=update
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;delete;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EncryptedDomain object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

const (
	challengePath string = "/.well-known/acme-challenge"
	challengePort string = "5002"
)

// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *EncryptedDomainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain")

	domain := letsencryptv1beta1.EncryptedDomain{}
	err := r.Get(ctx, req.NamespacedName, &domain)
	if err != nil {
		return ctrl.Result{}, err
	}

	//Collect matching routes
	log.Info("Collecting routes")
	routes, err := r.getMatchingRoutes(ctx, domain)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(routes) == 0 {
		log.Info("No matching routes found")
		return ctrl.Result{}, nil
	}

	log.Info("Ensuring private key is set")
	// Create a user. New accounts need an email and private key to start.
	privateKey, stopProcessing, err := r.ensurePrivateKey(ctx, domain)
	if stopProcessing || err != nil {
		log.Info("Private Key newly generated or error happened, returning")
		log.Info("Private Key: " + fmt.Sprintf("%v", privateKey))
		return ctrl.Result{}, err
	}
	log.Info("Private Key: " + fmt.Sprintf("%v", privateKey))

	myUser := MyUser{
		Email: domain.Spec.RegistrationMail,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	if domain.Spec.CADirInsecureSSL {
		log.Info("Ignoring insecure SSL on CA directory")
		config.HTTPClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	//config.CADirURL = "http://192.168.99.100:4000/directory"

	config.CADirURL = domain.Spec.CADir
	config.Certificate.KeyType = certcrypto.RSA2048
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return ctrl.Result{}, err
	}

	//TODO: Create route for hostname:5002/.well-known/acme-challenge
	for _, route := range routes {
		challengeRoute := routev1.Route{}
		err = r.Get(ctx, types.NamespacedName{Name: route.Name + "-acme-challenge", Namespace: "le-operator-system"}, &challengeRoute)
		if err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if err == nil {
			r.Delete(ctx, &challengeRoute)
		}

		challengeRoute = *route.DeepCopy()
		challengeRoute.Spec.Path = challengePath
		challengeRoute.Spec.TLS = nil
		challengeRoute.Name = challengeRoute.Name + "-acme-challenge"
		challengeRoute.Namespace = "le-operator-system"
		challengeRoute.Spec.To = routev1.RouteTargetReference{
			Kind: "Service",
			Name: "le-operator-acme-challenge",
		}
		challengeRoute.Spec.Port = &routev1.RoutePort{
			TargetPort: intstr.IntOrString{
				StrVal: challengePort,
			},
		}
		log.Info("Creating challenge route " + challengeRoute.Spec.Host + " in namespace " + challengeRoute.Namespace)
		r.Create(ctx, &challengeRoute)
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", challengePort))
	if err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Registering user " + domain.Spec.RegistrationMail)
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return ctrl.Result{}, err
	}
	myUser.Registration = reg

	//Collect matching hostnames from routes
	domains := []string{}
	for _, route := range routes {
		domains = append(domains, route.Spec.Host)

	}
	log.Info("Requesting certificates for domains " + fmt.Sprintf("%v", domains))
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return ctrl.Result{}, err
	}

	for _, route := range routes {
		route.Spec.TLS.CACertificate = string(certificates.IssuerCertificate)
		route.Spec.TLS.Certificate = string(certificates.Certificate)
		route.Spec.TLS.Key = string(certificates.PrivateKey)
		log.Info("Updating route " + route.Name + " in namespace " + route.Namespace)
		r.Update(ctx, &route)
	}
	//TODO: Save hostnames to status

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)

	return ctrl.Result{}, nil
}

func (r *EncryptedDomainReconciler) getMatchingRoutes(ctx context.Context, domain letsencryptv1beta1.EncryptedDomain) ([]routev1.Route, error) {
	matchingRoutes := []routev1.Route{}

	routes := routev1.RouteList{}
	r.List(ctx, &routes)

	hostnameRegex, err := regexp.Compile(domain.Spec.MatchingHostnames)
	if err != nil {
		return matchingRoutes, err
	}
	for _, route := range routes.Items {
		if hostnameRegex.MatchString(route.Spec.Host) {
			matchingRoutes = append(matchingRoutes, route)
		}
	}

	//TODO: Figure out if certificate is due for renewal or non-existent

	//TODO: Figure out if hostname is matched by a different EncryptedDomain already

	return matchingRoutes, nil
}

func (r *EncryptedDomainReconciler) ensurePrivateKey(ctx context.Context, domain letsencryptv1beta1.EncryptedDomain) (ecdsa.PrivateKey, bool, error) {
	if domain.Status.PrivateKey != "" {
		key, err := decodePrivateKey(domain)
		if err == nil {
			return *key, false, nil
		}
	}

	rsa.GenerateKey(rand.Reader, 256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ecdsa.PrivateKey{}, false, err
	}

	domain.Status.PrivateKey, err = encodePrivateKey(privateKey)
	if err != nil {
		return ecdsa.PrivateKey{}, false, err
	}

	err = r.Status().Update(ctx, &domain)
	if err != nil {
		return ecdsa.PrivateKey{}, false, err
	}

	return *privateKey, true, nil
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

// SetupWithManager sets up the controller with the Manager.
func (r *EncryptedDomainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&letsencryptv1beta1.EncryptedDomain{}).
		Complete(r)
}

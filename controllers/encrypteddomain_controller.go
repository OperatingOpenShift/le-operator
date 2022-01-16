/* Copyright 2022 Manuel Dewald.

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
	"regexp"
	"strconv"

	routev1 "github.com/openshift/api/route/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"

	letsencryptv1beta1 "github.com/operatingopenshift/le-operator/api/v1beta1"
	"github.com/operatingopenshift/le-operator/pkg/encdomain"

	"github.com/go-acme/lego/v4/registration"
	"k8s.io/apimachinery/pkg/api/errors"
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
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes/custom-host,verbs=get;list;watch;create;delete;update;patch
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;delete;update;patch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;delete;update;patch
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;delete;update;patch

func (r *EncryptedDomainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	m := encdomain.New(r.Client)
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain")

	domain := letsencryptv1beta1.EncryptedDomain{}
	err := r.Get(ctx, req.NamespacedName, &domain)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if domain.DeletionTimestamp != nil {
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
	log.Info(strconv.Itoa(len(routes)) + " matching routes found")

	log.Info("Creating LE client")
	client, user, stopProcessing, err := m.InitializeLeClient(ctx, domain)
	if stopProcessing || err != nil {
		return ctrl.Result{}, err
	}

	// New users will need to register
	log.Info("Registering user " + domain.Spec.RegistrationMail)
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return ctrl.Result{}, err
	}
	user.Registration = reg

	for _, route := range routes {
		// Check if current EncryptedDomain is responsible for this route
		managingDomain := m.GetManagingDomain(ctx, route)
		if managingDomain == nil || managingDomain.Namespace != domain.Namespace || managingDomain.Name != domain.Name {
			continue
		}

		domainModified, _, err := m.EnsureCertificate(ctx, client, domain, route)
		if err != nil || domainModified {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *EncryptedDomainReconciler) getMatchingRoutes(ctx context.Context, domain letsencryptv1beta1.EncryptedDomain) ([]routev1.Route, error) {
	matchingRoutes := []routev1.Route{}

	options := client.ListOptions{
		Namespace: domain.Namespace,
	}
	routes := routev1.RouteList{}
	r.List(ctx, &routes, &options)

	hostnameRegex, err := regexp.Compile(domain.Spec.MatchingHostnames)
	if err != nil {
		return matchingRoutes, err
	}
	for _, route := range routes.Items {
		if !hostnameRegex.MatchString(route.Spec.Host) {
			continue
		}
		label, ok := route.Labels[encdomain.UsageLabel]
		if ok && label == "acme-challenge" {
			continue

		}
		matchingRoutes = append(matchingRoutes, route)
	}

	return matchingRoutes, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EncryptedDomainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&letsencryptv1beta1.EncryptedDomain{}).
		Complete(r)
}

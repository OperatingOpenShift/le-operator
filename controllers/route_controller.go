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

	"github.com/go-acme/lego/v4/registration"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/operatingopenshift/le-operator/pkg/encdomain"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RouteReconciler reconciles a Route object
type RouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=route.openshift.io.operatingopenshift.org,resources=routes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io.operatingopenshift.org,resources=routes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=route.openshift.io.operatingopenshift.org,resources=routes/finalizers,verbs=update

func (r *RouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.Log.WithName("controllers").WithName("EncryptedDomain")

	m := encdomain.New(r.Client)

	route := routev1.Route{}
	err := r.Get(ctx, req.NamespacedName, &route)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if route.DeletionTimestamp != nil {
		return ctrl.Result{}, err
	}

	log.Info("Reconciling route: " + route.Name)

	label, ok := route.Labels[encdomain.UsageLabel]
	if ok && label == "acme-challenge" {
		log.Info("Ignoring acme-challenge route")
		return ctrl.Result{}, nil
	}

	// Figure out if this route should be managed by the operator
	domain := m.GetManagingDomain(ctx, route)
	if domain == nil {
		log.Info("No matching encrypted domain found for hostname " + route.Spec.Host)
		return ctrl.Result{}, nil
	}

	log.Info("Creating LE client")
	client, user, stopProcessing, err := m.InitializeLeClient(ctx, *domain)
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
	//No need to register the user, it will be done by the encrypted domain controller

	// Handle certificate renewal
	log.Info("Ensuring a LE cert is set")
	_, _, err = m.EnsureCertificate(ctx, client, *domain, route)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&routev1.Route{}).
		Complete(r)
}

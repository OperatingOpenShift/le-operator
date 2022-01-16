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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EncryptedDomainSpec defines the desired state of EncryptedDomain
type EncryptedDomainSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// MatchingHostnames is a regex describing which hostnames to generate certificates for.
	MatchingHostnames string `json:"matchingHostnames,omitempty"`

	// CA directory Endpoint to use for certificate requests
	CADir string `json:"caDir,omitempty"`

	// Ignore invalid SSL certificate on CADir
	CADirInsecureSSL bool `json:"caDirInsecureSSL,omitempty"`

	// Mail address to use for registration with CA directory
	RegistrationMail string `json:"registrationMail,omitempty"`
}

// EncryptedDomainStatus defines the observed state of EncryptedDomain
type EncryptedDomainStatus struct {
	GeneratedCertificates map[string]GeneratedCertificate `json:"generatedCertificate,omitempty"`
	PrivateKey            string                          `json:"privateKey,omitempty"`
}

type GeneratedCertificate struct {
	Hostname    string `json:"hostname,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Key         string `json:"key,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// EncryptedDomain is the Schema for the encrypteddomains API
type EncryptedDomain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EncryptedDomainSpec   `json:"spec,omitempty"`
	Status EncryptedDomainStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// EncryptedDomainList contains a list of EncryptedDomain
type EncryptedDomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EncryptedDomain `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EncryptedDomain{}, &EncryptedDomainList{})
}

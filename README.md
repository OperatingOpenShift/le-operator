# le-operator

This is a noperator to auomatically renew certificates of OpenShift routes.

It's currently not considered production-ready and is only built to show-case how simple it is to implement such an operator with [Operator SDK](https://sdk.operatorframework.io/) and [lego](https://github.com/go-acme/lego).

# Usage

Install to your cluster by running `make docker-build docker-push deploy IMG=your/docker-repository`, where you specify the image registry to push to with the `IMG` variable.

Create an EncryptedDomain resource to match all routes of your system for which you want to automatically renew certificates:

```
apiVersion: letsencrypt.operatingopenshift.org/v1beta1
kind: EncryptedDomain
metadata:
  name: encrypteddomain-sample
  namespace: default
spec:
  matchingHostnames: "^my-route.apps.mycluster.com$"
  caDir: "https://acme-staging-v02.api.letsencrypt.org/directory"
  RegistrationMail: "le-operator@operatingopenshift.org"
```

Le-operator will find all routes matching the hostname and care for certificate renewal using the ACME protocol against the provided directory.

The matchingHostnames property is a regex that you can use to customize which routes should be managed by this EncryptedDomain CR.
Le-operator will create a separate domain for each route matching the regex.
It as well supports managing multiple routes with the same hostname, typically used for [path-based routing](https://docs.openshift.com/container-platform/4.9/networking/routes/route-configuration.html#nw-path-based-routes_route-configuration).

The above example uses the [let's encrypt staging environment](https://letsencrypt.org/docs/staging-environment/).


# Development

For development, you can deploy a [Pebble](https://github.com/letsencrypt/pebble) instance to an OpenShift cluster by applying the file in [Pebble deployment](hack/pebble.yaml).

That allows as well to test the workflow with a cluster that is not publicly reachable, such as a [CRC](https://github.com/code-ready/crc) cluster.

Use it's service as configuration in the `EncryptedDomain` CR:

```
apiVersion: letsencrypt.operatingopenshift.org/v1beta1
kind: EncryptedDomain
metadata:
  name: encrypteddomain-sample
  namespace: default
spec:
  matchingHostnames: "^my-route.apps-crc.testing$"
  caDir: "https://pebble:14000/dir"
  RegistrationMail: "le-operator@operatingopenshift.org"
```

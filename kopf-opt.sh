#!/bin/sh
KOPF_OPTIONS="--log-format=json"
  
# Restrict watch to operator namespace.
KOPF_NAMESPACED=false

# Peering to orchestrate multiple replicas if scaled up.
KOPF_PEERING=${KOPF_PEERING:-openshift-oauth-client-authorizer}

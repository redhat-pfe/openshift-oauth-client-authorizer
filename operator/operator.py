#!/usr/bin/env python3

import kopf
import kubernetes
import logging
import os
import threading
import time

operator_domain = os.environ.get('OPERATOR_DOMAIN', 'pfe.redhat.com')
operator_api_version = os.environ.get('OPERATOR_API_VERSION', 'v1')
timer_interval = int(os.environ.get('TIMER_INTERVAL', 600))

if os.path.exists('/run/secrets/kubernetes.io/serviceaccount'):
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()


class InfiniteRelativeBackoff:
    def __init__(self, initial_delay=0.1, scaling_factor=2, maximum=60):
        self.initial_delay = initial_delay
        self.scaling_factor = scaling_factor
        self.maximum = maximum

    def __iter__(self):
        delay = self.initial_delay
        while True:
            if delay > self.maximum:
                yield self.maximum
            else:
                yield delay
                delay *= self.scaling_factor


class OAuthClientAuthorization:
    def __init__(self, resource):
        self.resource = resource

    @property
    def api_version(self):
        return 'oauth.openshift.io/v1'

    @property
    def automation_label_value(self):
        return self.resource['metadata'].get('labels', {}).get(f"{operator_domain}/OAuthClientAuthorizationAutomation")

    @property
    def kind(self):
        return 'OAuthClientAuthorization'

    @property
    def name(self):
        return self.resource['metadata']['name']

    @property
    def reference(self):
        metadata = self.resource['metadata']
        return dict(
            apiVersion = self.api_version,
            kind = self.kind,
            name = self.name,
            uid = self.uid,
        )

    @property
    def scopes(self):
        return self.resource['scopes']

    @property
    def uid(self):
        return self.resource['metadata']['uid']

    @property
    def user_uid(self):
        return self.resource['userUID']

    def delete(self):
        try:
            custom_objects_api.delete_cluster_custom_object(
                'oauth.openshift.io', 'v1', 'oauthclientauthorizations', self.name
            )
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                raise

class OAuthClientAuthorizationAutomation:
    instances = []
    register_lock = threading.Lock()

    @staticmethod
    def handle_user(user):
        with OAuthClientAuthorizationAutomation.register_lock:
            for instance in OAuthClientAuthorizationAutomation.instances:
                instance.authorize_user(user)

    def __init__(
        self,
        logger=None,
        name=None,
        namespace=None,
        spec=None,
        uid=None,
        **_
    ):
        self.logger = logger
        self.name = name
        self.namespace = namespace
        self.spec = spec
        self.uid = uid

    @property
    def api_version(self):
        return f"{operator_domain}/{operator_api_version}",

    @property
    def client_name(self):
        return f"system:serviceaccount:{self.namespace}:{self.service_account_name}"

    @property
    def kind(self):
        return 'OAuthClientAuthorizationAutomation'

    @property
    def reference(self):
        return dict(
            apiVersion = self.api_version,
            kind = self.kind,
            name = self.name,
            uid = self.uid,
        )

    @property
    def scopes(self):
        return self.spec.get('scopes', ['user:check-access', 'user:info'])

    @property
    def service_account_name(self):
        return self.spec['serviceAccountName']

    def authorize_user(self, user):
        authorization = None
        authorization_name = f"{user.name}:{self.client_name}"
        try:
            authorization = OAuthClientAuthorization(
                custom_objects_api.get_cluster_custom_object(
                    'oauth.openshift.io', 'v1', 'oauthclientauthorizations', authorization_name
                )
            )
            if authorization.scopes != self.scopes \
            or authorization.user_uid != user.uid \
            or authorization.automation_label_value != self.name:
                authorization.resource['scopes'] = self.scopes
                authorization.resource['userUID'] = user.uid
                if 'labels' in authorization.resource['metadata']:
                    authorization.resource['metadata']['labels'][f"{operator_domain}/OAuthClientAuthorizationAutomation"] = self.uid
                else:
                    authorization.resource['metadata']['labels'] = {
                        f"{operator_domain}/OAuthClientAuthorizationAutomation": self.uid
                    }
                authorization = OAuthClientAuthorization(
                    custom_objects_api.patch_cluster_custom_object(
                        'oauth.openshift.io', 'v1', 'oauthclientauthorizations', authorization_name,
                        authorization.resource
                    )
                )
            return authorization
        except kubernetes.client.rest.ApiException as e:
            if e.status == 404:
                pass
            elif e.status == 409:
                self.logger.warning(
                    "Conflict while updating OAuthClientAuthorization",
                    extra = dict(
                        OAuthClientAuthorization = authorization.reference
                    )
                )
                return authorization
            else:
                raise

        # Not found, create authorization
        attempt_number = 1
        while True:
            try:
                authorization = OAuthClientAuthorization(
                    custom_objects_api.create_cluster_custom_object(
                        'oauth.openshift.io', 'v1', 'oauthclientauthorizations',
                        {
                            "apiVersion": "oauth.openshift.io/v1",
                            "kind": "OAuthClientAuthorization",
                            "metadata": {
                                "name": authorization_name,
                                "labels": {
                                    f"{operator_domain}/OAuthClientAuthorizationAutomation": self.uid
                                },
                            },
                            "clientName": self.client_name,
                            "userName": user.name,
                            "userUID": user.uid,
                            "scopes": self.scopes,
                        }
                    )
                )
                self.logger.info(
                    'OAuthClientAuthorization created',
                    extra = dict(
                        User = user.reference,
                        OAuthClientAuthorization = authorization.reference,
                    )
                )
                return authorization
            except kubernetes.client.rest.ApiException as e:
                if e.status == 409:
                    self.logger.info(
                        'Conflict while creating OAuthClientAuthorization',
                        extra = dict(
                            User = user.reference
                        )
                    )
                    return OAuthClientAuthorization(
                        custom_objects_api.get_cluster_custom_object(
                            'oauth.openshift.io', 'v1', 'oauthclientauthorizations', authorization_name
                        )
                    )
                elif attempt_number < 5:
                    self.logger.exception('Error while creating OAuthClientAuthorization')
                    time.sleep(1)
                else:
                    raise

    def handle_deletion(self):
        for resource in custom_objects_api.list_cluster_custom_object(
            'oauth.openshift.io', 'v1', 'oauthclientauthorizations',
            label_selector=f"{operator_domain}/OAuthClientAuthorizationAutomation={self.uid}"
        ).get('items', []):
            authorization = OAuthClientAuthorization(resource)
            authorization.delete()

    def register(self):
        with OAuthClientAuthorizationAutomation.register_lock:
            for i, instance in enumerate(OAuthClientAuthorizationAutomation.instances):
                if instance.name == self.name:
                    OAuthClientAuthorizationAutomation.instances[i] = self
                    self.logger.info('updated')
                    return
            OAuthClientAuthorizationAutomation.instances.append(self)
            self.logger.info('registered')

    def run(self):
        for resource in custom_objects_api.list_cluster_custom_object(
            'user.openshift.io', 'v1', 'users'
        ).get('items', []):
            user = User(resource)
            self.authorize_user(user)

    def unregister(self):
        with OAuthClientAuthorizationAutomation.register_lock:
            for i, instance in enumerate(OAuthClientAuthorizationAutomation.instances):
                if instance.name == self.name:
                    OAuthClientAuthorizationAutomation.instances.pop(i)
                    self.logger.info('unregistered')

class User:
    def __init__(self, resource, logger=None):
        self.logger = logger
        self.resource = resource

    @property
    def api_version(self):
        return 'user.openshift.io/v1'

    @property
    def kind(self):
        return 'User'

    @property
    def name(self):
        return self.resource['metadata']['name']

    @property
    def reference(self):
        return dict(
            apiVersion = self.api_version,
            kind = self.kind,
            name = self.name,
            uid = self.uid,
        )

    @property
    def uid(self):
        return self.resource['metadata']['uid']

    def handle_deletion(self):
        for resource in custom_objects_api.list_cluster_custom_object(
            'oauth.openshift.io', 'v1', 'oauthclientauthorizations',
            field_selector=f"userName={self.name}"
        ).get('items', []):
            authorization = OAuthClientAuthorization(resource)
            self.logger.info(authorization.uid)
            authorization.delete()
            self.logger.info(authorization.uid)
            self.logger.info(
                'Delete OAuthClientAuthorization for deleted User',
                extra = dict(OAuthClientAuthorization=authorization.reference)
            )

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    # Never give up from network errors
    settings.networking.error_backoffs = InfiniteRelativeBackoff()

    # Use operator domain as finalizer
    settings.persistence.finalizer = operator_domain

    # Store progress in status.
    settings.persistence.progress_storage = kopf.StatusProgressStorage(field='status.kopf.progress')

    # Only create events for warnings and errors
    settings.posting.level = logging.WARNING

    # Disable scanning for CustomResourceDefinitions
    settings.scanning.disabled = True

@kopf.on.create(operator_domain, operator_api_version, 'oauthclientauthorizationautomations')
@kopf.on.resume(operator_domain, operator_api_version, 'oauthclientauthorizationautomations')
@kopf.on.update(operator_domain, operator_api_version, 'oauthclientauthorizationautomations')
def process_automation(**kwargs):
    automation = OAuthClientAuthorizationAutomation(**kwargs)
    automation.register()
    automation.run()

@kopf.on.timer(operator_domain, operator_api_version, 'oauthclientauthorizationautomations', interval=timer_interval)
def automation_timer(**kwargs):
    automation = OAuthClientAuthorizationAutomation(**kwargs)
    automation.run()

@kopf.on.delete(operator_domain, operator_api_version, 'oauthclientauthorizationautomations')
def process_deletion(**kwargs):
    automation = OAuthClientAuthorizationAutomation(**kwargs)
    automation.unregister()
    automation.handle_deletion()

@kopf.on.event('user.openshift.io', 'v1', 'users')
def on_user_event(event, logger, **_):
    event_type = event.get('type')
    resource = event.get('object')
    if not resource \
    or resource.get('kind') != 'User':
        logger.warning(event)
        return
    if event_type == 'DELETED':
        user = User(resource, logger)
        user.handle_deletion()
    else:
        user = User(resource, logger)
        OAuthClientAuthorizationAutomation.handle_user(user)

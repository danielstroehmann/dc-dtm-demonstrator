# DTM REST API – endpoint index

Generated on 2026-10-23 from the OpenAPI spec <https://dev.digicert.com/api-reference/openapi/device-trust.json> (343 operations, 291 paths). All paths relative to `https://<host>/devicetrustmanager`. Do not edit by hand – regenerate:

```bash
curl -sL https://dev.digicert.com/api-reference/openapi/device-trust.json -o dt.json
jq -r '.paths|to_entries[]|.key as $p|.value|to_entries[]|select(.key|test("get|post|put|patch|delete"))|[(.value.tags[0]//"-"),(.key|ascii_upcase),$p,(.value.summary//"")]|@tsv' dt.json | sort
```

## ACME

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/account/{acme_account_id}` | Get ACME account |
| GET | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/account/{acme_account_id}` | Get ACME account (with device group) |
| GET | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/directory` | Get ACME directory (with device group) |
| GET | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/new-nonce` | Get new nonce (with device group) |
| GET | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/directory` | Get ACME directory |
| GET | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/new-nonce` | Get new nonce |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/account/{acme_account_id}` | Update ACME account |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/authorization/{acme_authorization_id}` | Get authorization |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/authorization/{acme_authorization_id}/authorization/{acme_challenge_id}` | Respond to challenge |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/certificate/{acme_certificate_id}` | Download certificate |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/account/{acme_account_id}` | Update ACME account (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/authorization/{acme_authorization_id}` | Get authorization (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/authorization/{acme_authorization_id}/authorization/{acme_challenge_id}` | Respond to challenge (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/certificate/{acme_certificate_id}` | Download certificate (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/key-change` | Key change (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/new-account` | Create new ACME account (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/order` | Create new certificate order (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/order/{acme_order_id}` | Get order status (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/order/{acme_order_id}/finalize` | Finalize order (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/orders` | List orders for account (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/device-group/{device_group_id}/revoke` | Revoke certificate (with device group) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/key-change` | Key change (rollover) |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/new-account` | Create new ACME account |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/order` | Create new certificate order |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/order/{acme_order_id}` | Get order status |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/order/{acme_order_id}/finalize` | Finalize order |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/orders` | List orders for account |
| POST | `/certificate-issuance-service/api/v1/acme/{certificate_policy_id}/revoke` | Revoke certificate |

## ACME Authentication

| Method | Path | Purpose |
|---|---|---|
| DELETE | `/authentication-service/api/v2/acme-authentication/{acme_auth_id}` | Delete ACME authentication |
| GET | `/authentication-service/api/v2/acme-authentication` | Search ACME authentications |
| GET | `/authentication-service/api/v2/acme-authentication/account/{account_id}` | Search by account |
| GET | `/authentication-service/api/v2/acme-authentication/certificate-policy/{certificate_policy_id}` | Search by certificate policy |
| GET | `/authentication-service/api/v2/acme-authentication/device-group/{device_group_id}` | Search by device group |
| GET | `/authentication-service/api/v2/acme-authentication/division/{division_id}` | Search by division |
| GET | `/authentication-service/api/v2/acme-authentication/{acme_auth_id}` | Get ACME authentication by ID |
| GET | `/authentication-service/api/v2/acme-authentication/{acme_auth_id}/secret` | Get ACME authentication secret |
| POST | `/authentication-service/api/v2/acme-authentication` | Create ACME authentication |
| PUT | `/authentication-service/api/v2/acme-authentication/{acme_auth_id}` | Update ACME authentication |
| PUT | `/authentication-service/api/v2/acme-authentication/{acme_auth_id}/secret` | Regenerate ACME authentication secret |

## API Helper

| Method | Path | Purpose |
|---|---|---|
| GET | `/release/api/v4/api-helper/full-spec/{resource}/{id}` | Retrieve all endpoint specifications for releases by artifact |
| GET | `/release/api/v4/api-helper/{resource}/search` | Retrieve search endpoint specification for releases |
| GET | `/release/api/v4/api-helper/{resource}/{id}/{action}` | Retrieve endpoint specification for a specific release action |

## Alert Settings

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-configuration-service/api-ui/v1/alert-settings` | Search alert settings |
| GET | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}` | Get alert setting by ID |
| GET | `/certificate-configuration-service/api/v1/alert-settings/account/{accountId}/active/{type}` | Get active alert settings by account and type |
| GET | `/certificate-configuration-service/api/v1/alert-settings/active/{type}` | Get active alert settings by type |
| GET | `/certificate-configuration-service/api/v1/alert-settings/has-active/{type}` | Check if active alert exists for type |
| GET | `/certificate-configuration-service/api/v1/alert-settings/{alertSettingsId}/certificate-policies` | Get certificate policies for alert setting |
| GET | `/certificate-configuration-service/api/v1/alert-settings/{alertSettingsId}/notification` | Get alert notification |
| GET | `/certificate-configuration-service/api/v1/alert-settings/{id}` | Get alert setting by ID (External) |
| POST | `/certificate-configuration-service/api-ui/v1/alert-settings` | Create alert setting |
| POST | `/certificate-configuration-service/api-ui/v1/alert-settings/test-webhook` | Test webhook |
| POST | `/certificate-configuration-service/api/v1/alert-settings/{alertSettingsId}/notification` | Create alert notification |
| PUT | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}` | Update alert setting |
| PUT | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}/delete` | Delete alert setting |
| PUT | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}/disable` | Disable alert setting |
| PUT | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}/enable` | Enable alert setting |
| PUT | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}/remove-enrollment-profile/{enrollmentProfileId}` | Remove enrollment profile from alert setting |
| PUT | `/certificate-configuration-service/api-ui/v1/alert-settings/{id}/undelete` | Undelete alert setting |

## Artifact logs

| Method | Path | Purpose |
|---|---|---|
| GET | `/artifacts/api/v4/artifact/log/{artifact_log_id}` | Retrieve artifact log by Id |
| GET | `/artifacts/api/v4/artifact/logs` | Retrieve artifact logs |

## Artifacts

| Method | Path | Purpose |
|---|---|---|
| GET | `/artifacts/api/v4/artifact` | get a list of artifacts |
| GET | `/artifacts/api/v4/artifact/by-release/{release_id}` | get a list of artifacts |
| GET | `/artifacts/api/v4/artifact/{artifact_id}` | Get an artifact by Id. |
| GET | `/artifacts/api/v4/artifact/{artifact_id}/download` | Download Artifact |
| GET | `/artifacts/api/v4/artifact/{artifact_id}/download/manifest` | Download artifact manifest |
| PATCH | `/artifacts/api/v4/artifact/{artifact_id}/disable` | Disable an artifact |
| PATCH | `/artifacts/api/v4/artifact/{artifact_id}/enable` | Enable an artifact |
| POST | `/artifacts/api/v4/artifact` | Create an artifact. |
| PUT | `/artifacts/api/v4/artifact/{artifact_id}` | Update an artifact |

## Audit Logs

| Method | Path | Purpose |
|---|---|---|
| GET | `/audit-log-service/api/v1/audit-log` | Get audit log records |

## Authentication Certificates

| Method | Path | Purpose |
|---|---|---|
| GET | `/authentication-service/api/v1/authentication-certificate` | List authentication certificates |
| GET | `/authentication-service/api/v1/authentication-certificate/{authentication_certificate_id}` | Get authentication certificate details |
| POST | `/authentication-service/api/v1/authentication-certificate` | Create authentication certificate |
| PUT | `/authentication-service/api/v1/authentication-certificate/{authentication_certificate_id}` | Update authentication certificate |
| PUT | `/authentication-service/api/v1/authentication-certificate/{authentication_certificate_id}/delete` | Delete authentication certificate |
| PUT | `/authentication-service/api/v1/authentication-certificate/{authentication_certificate_id}/disable` | Disable authentication certificate |
| PUT | `/authentication-service/api/v1/authentication-certificate/{authentication_certificate_id}/enable` | Enable authentication certificate |
| PUT | `/authentication-service/api/v1/authentication-certificate/{authentication_certificate_id}/undelete` | Restore authentication certificate |

## Authentication Passcodes

| Method | Path | Purpose |
|---|---|---|
| GET | `/authentication-service/api/v1/passcode` | List authentication passcodes |
| GET | `/authentication-service/api/v1/passcode/{passcode_id}` | Get authentication passcode |
| POST | `/authentication-service/api/v1/passcode` | Create new authentication passcode |
| PUT | `/authentication-service/api/v1/passcode/{passcode_id}` | Update authentication passcode |
| PUT | `/authentication-service/api/v1/passcode/{passcode_id}/delete` | Delete authentication passcode |
| PUT | `/authentication-service/api/v1/passcode/{passcode_id}/disable` | Disable authentication passcode |
| PUT | `/authentication-service/api/v1/passcode/{passcode_id}/enable` | Enable authentication passcode |
| PUT | `/authentication-service/api/v1/passcode/{passcode_id}/undelete` | Restore deleted authentication passcode |

## Authentication Policies

| Method | Path | Purpose |
|---|---|---|
| GET | `/authentication-service/api/v1/authentication-policy` | List authentication policies |
| GET | `/authentication-service/api/v1/authentication-policy/{authentication_policy_id}` | Get authentication policy by ID |
| POST | `/authentication-service/api/v1/authentication-policy` | Create authentication policy |
| PUT | `/authentication-service/api/v1/authentication-policy/{authentication_policy_id}` | Update authentication policy |
| PUT | `/authentication-service/api/v1/authentication-policy/{authentication_policy_id}/delete` | Delete Authentication Policy |
| PUT | `/authentication-service/api/v1/authentication-policy/{authentication_policy_id}/disable` | Disable authentication policy |
| PUT | `/authentication-service/api/v1/authentication-policy/{authentication_policy_id}/enable` | Enable authentication policy |
| PUT | `/authentication-service/api/v1/authentication-policy/{authentication_policy_id}/undelete` | Restore authentication policy |

## Batch Certificate Enrollment

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-batch-service/api/v1/jobs` | List batch enrollment jobs |
| GET | `/certificate-batch-service/api/v1/jobs/{job_id}` | Get batch enrollment job by ID |
| GET | `/certificate-batch-service/api/v1/jobs/{job_id}/download/report` | Download batch enrollment job report |
| GET | `/certificate-batch-service/api/v1/jobs/{job_id}/download/result` | Download batch enrollment job result |
| POST | `/certificate-batch-service/api/v1/jobs/auth-certificate-upload` | Create batch authentication certificate upload job |
| POST | `/certificate-batch-service/api/v1/jobs/certificate-enroll` | Create batch certificate enrollment job |
| POST | `/certificate-batch-service/api/v1/jobs/device-registration` | Create batch device registration enrollment job |
| POST | `/certificate-batch-service/api/v1/jobs/passcode-import` | Create batch passcode import job |
| PUT | `/certificate-batch-service/api/v1/jobs/{job_id}/approve` | Approve batch enrollment job |
| PUT | `/certificate-batch-service/api/v1/jobs/{job_id}/reject` | Reject batch enrollment job |

## Blueprint

| Method | Path | Purpose |
|---|---|---|
| GET | `/blueprint-service/api/v1/blueprints` | Search blueprints |
| GET | `/blueprint-service/api/v1/blueprints/ledger/{blueprint_ledger_id}/status` | Get blueprint execution status |
| POST | `/blueprint-service/api/v1/blueprints/{blueprint_id}/execute` | Execute blueprint |

## Bootstrap Configuration

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/bootstrap-config/download` | Download zipped bootstrap config file and certificates by certificate |
| GET | `/api/v4/bootstrap-config/download/certificates` | Download Zipped certificates by certificate |
| GET | `/api/v4/bootstrap-config/download/config` | Download Bootstrap Configuration by certificate |
| GET | `/api/v4/bootstrap-config/download/{device_id}` | Download zipped bootstrap config file and certificates by device id |
| GET | `/api/v4/bootstrap-config/download/{device_id}/certificates` | Download Zipped certificates by device id |
| GET | `/api/v4/bootstrap-config/download/{device_id}/config` | Download Bootstrap Configuration by device id |

## Certificate Policies

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-configuration-service/api/v2/certificate-policy` | List certificate policies |
| GET | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}` | Get certificate policy by ID |
| GET | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}/assignable-ca` | List assignable ICA's |
| GET | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}/enrollment-specification` | Get certificate policy enrollment specification |
| GET | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}/example-request` | Get example certificate request by certificate policy ID |
| GET | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}/issuer` | Get issuing ICA |
| GET | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}/status` | Get certificate policy status |
| POST | `/certificate-configuration-service/api/v2/certificate-policy` | Create certificate policy |
| PUT | `/certificate-configuration-service/api/v2/certificate-policy/{certificate_policy_id}` | Update certificate policy |

## Certificate Profiles

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-configuration-service/api/v1/certificate-profile` | List certificate profiles |
| GET | `/certificate-configuration-service/api/v1/certificate-profile/{certificate_profile_id}` | Get certificate profile |
| POST | `/certificate-configuration-service/api/v1/certificate-profile` | Create certificate profile |
| PUT | `/certificate-configuration-service/api/v1/certificate-profile/{certificate_profile_id}` | Update certificate profile |
| PUT | `/certificate-configuration-service/api/v1/certificate-profile/{certificate_profile_id}/delete` | Delete certificate profile |
| PUT | `/certificate-configuration-service/api/v1/certificate-profile/{certificate_profile_id}/disable` | Disable certificate profile |
| PUT | `/certificate-configuration-service/api/v1/certificate-profile/{certificate_profile_id}/enable` | Enable certificate profile |
| PUT | `/certificate-configuration-service/api/v1/certificate-profile/{certificate_profile_id}/undelete` | Restore certificate profile |

## Certificate Templates

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-configuration-service/api/v1/certificate-template` | List certificate templates |
| GET | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}` | Get certificate template details |
| POST | `/certificate-configuration-service/api/v1/certificate-template` | Create certificate template |
| POST | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}/clone` | Clone certificate template |
| PUT | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}` | Update certificate template |
| PUT | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}/delete` | Delete certificate template |
| PUT | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}/disable` | Disable certificate template |
| PUT | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}/enable` | Enable certificate template |
| PUT | `/certificate-configuration-service/api/v1/certificate-template/{certificate_template_id}/undelete` | Restore certificate template |

## Certificate requests

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-issuance-service/api/v2/certificate-request/{certificate_request_id}/status` | Certificate request status |
| POST | `/certificate-issuance-service/api/v2/certificate/{certificate_id}/download-approved-certificate` | Download approved certificate |

## Certificates

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-issuance-service/api/v2/certificate` | List Certificates |
| GET | `/certificate-issuance-service/api/v2/certificate-status/certificate-id/{certificate_id}` | Get certificate status by ID |
| GET | `/certificate-issuance-service/api/v2/certificate-status/{certificate_serial_number}` | Get certificate status by serial number |
| GET | `/certificate-issuance-service/api/v2/certificate/certificate-value/{certificate_value}` | List certificates by certificate value |
| GET | `/certificate-issuance-service/api/v2/certificate/serial-number/{certificate_serial_number}/download/{format}` | Download a certificate by serial number |
| GET | `/certificate-issuance-service/api/v2/certificate/{certificate_id}/download/{format}` | Download a certificate by ID |
| GET | `/certificate-issuance-service/api/v2/certificate/{certificate_id}/example-request` | Get example certificate request by certificate ID |
| POST | `/certificate-issuance-service/api/v2/certificate` | Request a certificate |
| PUT | `/certificate-issuance-service/api/v2/certificate/serial-number/{certificate_serial_number}/renew` | Renew a certificate by certificate serial number |
| PUT | `/certificate-issuance-service/api/v2/certificate/serial-number/{certificate_serial_number}/revoke` | Revoke a certificate by serial number |
| PUT | `/certificate-issuance-service/api/v2/certificate/{certificate_id}/renew` | Renew a certificate by ID |
| PUT | `/certificate-issuance-service/api/v2/certificate/{certificate_id}/revoke` | Revoke a certificate by certificate ID |

## Cloud Platform Policy

| Method | Path | Purpose |
|---|---|---|
| DELETE | `/cloud-platform-policy/api/v4/cloud-platform-policy/device-group-policy-configuration/{id}` | Delete a device group policy configuration |
| DELETE | `/cloud-platform-policy/api/v4/cloud-platform-policy/mqtt-broker/{id}` | Delete a mqtt broker |
| DELETE | `/cloud-platform-policy/api/v4/cloud-platform-policy/{id}` | Delete a cloud platform policy |
| GET | `/cloud-platform-policy/api/v4/cloud-platform-policy` | Search cloud platform policies |
| GET | `/cloud-platform-policy/api/v4/cloud-platform-policy/recently-assigned-policies` | Retrieves recently assigned cloud platform policies |
| GET | `/cloud-platform-policy/api/v4/cloud-platform-policy/{id}` | Fetch a cloud platform policy by ID |
| PATCH | `/cloud-platform-policy/api/v4/cloud-platform-policy/device-group-policy-configuration/disable/{id}` | Disable a device group policy configuration |
| PATCH | `/cloud-platform-policy/api/v4/cloud-platform-policy/device-group-policy-configuration/enable/{id}` | Enable a device group policy configuration |
| PATCH | `/cloud-platform-policy/api/v4/cloud-platform-policy/disable/{id}` | Disable a cloud platform policy |
| PATCH | `/cloud-platform-policy/api/v4/cloud-platform-policy/enable/{id}` | Enable a cloud platform policy |
| PATCH | `/cloud-platform-policy/api/v4/cloud-platform-policy/mqtt-broker/disable/{id}` | Disable a mqtt broker |
| PATCH | `/cloud-platform-policy/api/v4/cloud-platform-policy/mqtt-broker/enable/{id}` | Enable a mqtt broker |
| POST | `/api/v4/cloud-platform-policy/cloud-provision` | Onboard a device to cloud platform |
| POST | `/cloud-platform-policy/api/v4/cloud-platform-policy` | Create a cloud platform policy |
| PUT | `/cloud-platform-policy/api/v4/cloud-platform-policy/{id}` | Update Cloud Platform Policy |

## Dashboard

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/dashboard/aggregation/cloud-platform-device-by-status` | Aggregate devices by cloud platform device status |
| GET | `/api/v4/dashboard/aggregation/connection-status` | Device Aggregation by connection status |
| GET | `/api/v4/dashboard/aggregation/device-by-cloud-platform-status` | Aggregate devices by device cloud platform policy status |
| GET | `/api/v4/dashboard/aggregation/device-states` | Device Aggregation by device state |
| GET | `/api/v4/dashboard/histogram/certificates-by-types` | Certificates histogram by type |
| GET | `/api/v4/dashboard/histogram/cloud-platform-policy-by-states` | Cloud Platform Policy Date Histogram by cloud platform policy states |
| GET | `/api/v4/dashboard/histogram/deployments-by-states` | Deployment Date Histogram by states |
| GET | `/api/v4/dashboard/histogram/device-by-cloud-platform-status` | Cloud Platform Device Date Histogram by device cloud platform status. |
| GET | `/api/v4/dashboard/histogram/device-by-connection-states` | Device Date Histogram by device connection states |
| GET | `/api/v4/dashboard/histogram/device-by-operational-status` | Device Date Histogram by device operational status |
| GET | `/api/v4/dashboard/histogram/device-by-states` | Device Date Histogram by device states |
| GET | `/api/v4/dashboard/histogram/device-group` | Device Group Date Histogram by division |

## Deployment logs

| Method | Path | Purpose |
|---|---|---|
| GET | `/release/api/v4/deployment/logs` | Retrieve deployment logs |
| GET | `/release/api/v4/deployment/logs/download` | Retrieve deployment logs report |

## Deployments

| Method | Path | Purpose |
|---|---|---|
| GET | `/release/api/v4/deployment` |  |
| GET | `/release/api/v4/deployment/by-artifact/{artifact_id}` |  |
| GET | `/release/api/v4/deployment/{deployment_id}` |  |
| GET | `/release/api/v4/deployment/{deployment_id}/summary` |  |
| PATCH | `/release/api/v4/deployment/{deployment_id}/abort` |  |
| POST | `/release/api/v4/deployment` |  |
| PUT | `/release/api/v4/deployment/{deployment_id}` | Update a deployment |

## Device

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/device` | List devices |
| GET | `/api/v4/device/certificates` | List device certificates |
| GET | `/api/v4/device/cloud-platform-policies` | List Cloud platform policies by device |
| GET | `/api/v4/device/metrics` | Get device metrics summary |
| GET | `/api/v4/device/{device_id}` | Get device |
| GET | `/api/v4/device/{device_id}/applied-policy` | Get applied policies to be applied to the device |
| GET | `/api/v4/device/{device_id}/pending-policy` | Get pending policies to be applied to the device |
| GET | `/api/v4/device/{device_id}/policies` | Get all policies for the device |
| PATCH | `/api/v4/device/{device_id}/delete` | Delete device |
| PATCH | `/api/v4/device/{device_id}/disable` | Disable a device |
| PATCH | `/api/v4/device/{device_id}/enable` | Enable a device |
| POST | `/api/v4/device/enroll` | Enroll a device |
| POST | `/api/v4/device/identitylookup` | Device lookup by identity attributes |
| POST | `/api/v4/device/registration` | Create a device |
| PUT | `/api/v4/device/{device_id}` | Update device |

## Device Group

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/device-group` | Search and paginate device groups |
| GET | `/api/v4/device-group/attributes` | Get inventory attributes |
| GET | `/api/v4/device-group/{device_group_id}` | Get the device group |
| GET | `/api/v4/device-group/{device_group_id}/device-onboarding-summary` |  |
| PATCH | `/api/v4/device-group/{device_group_id}/delete` | soft delete device group |
| PATCH | `/api/v4/device-group/{device_group_id}/disable` | Disable a device group |
| PATCH | `/api/v4/device-group/{device_group_id}/enable` | Enable a device group |
| PATCH | `/api/v4/device-group/{device_group_id}/policy/disable` | Disable a device group policy |
| PATCH | `/api/v4/device-group/{device_group_id}/policy/enable` | Enable a device group policy |
| POST | `/api/v4/device-group` | Create a device group |
| POST | `/api/v4/device-group/lookup-by-auth-policies` | Get device groups for given auth policy ids |
| POST | `/api/v4/device-group/lookup-by-certificate-policies` | Get device groups for given certificate policy ids |
| PUT | `/api/v4/device-group/{device_group_id}` | Update a device group |

## Device logs

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/device/log/{device_log_id}` | Retrieve device log by Id |
| POST | `/api/v4/device/logs` | Retrieve device logs |

## Division

| Method | Path | Purpose |
|---|---|---|
| DELETE | `/api/v4/division/{division_id}` | Delete division |
| GET | `/api/v4/division` | List divisions |
| GET | `/api/v4/division/{division_id}` | Get division |
| GET | `/api/v4/division/{division_id}/users` | List user assignments |
| PATCH | `/api/v4/division/{division_id}/disable` | Disable a division |
| PATCH | `/api/v4/division/{division_id}/enable` | Enable a division |
| POST | `/api/v4/division` | Create division |
| POST | `/api/v4/division/accounts` | Get active divisions by account ids |
| POST | `/api/v4/division/user/{user_id}` | List of divisions by user id for given criteria |
| PUT | `/api/v4/division/default` | Create Default division |
| PUT | `/api/v4/division/{division_id}` | Update division |
| PUT | `/api/v4/division/{division_id}/users/assign` | Assign users to division |
| PUT | `/api/v4/division/{division_id}/users/remove` | Remove users from division |

## Event Grid Connection Check

| Method | Path | Purpose |
|---|---|---|
| POST | `/cloud-platform-policy/api/v4/connection-check/device` | Test connectivity to an Azure Event Grid MQTT broker |
| POST | `/cloud-platform-policy/api/v4/connection-check/platform` | Validate Azure Event Grid MQTT broker configuration |
| POST | `/cloud-platform-policy/api/v4/connection-check/platform/{platform}` | Generic cloud platform connection check |

## Health

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/health` | Health monitoring |
| GET | `/api/v4/health/basic` | Basic Health monitoring |
| GET | `/api/v4/health/extensive` | Service Connector Health monitoring |
| GET | `/artifacts/api/v4/health` | Artifacts Service Basic Health monitoring |
| GET | `/artifacts/api/v4/health/basic` | Artifacts Service Basic Health monitoring |
| GET | `/artifacts/api/v4/health/extensive` | Artifacts Service Health monitoring |
| GET | `/cloud-platform-policy/api/v4/health` | Cloud Platform Policy Service Health monitoring |
| GET | `/cloud-platform-policy/api/v4/health/basic` | Cloud Platform Policy Service Basic Health monitoring |
| GET | `/cloud-platform-policy/api/v4/health/extensive` | Update Policy Service Basic Health monitoring |
| GET | `/data-aggregation/api/v4/health` | Data Aggregation Service Health monitoring |
| GET | `/data-aggregation/api/v4/health/basic` | Data Aggregation Service Basic Health monitoring |
| GET | `/data-aggregation/api/v4/health/extensive` | Data Aggregation Service Health monitoring |
| GET | `/release/api/v4/health` | Release Service Health monitoring |
| GET | `/release/api/v4/health/basic` | Release Service Basic Health monitoring |
| GET | `/release/api/v4/health/extensive` | Release Service Health monitoring |
| GET | `/update-policy/api/v4/health` | Update Policy Service Health monitoring |
| GET | `/update-policy/api/v4/health/basic` | Update Policy Service Basic Health monitoring |
| GET | `/update-policy/api/v4/health/extensive` | Update Policy Service Health monitoring |

## Issuing CAs

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-configuration-service/api/v1/managed-ca` | Search Issuing CAs |
| GET | `/certificate-configuration-service/api/v1/managed-ca/{issuing_ca_id}` | Get Issuing CA by ID |

## Labels

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/labels` | Search and paginate labels |
| POST | `/api/v4/labels` | Create a Label |

## Registered Values

| Method | Path | Purpose |
|---|---|---|
| DELETE | `/certificate-configuration-service/api/v1/registered-values/{id}` | Delete registered values |
| DELETE | `/certificate-configuration-service/api/v1/registered-values/{id}/conditions/{conditionsId}` | Delete condition |
| GET | `/certificate-configuration-service/api/v1/registered-values` | Search registered values |
| GET | `/certificate-configuration-service/api/v1/registered-values/{id}` | Get registered values by ID |
| GET | `/certificate-configuration-service/api/v1/registered-values/{id}/available-attributes` | Get available certificate policy attributes |
| GET | `/certificate-configuration-service/api/v1/registered-values/{id}/certificate-management-policies` | Get assigned certificate management policies |
| GET | `/certificate-configuration-service/api/v1/registered-values/{id}/certificate-management-policies/assignable` | Get certificate management policies that can be assigned |
| GET | `/certificate-configuration-service/api/v1/registered-values/{id}/divisions` | Get assigned divisions |
| GET | `/certificate-configuration-service/api/v1/registered-values/{id}/divisions/assignable` | Get divisions that can be assigned |
| POST | `/certificate-configuration-service/api/v1/registered-values` | Create registered values |
| POST | `/certificate-configuration-service/api/v1/registered-values/add-conditions` | Add conditions to registered values |
| POST | `/certificate-configuration-service/api/v1/registered-values/add-dataset` | Add dataset to registered values |
| POST | `/certificate-configuration-service/api/v1/registered-values/certificate-policy-attributes` | Get certificate policy attributes |
| POST | `/certificate-configuration-service/api/v1/registered-values/certificate-policy-validation` | Validate certificate policy attributes |
| POST | `/certificate-configuration-service/api/v1/registered-values/conditions/{id}/{status}` | Update condition status |
| POST | `/certificate-configuration-service/api/v1/registered-values/dataset/{id}/{status}` | Update dataset status |
| POST | `/certificate-configuration-service/api/v1/registered-values/delete-dataset` | Delete full dataset |
| POST | `/certificate-configuration-service/api/v1/registered-values/download-csv-template` | Download CSV template |
| POST | `/certificate-configuration-service/api/v1/registered-values/download-dataset` | Download dataset as ZIP |
| POST | `/certificate-configuration-service/api/v1/registered-values/update-conditions` | Update conditions for registered values |
| POST | `/certificate-configuration-service/api/v1/registered-values/update-dataset` | Update dataset values |
| POST | `/certificate-configuration-service/api/v1/registered-values/validate-dataset` | Validate dataset CSV file |
| POST | `/certificate-configuration-service/api/v1/registered-values/{id}/{status}` | Update registered values status |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}` | Update registered values |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}/certificate-management-policies/assign` | Assign certificate management policies |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}/certificate-management-policies/remove` | Remove certificate management policies |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}/dataset/{datasetId}` | Update dataset general info |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}/divisions/assign` | Assign divisions |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}/divisions/limited` | Update limited by divisions setting |
| PUT | `/certificate-configuration-service/api/v1/registered-values/{id}/divisions/remove` | Remove divisions |

## Registered Values Links

| Method | Path | Purpose |
|---|---|---|
| DELETE | `/certificate-configuration-service/api/v1/registered-values-link` | Delete registered values link |
| GET | `/certificate-configuration-service/api/v1/registered-values-link` | Search registered values links |
| POST | `/certificate-configuration-service/api/v1/registered-values-link` | Create registered values link |

## Release logs

| Method | Path | Purpose |
|---|---|---|
| GET | `/release/api/v4/release/log/{release_log_id}` | Retrieve release log by Id |
| GET | `/release/api/v4/release/logs` | Retrieve release logs |

## Releases

| Method | Path | Purpose |
|---|---|---|
| GET | `/release/api/v4/release` |  |
| GET | `/release/api/v4/release/by-artifact/{artifact_id}` |  |
| GET | `/release/api/v4/release/{release_id}` |  |
| PATCH | `/release/api/v4/release/{release_id}/disable` | Disable a release |
| PATCH | `/release/api/v4/release/{release_id}/enable` | Enable a release |
| POST | `/release/api/v4/release` |  |
| PUT | `/release/api/v4/release/{release_id}` |  |

## Rendezvous Zone

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/rendezvous-zone` | List All Rendezvous zones |
| GET | `/api/v4/rendezvous-zone/device-count/{rzone_id}` | Get device count details for given rzone id |
| GET | `/api/v4/rendezvous-zone/summary` | Get summary of rzones |
| GET | `/api/v4/rendezvous-zone/{rzone_id}` | Get rendezvous zone |
| GET | `/api/v4/rendezvous-zone/{rzone_id}/divisions` | Get Divisions associated with Rendezvous Zone |
| GET | `/api/v4/rendezvous-zone/{rzone_id}/download` | Download Rendezvous Zone certificate |
| GET | `/api/v4/rendezvous-zone/{rzone_id}/health-check` | Health check for rendezvous zone |
| PATCH | `/api/v4/rendezvous-zone/{rzone_id}/disable` | Disable Rendezvous Zone |
| PATCH | `/api/v4/rendezvous-zone/{rzone_id}/enable` | Enable Rendezvous Zone |
| POST | `/api/v4/rendezvous-zone` | Create a new Rendezvous Zone |
| PUT | `/api/v4/rendezvous-zone/{rzone_id}` | Update Rendezvous Zone |

## Scheduled Report

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v4/schedule/report` | List scheduled reports |
| GET | `/api/v4/schedule/report/{scheduled_report_id}` | Get scheduled report |
| PATCH | `/api/v4/schedule/report/{scheduled_report_id}/cancel` | Cancel a scheduled report |
| POST | `/api/v4/schedule/report` | Scheduled a report |
| PUT | `/api/v4/schedule/report/{scheduled_report_id}` | Update scheduled report |

## Secure Objects

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/secure-object` | Search secure objects |
| GET | `/api/v1/secure-object/{id}` | Get secure object by ID |
| POST | `/api/v1/secure-object` | Create a secure object |
| POST | `/api/v1/secure-object/{id}/download` | Download secure object file |
| PUT | `/api/v1/secure-object/{id}` | Update secure object |
| PUT | `/api/v1/secure-object/{id}/assign` | Assign secure groups to a secure object |
| PUT | `/api/v1/secure-object/{id}/delete` | Delete a secure object (soft delete) |
| PUT | `/api/v1/secure-object/{id}/disable` | Disable a secure object |
| PUT | `/api/v1/secure-object/{id}/enable` | Enable a secure object |
| PUT | `/api/v1/secure-object/{id}/unassign` | Unassign secure groups from a secure object |
| PUT | `/api/v1/secure-object/{id}/undelete` | Undelete a secure object |

## Trust Bundles

| Method | Path | Purpose |
|---|---|---|
| GET | `/certificate-configuration-service/api/v1/trust-bundle` | List trust bundles |
| GET | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}` | Get trust bundle by ID |
| GET | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/certificates` | List trust bundle certificates |
| GET | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/certificates/download` | Download trust bundle certificates |
| GET | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/divisions` | Get divisions assigned to trust bundles |
| POST | `/certificate-configuration-service/api/v1/trust-bundle` | Create trust bundle |
| POST | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/certificates` | Add certificates to trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}` | Update trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/certificates/remove` | Remove certificates from trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/delete` | Delete trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/disable` | Disable trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/divisions/assign` | Assign divisions to trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/divisions/limited` | Update trust bundle limited by divisions |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/divisions/remove` | Remove divisions from trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/enable` | Enable trust bundle |
| PUT | `/certificate-configuration-service/api/v1/trust-bundle/{trust_bundle_id}/undelete` | Restore trust bundle |

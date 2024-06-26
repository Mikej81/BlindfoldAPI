# BlindfoldAPI (Proof of Concept)

This is to create an API for Blindfolding Secrets programatically.

1. Create an API Token in your tenant. (This maps to Tenant Token in POST Body)
2. Map your Tenant URL and Token to the Example POST body below.
3. Ensure that your Private Key is in PEM format.

## Usage

1. Deploy workload and sign in.  First user is assiged admin role.  All other accouts are user role.  
2. Generate API Token.  (This maps to VESToken in POST Header)

```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: VESToken {APIToken}" https://blindfold.domain.com/blindfoldkey -d @body.json
```

Example POST Body:

```json
{
    "tenantUrl": "https://example.tenant.com",
    "tenantToken": "exampleTenantToken456",
    "privateKey": "examplePrivateKey789",
    "secretsPolicyName": "ves-io-allow-volterra"
}
```

Example Response Body:

```json
{
   "metadata" : {
      "name" : "Blindfold Cert",
      "namespace" : "Shared"
   },
   "spec" : {
      "certificate_url" : "string:///Base64EncodedCertificate",
      "private_key" : {
         "blindfold_secret_info" : {
            "location" : "string:///AAAADmY1LXNhLXJueGV1ZHNzAAAAAQAAAAAAAABlAgAAAAUDh3Rb2QAAAQDH7"
         }
      }
   }
}
```

API Spec:

```yaml
openapi: 3.0.0
info:
  title: vesctl API
  version: "1.0.0"
paths:
  /blindfoldkey:
    post:
      summary: Use vesctl to offline blindfold a private key
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                tenantUrl:
                  type: string
                tenantToken:
                  type: string
                privateKey:
                  type: string
                secretsPolicyName: # optional
                  type: string
              required: 
                - tenantUrl
                - tenantToken
                - privateKey
      responses:
        "200":
          description: Successfully blindfolded the private key
          content:
            application/json:
              schema:
                type: object
                properties:
                  result:
                    type: string
        "400":
          description: Bad Request

```

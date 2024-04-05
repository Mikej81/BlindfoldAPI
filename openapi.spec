openapi: 3.0.0
info:
  title: vesctl API
  version: "1.0.0"
paths:
  /blindfold-key:
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
                secretsPolicyName: # Now optional
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

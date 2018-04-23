# Users

## Endpoint URLs

```users.<env>.fathomai.com/v1/user```
Environments:
dev, qa, production

Example Endpoints:

```
POST:
https://users.dev.fathomai.com/v1/user/sign_in
{
    "email": "{email_address}",
    "password": "{password}"
}

GET:
https://users.dev.fathomai.com/v1/user/{user-uid}
```


## Contribution

1. Download Repo : ```git clone https://github.com/biometrixtech/Users.git```
2. Install Docker
3. Start Docker bash
     ```docker run -v {directory with your code}:/working -it --rm python:3.6.5```
4. Install Requirements
     ```pip install -r pip_requirements```
5. Install sam local
    a. https://github.com/awslabs/aws-sam-local#getting-started
6. Start API using SAM Local
    ```sam local start-api```
7. Use Postman to test API

## Deployment

See [infrastructure/documentation/api.md](https://github.com/biometrixtech/infrastructure/blob/master/documentation/api.md)

```deploy_lambda.py <region> <service> <environment> apigateway --no-update```


# Go Track-IT!  

This project is a *nearly* complete API wrapper for Track-IT!'s 11.4 Web Services API. Below you will find documentation outling technologies used, how to install/use, and contribution guidelines.

## Installation - Docker Run

This project automatically builds and packages Docker images into Github's Container Registry (GHCR). This allows for automatic deployment and rebuilds via Containrr/Watchtower. 

#### Login to Github Container Registry
```bash
docker login https://ghcr.io/
```

#### Run Docker Container
```bash
docker run \
  --name trackit-wrapper \
  --restart unless-stopped \
  -p 3006:3006 \
  -e WHITELISTED_IP={WHITELISTED_IP} \
  -e AUTHORIZATION_KEY={AUTHORIZATION_KEY} \
  -e TRACKIT_API_URL={TRACKIT_API_URL} \
  -e TRACKIT_USERNAME={TRACKIT_USERNAME} \
  -e TRACKIT_PASSWORD={TRACKIT_PASSWORD} \
  -d \
  ghcr.io/garrettpfoy/trackit-wrapper:{TAG}
```

#### View Container Logs
```bash
docker logs [-f] trackit-wrapper
```

#### Attach To Container
```bash
docker exec -it trackit-wrapper bash
```
## Environment Variables

This image will access multiple APIs and utilize a few different SDKs. Due to these integrations, environment variables are needed for full script functionality. **Note:** *All environment variables are required, the program may not run as expected if a given secret is invalid*

`WHITELISTED_IP` - What IP should we expect (and require) all incoming requests to come from?

`AUTHORIZATION KEY` - What Bearer token is expected in authorization header?("Authorization": "Bearer [TOKEN]")

`TRACKIT_API_URL` - Server/hostname the Track-IT server was installed on (after HTTP:// and before /WebServicesAPI/...)

`TRACKIT_USERNAME` - Technician username to use to request access token from Track-IT!

`TRACKIT_PASSWORD` - Technician password to use to request access token from Track-IT!
## Endpoints

`getWorkOrder` - Requires ID passed in parameter, returns a given work order, if found.

`createWorkOrder` - Requires WorkOrder information in HTTP data body

`updateWorkOrder` - Requires both ID and WorkOrder information

## Contributors

- [@garrettpfoy - DevOps Intern](https://www.github.com/garrettpfoy)


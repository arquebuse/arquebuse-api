# Arquebuse API

Arquebuse API server

For more information about [Arquebuse](https://arquebuse.io), an email infrastructure testing tool, please visit [Arquebuse website](https://arquebuse.io) or the [main project page](https://github.com/arquebuse/arquebuse).

# How To build

To build from sources:

    cd cmd/arquebuse-api
    go get
    go build -ldflags "-X github.com/arquebuse/arquebuse-api/pkg/version.GitCommit=$(git rev-parse --short HEAD) -X github.com/arquebuse/arquebuse-api/pkg/version.Version=snapshot -X github.com/arquebuse/arquebuse-api/pkg/version.BuildTime=$(date +%Y.%m.%d-%H:%M:%S)"

# Thanks to

* [Anthony Alaribe](https://github.com/tonyalaribe) for his post on [Structuring production grade REST API’s in Golang](https://itnext.io/structuring-a-production-grade-rest-api-in-golang-c0229b3feedc)
* [Soham Kamani](https://www.sohamkamani.com) for his post on [Implementing JWT based authentication in Golang](https://www.sohamkamani.com/blog/golang/2019-01-01-jwt-authentication/)
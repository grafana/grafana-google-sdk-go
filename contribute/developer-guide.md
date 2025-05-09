# Developer guide

This guide helps you get started developing Grafana Google SDK for Go.

## Tooling

Make sure you have the following tools installed before setting up your developer environment:

- [Git](https://git-scm.com/)
- [Go](https://golang.org/dl/) (see [go.mod](../go.mod#L3) for minimum required version)
- [Mage](https://magefile.org/)

## Building

We use [Mage](https://magefile.org/) as our primary tool for development related tasks like building and testing etc. It should be run from the root of this repository.

List available Mage targets that are available:

```bash
mage -l
```

You can use the `build` target to verify all code compiles. It doesn't output any binary though.

```bash
mage -v build
```

The `-v` flag can be used to show verbose output when running Mage targets.

### Testing

```bash
mage test
```

### Linting

```bash
mage lint
```

### Dependency management

We use Go modules for managing Go dependencies. After you've updated/modified modules dependencies, please run `go mod tidy` to cleanup dependencies.

## Releasing

If you want to tag a new version of the SDK for release, follow these steps:

- Checkout the commit you want to tag (`git checkout <COMMIT_SHA>`)
- Run `git tag <VERSION>` (For example **v0.3.1**)
  - NOTE: We're using Lightweight Tags, so no other options are required
- Run `git push origin <VERSION>`
- Verify that the tag was create successfully [here](https://github.com/grafana/grafana-google-sdk-go/releases)
- Run [`gorelease`](https://pkg.go.dev/golang.org/x/exp/cmd/gorelease) to compare the new tag with the previous release. For example, when releasing v0.3.1:

```
gorelease -base v0.3.0 -version v0.3.1
```

- Edit the tag on GitHub and create a release from it. Use the tag name as title and the output of the command above as the body.

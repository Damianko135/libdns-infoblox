package infoblox

import (
	"errors"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

const (
	defaultPort                = "443"
	defaultView                = "default"
	defaultHTTPRequestTimeout  = 20 // seconds
	defaultHTTPPoolConnections = 10
)

// validate checks that the settings required to reach the Infoblox WAPI are present.
func (p *Provider) validate() error {
	if p.Host == "" {
		return errors.New("infoblox: Host is required")
	}
	if p.Username == "" {
		return errors.New("infoblox: Username is required")
	}
	if p.Password == "" {
		return errors.New("infoblox: Password is required")
	}
	if p.Version == "" {
		return errors.New("infoblox: Version (WAPI version, e.g. \"2.12\") is required")
	}
	return nil
}

// port returns the configured port, or 443 if unset.
func (p *Provider) port() string {
	if p.Port != "" {
		return p.Port
	}
	return defaultPort
}

// view returns the configured DNS view, or "default" if unset.
func (p *Provider) view() string {
	if p.View != "" {
		return p.View
	}
	return defaultView
}

func (p *Provider) getConnector() (*ibclient.Connector, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	hostConfig := ibclient.HostConfig{
		Scheme:  "https",
		Host:    p.Host,
		Version: p.Version,
		Port:    p.port(),
	}

	authConfig := ibclient.AuthConfig{
		Username: p.Username,
		Password: p.Password,
	}

	// Certificate verification is enabled by default. Set Provider.Insecure to
	// skip it, e.g. against a lab/test grid with a self-signed certificate.
	sslVerify := "true"
	if p.Insecure {
		sslVerify = "false"
	}

	transportConfig := ibclient.NewTransportConfig(sslVerify, defaultHTTPRequestTimeout, defaultHTTPPoolConnections)
	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}

	conn, err := ibclient.NewConnector(hostConfig, authConfig, transportConfig, requestBuilder, requestor)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (p *Provider) getObjectManager() (ibclient.IBObjectManager, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, err
	}

	return ibclient.NewObjectManager(conn, "", ""), nil
}

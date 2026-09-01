
package infoblox

import ibclient "github.com/infobloxopen/infoblox-go-client/v2"

func (p *Provider) getConnector() (*ibclient.Connector, error) {
	hostConfig := ibclient.HostConfig{
		Scheme:  "https",
		Host:    p.Host,
		Version: p.Version,
		Port:    "443",
	}

	authConfig := ibclient.AuthConfig{
		Username: p.Username,
		Password: p.Password,
	}

	transportConfig := ibclient.NewTransportConfig("false", 20, 10)
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
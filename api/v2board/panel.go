package panel

import (
	ss "github.com/wyx2685/v2node/api/sspanel"
	"github.com/wyx2685/v2node/conf"
)

// Client is a compatibility alias that forwards v2board callers to sspanel client.
type Client = ss.Client

func New(c *conf.NodeConfig) (*Client, error) {
	return ss.New(c)
}

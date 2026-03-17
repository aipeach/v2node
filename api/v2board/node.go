package panel

import ss "github.com/wyx2685/v2node/api/sspanel"

// Security type
const (
	None                      = ss.None
	Tls                       = ss.Tls
	Reality                   = ss.Reality
	SSRSinglePortModeAuto     = ss.SSRSinglePortModeAuto
	SSRSinglePortModeProtocol = ss.SSRSinglePortModeProtocol
	SSRSinglePortModeObfs     = ss.SSRSinglePortModeObfs
)

type NodeInfo = ss.NodeInfo
type CommonNode = ss.CommonNode
type Route = ss.Route
type BaseConfig = ss.BaseConfig
type TlsSettings = ss.TlsSettings
type CertInfo = ss.CertInfo
type EncSettings = ss.EncSettings
type FallbackObject = ss.FallbackObject

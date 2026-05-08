package device

import "errors"

type awgConfig struct {
	junk     awgJunkConfig
	headers  awgHeaderConfig
	paddings awgPaddingConfig
	ipackets [5]*obfChain
}

type awgJunkConfig struct {
	min   int
	max   int
	count int
}

type awgHeaderConfig struct {
	init      *magicHeader
	cookie    *magicHeader
	response  *magicHeader
	transport *magicHeader
}

type awgPaddingConfig struct {
	init      int
	response  int
	cookie    int
	transport int
}

var defaultAWGConfig = &awgConfig{
	headers: awgHeaderConfig{
		init:      &magicHeader{start: MessageInitiationType, end: MessageInitiationType},
		response:  &magicHeader{start: MessageResponseType, end: MessageResponseType},
		cookie:    &magicHeader{start: MessageCookieReplyType, end: MessageCookieReplyType},
		transport: &magicHeader{start: MessageTransportType, end: MessageTransportType},
	},
}

func (device *Device) getAWGConfig() *awgConfig {
	cfg := device.awg.Load()
	if cfg != nil {
		return cfg
	}
	return defaultAWGConfig
}

func (cfg *awgConfig) clone() *awgConfig {
	next := *cfg
	return &next
}

func validateAWGHeaders(headers awgHeaderConfig) error {
	all := []*magicHeader{headers.init, headers.response, headers.cookie, headers.transport}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			left := all[i]
			right := all[j]
			if left.start <= right.end && right.start <= left.end {
				return errors.New("headers must not overlap")
			}
		}
	}
	return nil
}

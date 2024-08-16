package options

import (
	"github.com/anchore/syft/syft/format/octsgjson"
)

type FormatOCTSGJSON struct {
	Pretty *bool `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
}

func DefaultFormatOCTSGJSON() FormatOCTSGJSON {
	return FormatOCTSGJSON{}
}

func (o FormatOCTSGJSON) config(v string) octsgjson.EncoderConfig {
	var pretty bool
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	return octsgjson.EncoderConfig{
		Version: v,
		Pretty:  pretty,
	}
}

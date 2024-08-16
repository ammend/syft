package octsgjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spdx/tools-golang/convert"
	octsgModel "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/anchore/syft/syft/format/common/octsghelpers"
	"github.com/anchore/syft/syft/format/internal/octsgutil"
	"github.com/anchore/syft/syft/sbom"
)

const ID = octsgutil.JSONFormatID

func SupportedVersions() []string {
	return octsgutil.SupportedVersions(ID)
}

type EncoderConfig struct {
	Version string
	Pretty  bool // don't include spaces and newlines; same as jq -c
}

type encoder struct {
	cfg EncoderConfig
}

func NewFormatEncoderWithConfig(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	return encoder{
		cfg: cfg,
	}, nil
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		Version: octsgutil.DefaultVersion,
		Pretty:  false,
	}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{}
}

func (e encoder) Version() string {
	return e.cfg.Version
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	doc := octsghelpers.ToFormatModel(s)
	if doc == nil {
		return fmt.Errorf("unable to convert SBOM to Open Chain Telco Guide document")
	}

	var err error
	var encodeDoc any
	switch e.cfg.Version {
	case "1.0":
		targetDoc := octsgModel.Document{}
		err = convert.Document(doc, &targetDoc)
		encodeDoc = targetDoc
	default:
		return fmt.Errorf("unsupported Open Chain Telco Guide version %q", e.cfg.Version)
	}

	if err != nil {
		return fmt.Errorf("unable to convert SBOM to Open Chain Telco Guide document: %w", err)
	}

	enc := json.NewEncoder(writer)

	enc.SetEscapeHTML(false)

	if e.cfg.Pretty {
		enc.SetIndent("", " ")
	}

	return enc.Encode(encodeDoc)
}

package octsgutil

import (
	"github.com/anchore/syft/syft/sbom"
)

const DefaultVersion = "1.0"

const (
	JSONFormatID     sbom.FormatID = "octsg-json"
	TagValueFormatID sbom.FormatID = "octsg-tag-value"
)

func SupportedVersions(id sbom.FormatID) []string {
	versions := []string{
		"1.0",
	}

	if id != JSONFormatID {
		// JSON format is not supported in v2.1
		return append([]string{}, versions...)
	}

	return versions
}

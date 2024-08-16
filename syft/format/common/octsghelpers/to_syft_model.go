package octsghelpers

import (
	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func ToSyftModel(doc *spdx.Document) (*sbom.SBOM, error) {
	s, err := spdxhelpers.ToSyftModel(doc)
	return s, err
}

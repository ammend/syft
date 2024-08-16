//nolint:gosec // sha1 is used as a required hash function for SPDX, not a crypto function
package octsghelpers

import (
	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

// ToFormatModel creates and populates a new SPDX document struct that follows the OpenChain Telco SBOM Guide 1.0
func ToFormatModel(s sbom.SBOM) *spdx.Document {
	doc := spdxhelpers.ToFormatModel(s)
	// add mandatory field in OpenChain Telco SBOM Guide 1.0
	// "doc(object)->creationInfo(object)->comment",
	// "doc(object)->packages(array)->packages_item(object)->copyrightText",
	// "doc(object)->packages(array)->packages_item(object)->licenseConcluded",
	// "doc(object)->packages(array)->packages_item(object)->licenseDeclared",
	// "doc(object)->packages(array)->packages_item(object)->supplier",
	// "doc(object)->packages(array)->packages_item(object)->versionInfo"
	doc.CreationInfo.CreatorComment = "Analyzed"
	return doc
}

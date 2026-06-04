//go:build ignore

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type goModule struct {
	Path    string `json:"Path"`
	Version string `json:"Version,omitempty"`
	Main    bool   `json:"Main,omitempty"`
	Replace *struct {
		Path    string `json:"Path"`
		Version string `json:"Version,omitempty"`
	} `json:"Replace,omitempty"`
}

type spdxDocument struct {
	SPDXID            string             `json:"SPDXID"`
	SPDXVersion       string             `json:"spdxVersion"`
	CreationInfo      creationInfo       `json:"creationInfo"`
	DataLicense       string             `json:"dataLicense"`
	DocumentName      string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID              string            `json:"SPDXID"`
	Name                string            `json:"name"`
	VersionInfo         string            `json:"versionInfo,omitempty"`
	DownloadLocation    string            `json:"downloadLocation"`
	FilesAnalyzed       bool              `json:"filesAnalyzed"`
	PackageExternalRefs []spdxExternalRef `json:"externalRefs,omitempty"`
	LicenseConcluded    string            `json:"licenseConcluded"`
	LicenseDeclared     string            `json:"licenseDeclared"`
	CopyrightText       string            `json:"copyrightText"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func main() {
	version := flag.String("version", "dev", "release version")
	output := flag.String("output", "", "output SPDX JSON path")
	flag.Parse()
	if *output == "" {
		fail("output is required")
	}

	modules, err := loadModules()
	if err != nil {
		fail("%v", err)
	}
	if len(modules) == 0 {
		fail("go list returned no modules")
	}

	doc := buildSPDX(*version, modules)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fail("marshal SPDX: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fail("write SPDX: %v", err)
	}
}

func loadModules() ([]goModule, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list modules: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	var modules []goModule
	for dec.More() {
		var mod goModule
		if err := dec.Decode(&mod); err != nil {
			return nil, fmt.Errorf("decode module json: %w", err)
		}
		modules = append(modules, mod)
	}
	return modules, nil
}

func buildSPDX(version string, modules []goModule) spdxDocument {
	main := modules[0]
	docID := "SPDXRef-DOCUMENT"
	mainID := spdxID("SPDXRef-Package", main.Path, version)
	namespaceHash := sha256.Sum256([]byte(main.Path + "@" + version))

	doc := spdxDocument{
		SPDXID:            docID,
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		DocumentName:      fmt.Sprintf("%s %s SBOM", main.Path, version),
		DocumentNamespace: fmt.Sprintf("https://github.com/shuffleman/chimney-protocol/sbom/%s/%s", version, hex.EncodeToString(namespaceHash[:8])),
		CreationInfo: creationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: chimney generate-spdx-sbom.go"},
		},
	}

	packages := make([]spdxPackage, 0, len(modules))
	relationships := []spdxRelationship{
		{
			SPDXElementID:      docID,
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: mainID,
		},
	}

	for _, mod := range modules {
		name := mod.Path
		versionInfo := mod.Version
		download := downloadLocation(mod)
		if mod.Main {
			versionInfo = version
			download = "https://github.com/shuffleman/chimney-protocol"
		}
		id := spdxID("SPDXRef-Package", name, versionInfo)
		pkg := spdxPackage{
			SPDXID:           id,
			Name:             name,
			VersionInfo:      versionInfo,
			DownloadLocation: download,
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			CopyrightText:    "NOASSERTION",
			PackageExternalRefs: []spdxExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  purl(mod, versionInfo),
				},
			},
		}
		packages = append(packages, pkg)

		if !mod.Main {
			relationships = append(relationships, spdxRelationship{
				SPDXElementID:      mainID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: id,
			})
		}
	}

	sort.Slice(packages, func(i, j int) bool { return packages[i].SPDXID < packages[j].SPDXID })
	sort.Slice(relationships, func(i, j int) bool {
		if relationships[i].SPDXElementID == relationships[j].SPDXElementID {
			return relationships[i].RelatedSPDXElement < relationships[j].RelatedSPDXElement
		}
		return relationships[i].SPDXElementID < relationships[j].SPDXElementID
	})
	doc.Packages = packages
	doc.Relationships = relationships
	return doc
}

func downloadLocation(mod goModule) string {
	if mod.Replace != nil {
		if mod.Replace.Version != "" {
			return moduleProxyURL(mod.Replace.Path, mod.Replace.Version)
		}
		return "NOASSERTION"
	}
	if mod.Version == "" {
		return "NOASSERTION"
	}
	return moduleProxyURL(mod.Path, mod.Version)
}

func moduleProxyURL(path, version string) string {
	return "https://proxy.golang.org/" + strings.ToLower(path) + "/@v/" + version + ".zip"
}

func purl(mod goModule, version string) string {
	name := mod.Path
	if mod.Replace != nil {
		name = mod.Replace.Path
		if mod.Replace.Version != "" {
			version = mod.Replace.Version
		}
	}
	if version == "" {
		return "pkg:golang/" + name
	}
	return "pkg:golang/" + name + "@" + version
}

var invalidSPDXID = regexp.MustCompile(`[^A-Za-z0-9.-]`)

func spdxID(prefix, name, version string) string {
	if version != "" {
		name += "-" + version
	}
	return invalidSPDXID.ReplaceAllString(prefix+"-"+name, "-")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "generate-spdx-sbom: "+format+"\n", args...)
	os.Exit(1)
}

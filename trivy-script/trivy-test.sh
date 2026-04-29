#!/bin/bash
images=$(docker images --format "{{.Repository}}:{{.Tag}}")

TEMPLATE_DIR="/tmp"
TEMPLATE_FILE="$TEMPLATE_DIR/trivy.tpl"

cat <<EOL > "$TEMPLATE_FILE"
{{- range \$r := . }}
  {{- range .Vulnerabilities }}
"{{ .PkgName }}","{{ .VulnerabilityID }}","{{ .Severity }}","{{ .InstalledVersion }}","{{ .Title }}","{{ .PrimaryURL }}"
  {{- end }}
{{- end }}
EOL


if [ -z "$images" ]; then
  echo "No docker images found. Exists..."
  exit 0
fi

for image in $images; do
    echo "-------------------------------------------------------------------------------------------------------------------------------------"
    echo "Image", "Package", "Vulnerability ID", "Severity", "Installed Version", "Description", "Solution Reference"
    trivy i --quiet --format template --template "@/tmp/trivy.tpl" --scanners vuln $image | awk 'NF' | sed "s|^|Trivy: \"$image\",|"
    echo 
done

rm -f "$TEMPLATE_FILE"